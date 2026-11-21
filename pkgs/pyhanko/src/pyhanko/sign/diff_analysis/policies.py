"""
Module defining pyHanko's standard difference policy implementation.
"""

import logging
from collections import defaultdict
from collections.abc import Iterator

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader
from pyhanko.sign.fields import FieldMDPSpec, MDPPerm

from .form_rules_api import FormUpdatingRule
from .policy_api import (
    DiffPolicy,
    DiffResult,
    ModificationLevel,
    SuspiciousModification,
)
from .rules.file_structure_rules import (
    CatalogModificationRule,
    ObjectStreamRule,
    XrefStreamRule,
)
from .rules.form_field_rules import (
    DSSCompareRule,
    GenericFieldModificationRule,
    SigFieldCreationRule,
    SigFieldModificationRule,
)
from .rules.metadata_rules import MetadataIdentityRule
from .rules_api import (
    ApprovalType,
    Context,
    QualifiedWhitelistRule,
    ReferenceUpdate,
)

logger = logging.getLogger(__name__)


__all__ = [
    'DEFAULT_DIFF_POLICY',
    'NO_CHANGES_DIFF_POLICY',
    'StandardDiffPolicy',
]


def _find_orphans(hist_rev: HistoricalResolver):
    """
    Within a revision, find new refs that can't be reached from refs in the
    older ones.
    """

    # Note: this function assumes that there is no shady behaviour with older
    #  revisions referring to as-of-yet-undefined references in future
    #  revisions.
    # TODO I might want to put a failsafe in the PdfFileReader class's
    #  dereferencing logic to prevent that.

    # This assumption makes finding orphans relatively cheap: we only need to
    # pull up the dependencies of the older objects that were overwritten
    # in this exact revision, and we only have to recurse into branches that
    # pass through new objects themselves.

    new_refs = hist_rev.explicit_refs_in_revision()

    previous = hist_rev.reader.get_historical_resolver(hist_rev.revision - 1)

    # These are newly updated refs that already existed in older revisions.
    #  We want to know which of the new refs are reachable from one of these.
    updated_old_refs = set()
    # The candidate orphans are all the others
    candidate_orphans = set()
    for ref in new_refs:
        if previous.is_ref_unassignable(ref):
            # ref didn't exist in previous revision
            candidate_orphans.add(ref)
        else:
            updated_old_refs.add(ref)

    def _objs_to_check() -> Iterator[generic.PdfObject]:
        # check the trailer too!
        yield hist_rev.trailer_view
        for _ref in updated_old_refs:
            # take care to return the historical value here
            yield hist_rev(_ref)

    obj_iter = _objs_to_check()
    while candidate_orphans:
        try:
            obj = next(obj_iter)
        except StopIteration:
            break
        candidate_orphans -= hist_rev.collect_dependencies(
            obj, since_revision=hist_rev.revision
        )
    return candidate_orphans


def _annotate_revision(exc: SuspiciousModification, new: HistoricalResolver):
    """
    Fill in revision-level location information on a
    :class:`.SuspiciousModification` thrown by a rule, unless the rule already
    provided it.
    """
    if exc.revision is None:
        exc.revision = new.revision


def _is_id(old_object: generic.PdfObject, new_object: generic.PdfObject):
    primitives = (
        generic.NumberObject,
        generic.FloatObject,
        generic.BooleanObject,
        generic.NameObject,
        generic.NullObject,
        generic.IndirectObject,
    )
    for prim in primitives:
        if isinstance(old_object, prim):
            return isinstance(new_object, prim) and new_object == old_object

    strings = (generic.TextStringObject, generic.ByteStringObject)
    if isinstance(old_object, strings):
        return (
            isinstance(new_object, strings)
            and old_object.original_bytes == new_object.original_bytes
        )

    if isinstance(old_object, generic.ArrayObject):
        return (
            isinstance(new_object, generic.ArrayObject)
            and len(new_object) == len(old_object)
            and all(_is_id(x, y) for x, y in zip(old_object, new_object))
        )

    if isinstance(old_object, generic.StreamObject) and not (
        isinstance(new_object, generic.StreamObject)
        and new_object.encoded_data == old_object.encoded_data
    ):
        return False
    if isinstance(old_object, generic.DictionaryObject):
        if not (
            isinstance(new_object, generic.DictionaryObject)
            and new_object.keys() == old_object.keys()
        ):
            return False

        return all(
            _is_id(old_object.raw_get(k), new_object.raw_get(k))
            for k in new_object
        )
    raise NotImplementedError


class StandardDiffPolicy(DiffPolicy):
    """
    Run a list of rules to analyse the differences between two revisions.

    :param global_rules:
        The :class:`.QualifiedWhitelistRule` objects encoding the rules to
        apply.
    :param form_rule:
        The :class:`.FormUpdatingRule` that adjudicates changes to form fields
        and their values.
    :param reject_object_freeing:
        Always fail revisions that free objects that existed prior to signing.

        .. note::
            PyHanko resolves freed references to the ``null`` object in PDF,
            and a freeing instruction in a cross-reference section is
            always registered as a change that needs to be approved, regardless
            of the value of this setting.

            It is theoretically possible for a rule to permit deleting content,
            in which case allowing objects to be freed might be reasonable.
            That said, pyHanko takes the conservative default position to reject
            all object freeing instructions as suspect.
    :param ignore_orphaned_objects:
        Some PDF writers create objects that aren't used anywhere (tsk tsk).
        Since those don't affect the "actual" document content, they can usually
        be ignored. If ``True``, newly created orphaned objects will be
        cleared at level :attr:`.ModificationLevel.LTA_UPDATES`.
        Default is ``True``.
    :param ignore_orphaned_objects:
        Some PDF writers overwrite objects with identical copies.
        Pointless and annoying, but also more or less harmless.
    """

    def __init__(
        self,
        global_rules: list[QualifiedWhitelistRule],
        form_rule: FormUpdatingRule | None,
        reject_object_freeing=True,
        ignore_orphaned_objects=True,
        ignore_identical_objects=True,
    ):
        self.global_rules = global_rules
        self.form_rule = form_rule
        self.reject_object_freeing = reject_object_freeing
        self.ignore_orphaned_objects = ignore_orphaned_objects
        self.ignore_identical_objects = ignore_identical_objects

    def apply(
        self,
        old: HistoricalResolver,
        new: HistoricalResolver,
        field_mdp_spec: FieldMDPSpec | None = None,
        doc_mdp: MDPPerm | None = None,
    ) -> DiffResult:
        if doc_mdp == MDPPerm.ANNOTATE:
            logger.warning(
                "StandardDiffPolicy was not designed to support "
                "DocMDP level 3 (MDPPerm.ANNOTATE). Unexpected validation "
                "results may occur."
            )

        if self.reject_object_freeing:
            freed = new.refs_freed_in_revision()
            if freed:
                raise SuspiciousModification(
                    f"The refs {freed} were freed in the revision provided. "
                    "The configured difference analysis policy does not allow "
                    "object freeing."
                )
        # we need to verify that there are no xrefs in the revision's xref table
        # other than the ones we can justify.
        new_xrefs = new.explicit_refs_in_revision()

        explained = defaultdict(set)

        # prepare LUT for refs that are used multiple times in the old revision
        # (this reads all objects in the signed revision, but only enumerates
        #  the paths to the overridden refs)
        def _init_multi_lut():
            old._load_reverse_xref_cache(targets=new_xrefs)
            for new_ref in new_xrefs:
                usages = old._get_usages_of_ref(new_ref)
                if usages:
                    contexts = {Context.from_absolute(old, p) for p in usages}
                    yield new_ref, (ModificationLevel.NONE, contexts)

        # orphaned objects are cleared at LTA update level
        if self.ignore_orphaned_objects:
            for _ref in _find_orphans(new):
                explained[ModificationLevel.LTA_UPDATES].add(_ref)

        # This table records all the overridden refs that already existed
        # in the old revision, together with the different ways they can be
        # reached from the document trailer.
        # Unlike fresh refs, these need to be cleared together with the paths
        # through which they are accessed.
        old_usages_to_clear = dict(_init_multi_lut())

        def ingest_ref(_level: ModificationLevel, _upd: ReferenceUpdate):
            ref = _upd.updated_ref
            try:
                current_max_level, usages = old_usages_to_clear[ref]
                upd_type = _upd.approval_type
                if upd_type == ApprovalType.BLANKET_APPROVE:
                    # approve all usages at once
                    usages = set()
                elif upd_type == ApprovalType.APPROVE_RELATIVE_CONTEXT:
                    # approve all usages that match the relative context,
                    # keep the rest
                    usages = {
                        ctx
                        for ctx in usages
                        if ctx.relative_view != _upd.context_checked
                    }
                else:
                    # Last case: path-level approval
                    # remove the path that has just been cleared from
                    # the checklist
                    usages.discard(_upd.context_checked)
                # bump the modification level for this reference if necessary
                _level = max(current_max_level, _level)
                old_usages_to_clear[ref] = _level, usages
                if usages:
                    # not all paths/usages have been cleared, so we can't
                    # approve the reference yet
                    return
            except KeyError:
                pass
            explained[_level].add(ref)

        # Rules are allowed to raise SuspiciousModification directly; we make
        # sure that the exception identifies the revision it was raised in, so
        # that callers can locate the offending incremental update even when
        # the rule itself didn't bother to fill in that information.
        for rule in self.global_rules:
            try:
                for level, upd in rule.apply_qualified(old, new):
                    ingest_ref(level, upd)
            except SuspiciousModification as exc:
                _annotate_revision(exc, new)
                raise

        changed_form_fields = set()

        if self.form_rule:
            form_changes = self.form_rule.apply(old, new)

            def is_locked(fq_name):
                return field_mdp_spec is not None and field_mdp_spec.is_locked(
                    fq_name
                )

            for level, fu in form_changes:
                ingest_ref(level, fu)
                field_name = fu.field_name
                if field_name is not None and not fu.valid_when_locked:
                    if is_locked(field_name):
                        raise SuspiciousModification(
                            f"Update of {fu.updated_ref} is not allowed "
                            f"because the form field {field_name} is locked.",
                            revision=new.revision,
                            locations=(fu.updated_ref,),
                        )
                    changed_form_fields.add(field_name)
                if doc_mdp is not None and not fu.valid_when_certifying:
                    raise SuspiciousModification(
                        f"Update of {fu.updated_ref} is only allowed "
                        f"after an approval signature, not a certification "
                        f"signature.",
                        revision=new.revision,
                        locations=(fu.updated_ref,),
                    )

        unexplained_lta = new_xrefs - explained[ModificationLevel.LTA_UPDATES]
        unexplained_formfill = (
            unexplained_lta - explained[ModificationLevel.FORM_FILLING]
        )
        unexplained_annot = (
            unexplained_formfill - explained[ModificationLevel.ANNOTATIONS]
        )

        xref_cache = old.reader.xrefs
        if self.ignore_identical_objects:
            identical_objs = {
                unex_ref
                for unex_ref in unexplained_lta
                if xref_cache.get_historical_ref(unex_ref, old.revision)
                is not None
                and _is_id(old(unex_ref), new(unex_ref))
            }
            if identical_objs:
                logger.debug(
                    f"Found identical overridden objects between revisions "
                    f"{old.revision} and {new.revision}; following no-op "
                    f"changes will be ignored: {identical_objs}"
                )
                unexplained_annot.difference_update(identical_objs)
                unexplained_formfill.difference_update(identical_objs)
                unexplained_lta.difference_update(identical_objs)

        if unexplained_annot:
            msg = misc.LazyJoin(
                '\n',
                (
                    f'{x!r}:{repr(x.get_object())[:300]}...'
                    for x in unexplained_annot
                ),
            )
            logger.debug(
                "Unexplained xrefs in revision %d:\n%s", new.revision, msg
            )
            unexplained_overrides = [
                f" - {ref!r} is also used in "
                f"{', '.join(str(p) for p in paths_remaining)} in the prior "
                f"revision."
                for ref, (_, paths_remaining) in old_usages_to_clear.items()
                if paths_remaining
            ]
            err_msg = (
                f"There are unexplained xrefs in revision {new.revision}: "
                f"{', '.join(repr(x) for x in unexplained_annot)}."
            )
            if unexplained_overrides:
                unchecked_paths_msg = (
                    f"Some objects from revision {old.revision} were replaced "
                    f"in revision {new.revision} without precise "
                    "justification:\n" + '\n'.join(unexplained_overrides)
                )
                err_msg = f"{err_msg}\n{unchecked_paths_msg}"
                logger.debug(unchecked_paths_msg)

            raise SuspiciousModification(
                err_msg,
                revision=new.revision,
                locations=tuple(
                    sorted(
                        unexplained_annot,
                        key=lambda ref: (ref.idnum, ref.generation),
                    )
                ),
            )
        elif unexplained_formfill:
            level = ModificationLevel.ANNOTATIONS
        elif unexplained_lta:
            level = ModificationLevel.FORM_FILLING
        else:
            level = ModificationLevel.LTA_UPDATES

        return DiffResult(
            modification_level=level,
            changed_form_fields=changed_form_fields,
            metadata_identity=self._metadata_identity_findings(old, new),
        )

    def _has_metadata_rule(self) -> bool:
        from .rules_api import _WrappingQualifiedWhitelistRule

        for rule in self.global_rules:
            if isinstance(rule, MetadataIdentityRule):
                return True
            if isinstance(rule, _WrappingQualifiedWhitelistRule) and isinstance(
                rule.rule, MetadataIdentityRule
            ):
                return True
        return False

    def _metadata_identity_findings(
        self, old: HistoricalResolver, new: HistoricalResolver
    ) -> tuple:
        """
        Record the identity-level view of a revision pair, if the policy
        includes a :class:`.MetadataIdentityRule`.

        The identity analysis is memoised on the resolvers, so this is
        inexpensive if the rule already ran. Recording it on the
        :class:`.DiffResult` lets callers trace identity changes (and
        pre-existing anomalies) for every accepted revision, not just for the
        revisions that were rejected.
        """
        if not self._has_metadata_rule():
            return ()
        from pyhanko.pdf_utils.metadata.identity import (
            analyse_metadata_identity,
        )

        return (analyse_metadata_identity(old, new),)

    def _check_metadata_identity_step(
        self, previous: HistoricalResolver, current: HistoricalResolver
    ) -> object:
        """
        Compare the metadata identity of one incremental step, and refuse the
        step if it introduces a contradiction between the metadata channels,
        metadata that cannot be interpreted, or a channel replacement that
        falls outside the signature's coverage.

        This complements the per-rule check: :class:`.MetadataIdentityRule`
        compares the signed revision to the revision under review, whereas
        this step-level check pins any problem to the exact incremental
        revision that introduced it. That also catches contradictions that a
        later revision repairs again, which a comparison against the signed
        revision would no longer see.
        """
        from pyhanko.pdf_utils.metadata.identity import (
            MetadataIdentityVerdict,
            analyse_metadata_identity,
        )

        report = analyse_metadata_identity(previous, current)
        verdict = report.verdict
        if verdict == MetadataIdentityVerdict.CONTRADICTION:
            fields = ', '.join(
                cmp.field for cmp in report.newly_problematic_fields
            ) or ', '.join(cmp.field for cmp in report.problematic_fields)
            raise SuspiciousModification(
                f"The metadata channels in revision {current.revision} "
                f"contradict each other on the following identity fields: "
                f"{fields}. {report.summary()}",
                revision=current.revision,
                locations=report.locations,
                metadata_identity=(report,),
            )
        elif verdict == MetadataIdentityVerdict.UNPARSEABLE:
            raise SuspiciousModification(
                f"The document metadata in revision {current.revision} could "
                f"not be interpreted consistently. {report.summary()}",
                revision=current.revision,
                locations=report.locations,
                metadata_identity=(report,),
            )
        elif verdict == MetadataIdentityVerdict.CHANNEL_REPLACEMENT:
            raise SuspiciousModification(
                f"Revision {current.revision} redirects the following "
                f"metadata channels to pre-existing objects instead of "
                f"updating them: {', '.join(report.replaced_channels)}. "
                f"That replacement falls outside the metadata semantics "
                f"covered by the signature. {report.summary()}",
                revision=current.revision,
                locations=report.locations,
                metadata_identity=(report,),
            )
        return report

    def review_file(
        self,
        reader: PdfFileReader,
        base_revision: int | HistoricalResolver,
        field_mdp_spec: FieldMDPSpec | None = None,
        doc_mdp: MDPPerm | None = None,
    ) -> DiffResult | SuspiciousModification:
        """
        Implementation of :meth:`.DiffPolicy.review_file` that reviews
        each intermediate revision between the base revision and the current one
        individually.
        """

        changed_form_fields = set()
        metadata_identity = []

        rev_count = reader.xrefs.total_revisions
        current_max = ModificationLevel.NONE
        if isinstance(base_revision, int):
            base_rev_resolver = reader.get_historical_resolver(base_revision)
            base_revision_no = base_revision
        else:
            base_rev_resolver = base_revision
            base_revision_no = base_rev_resolver.revision

        # Note: there's a pragmatic reason why we iterate over all revisions
        # instead of just asking for all updated objects between the signed
        # revision and the most recent one:
        #
        # The effect of intermediate updates may not be detectable anymore in
        # the most recent version, so if we'd consolidate all checks into one,
        # we would have no way to tell whether or not the objects created
        # (and later forgotten) by these intermediate revisions actually
        # constituted legitimate changes.
        # (see the test_pades_revinfo tests for examples where this applies)
        #
        # Until we have a reference counter (which comes with its own
        # performance problems that may or may not be worse), I don't really
        # see a good way around this issue other than diffing every intermediate
        # version separately.
        for revision in range(base_revision_no + 1, rev_count):
            new_resolver = reader.get_historical_resolver(revision)
            try:
                if self._has_metadata_rule():
                    # Adjudicate the identity-level change of this exact
                    # incremental step, so that a contradiction introduced and
                    # repaired in different revisions is still caught, and so
                    # that the resulting report can be tied to this revision.
                    metadata_identity.append(
                        self._check_metadata_identity_step(
                            reader.get_historical_resolver(revision - 1),
                            new_resolver,
                        )
                    )
                diff_result = self.apply(
                    old=base_rev_resolver,
                    new=new_resolver,
                    field_mdp_spec=field_mdp_spec,
                    doc_mdp=doc_mdp,
                )
            except SuspiciousModification as e:
                logger.warning(
                    'Error in diff operation between revision '
                    f'{base_revision_no} and {revision}',
                    exc_info=e,
                )
                if e.revision is None:
                    e.revision = revision
                # Retain the identity findings for every revision leading up
                # to (and including) the offending one, so the caller can see
                # the full trajectory rather than just the final report.
                # Reports are keyed by the revision pair they describe; the
                # step-level check and the rule may both have produced one for
                # the offending revision, in which case the rule's report (the
                # last one) wins.
                merged = {
                    (rep.base_revision, rep.revision): rep
                    for rep in (
                        *metadata_identity,
                        *e.metadata_identity,
                    )
                }
                if merged:
                    e.metadata_identity = tuple(merged.values())
                return e
            current_max = max(current_max, diff_result.modification_level)
            changed_form_fields |= diff_result.changed_form_fields
        return DiffResult(
            current_max, changed_form_fields, tuple(metadata_identity)
        )


DEFAULT_DIFF_POLICY = StandardDiffPolicy(
    global_rules=[
        CatalogModificationRule(),
        MetadataIdentityRule(),
        XrefStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
        ObjectStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
        DSSCompareRule().as_qualified(ModificationLevel.LTA_UPDATES),
    ],
    form_rule=FormUpdatingRule(
        field_rules=[
            SigFieldCreationRule(),
            SigFieldModificationRule(),
            GenericFieldModificationRule(),
        ],
    ),
)
"""
Default :class:`.DiffPolicy` implementation.

This policy includes the following rules, all with the default settings.
The unqualified rules in the list all have their updates qualified at
level :class:`~.ModificationLevel.LTA_UPDATES`.

* :class:`.CatalogModificationRule`,
* :class:`.MetadataIdentityRule`,
* :class:`.ObjectStreamRule`,
* :class:`.XrefStreamRule`,
* :class:`.DSSCompareRule`.
* :class:`.FormUpdatingRule`, with the following field rules:

    * :class:`.SigFieldCreationRule`,
    * :class:`.SigFieldModificationRule`,
    * :class:`.GenericFieldModificationRule`.

.. note::
    Document metadata is adjudicated jointly across the information
    dictionary and the XMP metadata stream. Updates that are coherent across
    the channels that carry the title, author, subject or creation date are
    cleared as LTA updates. Contradictory or unparseable metadata is rejected
    outright. See :class:`.MetadataIdentityRule`.
"""


NO_CHANGES_DIFF_POLICY = StandardDiffPolicy(global_rules=[], form_rule=None)
"""
:class:`.DiffPolicy` implementation that does not provide any rules,
and will therefore simply reject all changes.
"""
