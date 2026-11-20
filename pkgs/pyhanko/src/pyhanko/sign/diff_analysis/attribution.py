"""
Per-revision attribution of incremental updates in signed PDF files.

This module builds on pyHanko's difference analysis toolkit
(:mod:`pyhanko.sign.diff_analysis`) to produce a stable, revision-by-revision
account of what happened to a document after it was signed.

Where :class:`~pyhanko.sign.diff_analysis.DiffPolicy` implementations
ultimately compress their findings into a single :class:`.DiffResult`
judgment, the attribution API in this module treats every incremental
revision individually. For each revision, it records

* which objects were added or overwritten (and which were freed);
* which of those objects are attributable to document metadata
  (the trailer's ``/Info`` dictionary and the XMP ``/Metadata`` stream);
* which of those objects are attributable to page content
  (page tree nodes, page objects and their content streams);
* how the revision relates to the document's signatures
  (which signatures it introduces, and which signatures cover it);
* a verdict classifying the revision as allowed maintenance, an unknown
  (but explained) modification, or a signature-breaking modification.

The output is deterministic: all object references and names are reported
in a stable order, so reports can be compared and serialised reliably.
"""

import enum
import logging
from dataclasses import dataclass

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader

from .policies import DEFAULT_DIFF_POLICY
from .policy_api import (
    DiffPolicy,
    ModificationLevel,
    SuspiciousModification,
)

__all__ = [
    'IncrementalAttributionReport',
    'RevisionAttribution',
    'RevisionVerdict',
    'attribute_incremental_updates',
]

logger = logging.getLogger(__name__)


@enum.unique
class RevisionVerdict(misc.OrderedEnum):
    """
    Per-revision judgment produced by the attribution analysis.

    The members are ordered by increasing severity, so ``max`` can be used
    to aggregate verdicts.
    """

    ALLOWED_MAINTENANCE = 0
    """
    The revision only contains updates of the kind that are allowed as part
    of routine maintenance (LTA processing, to be precise: DSS updates,
    document timestamps, metadata tweaks, ...). These do not affect any
    signature's validity.
    """

    UNKNOWN_MODIFICATION = 1
    """
    The revision contains modifications that were explained by the difference
    policy, but that go beyond pure maintenance (e.g. form filling).
    Whether these are acceptable depends on the applicable DocMDP/FieldMDP
    settings, so they are reported as "unknown" rather than unconditionally
    allowed or rejected.
    """

    SIGNATURE_BREAKING = 2
    """
    The revision contains modifications that the difference policy could not
    account for. Any signature whose signed revision precedes this revision
    must be considered compromised.
    """


def _sort_refs(refs) -> tuple[generic.Reference, ...]:
    return tuple(sorted(refs, key=lambda ref: (ref.idnum, ref.generation)))


def _format_ref(ref: generic.Reference) -> str:
    return f"{ref.idnum} {ref.generation} R"


def _metadata_refs(resolver: HistoricalResolver) -> set[generic.Reference]:
    """
    Collect the references backing the document's metadata in the revision
    viewed by ``resolver``: the trailer's ``/Info`` dictionary and the
    document catalog's XMP ``/Metadata`` stream.
    """
    refs: set[generic.Reference] = set()
    try:
        info_ref = resolver.trailer_view.get_value_as_reference(
            '/Info', optional=True
        )
    except misc.IndirectObjectExpected:
        info_ref = None
    if info_ref is not None:
        refs.add(info_ref)
    try:
        metadata_ref = resolver.root.get_value_as_reference(
            '/Metadata', optional=True
        )
    except misc.IndirectObjectExpected:
        metadata_ref = None
    if metadata_ref is not None:
        refs.add(metadata_ref)
    return refs


def _page_content_refs(
    resolver: HistoricalResolver,
) -> set[generic.Reference]:
    """
    Collect the references that make up the page content in the revision
    viewed by ``resolver``: page tree nodes, page objects and the objects
    backing their ``/Contents`` entries.
    """
    refs: set[generic.Reference] = set()
    try:
        pages_root = resolver.root.raw_get('/Pages')
    except (KeyError, misc.PdfReadError):
        return refs

    seen: set[generic.Reference] = set()
    stack = [pages_root]
    while stack:
        node = stack.pop()
        if isinstance(node, generic.IndirectObject):
            ref = node.reference
            if ref in seen:
                continue
            seen.add(ref)
            refs.add(ref)
            try:
                node = node.get_object()
            except misc.PdfReadError:
                continue
        if not isinstance(node, generic.DictionaryObject):
            continue
        try:
            kids = node.raw_get('/Kids')
        except KeyError:
            kids = None
        if isinstance(kids, generic.ArrayObject):
            stack.extend(kids)
            continue
        # no (array-valued) /Kids entry -> treat as a page leaf
        try:
            contents = node.raw_get('/Contents')
        except KeyError:
            continue
        if isinstance(contents, generic.ArrayObject):
            content_items = contents
        else:
            content_items = [contents]
        for item in content_items:
            if isinstance(item, generic.IndirectObject):
                refs.add(item.reference)
    return refs


@dataclass(frozen=True)
class _SignaturePlacement:
    field_name: str
    signed_revision: int


def _collect_signature_placements(
    reader: PdfFileReader,
) -> tuple[_SignaturePlacement, ...]:
    try:
        embedded = reader.embedded_signatures
    except Exception as e:
        logger.warning(
            "Could not enumerate embedded signatures; signature coverage "
            "information will be incomplete.",
            exc_info=e,
        )
        return ()
    return tuple(
        _SignaturePlacement(
            field_name=emb.field_name, signed_revision=emb.signed_revision
        )
        for emb in embedded
    )


@dataclass(frozen=True)
class RevisionAttribution:
    """
    Attribution record for a single incremental revision.

    All reference collections are stored as tuples sorted by object and
    generation number, so the output is stable across runs.
    """

    revision: int
    """
    The revision index (``0`` is the original revision of the file).
    """

    new_objects: tuple[generic.Reference, ...]
    """
    Objects added or overwritten in this revision, sorted by object number.
    """

    freed_objects: tuple[generic.Reference, ...]
    """
    Objects explicitly freed in this revision, sorted by object number.
    """

    metadata_objects: tuple[generic.Reference, ...]
    """
    Subset of :attr:`new_objects` attributable to document metadata
    (``/Info`` dictionary and/or XMP ``/Metadata`` stream).
    """

    page_content_objects: tuple[generic.Reference, ...]
    """
    Subset of :attr:`new_objects` attributable to page content (page tree
    nodes, page objects and their content streams).
    """

    signatures_introduced: tuple[str, ...]
    """
    Names of signature fields whose signature was added in this revision,
    sorted alphabetically.
    """

    covered_by_signatures: tuple[str, ...]
    """
    Names of signature fields whose signature (cryptographically) covers
    this revision, sorted alphabetically. A signature covers all revisions
    up to and including the one it was applied in.
    """

    modification_level: ModificationLevel | None
    """
    The modification level reported by the difference policy for this
    revision in isolation, or ``None`` if the policy raised a
    :class:`~pyhanko.sign.diff_analysis.SuspiciousModification`.
    """

    verdict: RevisionVerdict
    """
    The verdict for this revision in isolation.
    """

    detail: str | None = None
    """
    Human-readable detail, typically the reason why the revision was
    flagged as :attr:`RevisionVerdict.SIGNATURE_BREAKING`.
    """

    def as_dict(self) -> dict:
        """
        Return a JSON-serialisable, deterministically ordered representation
        of this attribution record.
        """
        return {
            'revision': self.revision,
            'verdict': self.verdict.name,
            'modification_level': (
                self.modification_level.name
                if self.modification_level is not None
                else None
            ),
            'new_objects': [_format_ref(ref) for ref in self.new_objects],
            'freed_objects': [_format_ref(ref) for ref in self.freed_objects],
            'metadata_objects': [
                _format_ref(ref) for ref in self.metadata_objects
            ],
            'page_content_objects': [
                _format_ref(ref) for ref in self.page_content_objects
            ],
            'signatures_introduced': list(self.signatures_introduced),
            'covered_by_signatures': list(self.covered_by_signatures),
            'detail': self.detail,
        }

    def summary_line(self) -> str:
        """
        Return a one-line, deterministic human-readable summary of this
        attribution record.
        """
        level = (
            self.modification_level.name
            if self.modification_level is not None
            else 'N/A'
        )
        introduced = ', '.join(self.signatures_introduced) or '-'
        covered_by = ', '.join(self.covered_by_signatures) or '-'
        parts = [
            f"revision {self.revision}",
            f"verdict={self.verdict.name}",
            f"level={level}",
            f"new={len(self.new_objects)}",
            f"freed={len(self.freed_objects)}",
            f"metadata={len(self.metadata_objects)}",
            f"page_content={len(self.page_content_objects)}",
            f"signatures_introduced={introduced}",
            f"covered_by={covered_by}",
        ]
        if self.detail:
            parts.append(f"detail={' '.join(self.detail.split())}")
        return '; '.join(parts)


@dataclass(frozen=True)
class IncrementalAttributionReport:
    """
    Per-revision attribution report for the incremental updates appended
    to a (signed) PDF document.

    The report always contains one :class:`RevisionAttribution` per
    incremental revision after the base revision; it never collapses
    multiple revisions into a single aggregate judgment (although
    :attr:`overall_verdict` provides the worst-case rollup for convenience).
    """

    base_revision: int
    """
    The revision from which the analysis started (typically the revision
    in which the first signature was applied).
    """

    revisions: tuple[RevisionAttribution, ...]
    """
    Attribution records for every revision after :attr:`base_revision`,
    in revision order.
    """

    @property
    def overall_verdict(self) -> RevisionVerdict:
        """
        The most severe verdict among all attributed revisions
        (:attr:`RevisionVerdict.ALLOWED_MAINTENANCE` if there are none).
        """
        verdict = RevisionVerdict.ALLOWED_MAINTENANCE
        for rev in self.revisions:
            verdict = max(verdict, rev.verdict)
        return verdict

    @property
    def signature_breaking_revisions(self) -> tuple[int, ...]:
        """
        Revision indices of all revisions judged
        :attr:`RevisionVerdict.SIGNATURE_BREAKING`.
        """
        return tuple(
            rev.revision
            for rev in self.revisions
            if rev.verdict == RevisionVerdict.SIGNATURE_BREAKING
        )

    def as_dict(self) -> dict:
        """
        Return a JSON-serialisable, deterministically ordered representation
        of this report.
        """
        return {
            'base_revision': self.base_revision,
            'overall_verdict': self.overall_verdict.name,
            'revisions': [rev.as_dict() for rev in self.revisions],
        }

    def summary(self) -> str:
        """
        Return a deterministic multi-line human-readable summary of this
        report, with one line per revision.
        """
        header = (
            f"Attribution of incremental updates after revision "
            f"{self.base_revision} (overall verdict: "
            f"{self.overall_verdict.name})"
        )
        lines = [header]
        lines.extend(rev.summary_line() for rev in self.revisions)
        return '\n'.join(lines)


def _attribute_revision(
    reader: PdfFileReader,
    revision: int,
    diff_policy: DiffPolicy,
    placements: tuple[_SignaturePlacement, ...],
) -> RevisionAttribution:
    xref_cache = reader.xrefs
    new_refs = xref_cache.explicit_refs_in_revision(revision)
    freed_refs = xref_cache.refs_freed_in_revision(revision)

    new_resolver = reader.get_historical_resolver(revision)
    old_resolver = reader.get_historical_resolver(revision - 1)

    metadata_objects = _metadata_refs(new_resolver) & new_refs
    page_content_objects = _page_content_refs(new_resolver) & new_refs

    introduced = tuple(
        sorted(
            p.field_name for p in placements if p.signed_revision == revision
        )
    )
    covered_by = tuple(
        sorted(
            p.field_name for p in placements if p.signed_revision >= revision
        )
    )

    modification_level: ModificationLevel | None
    detail: str | None = None
    try:
        diff_result = diff_policy.apply(old=old_resolver, new=new_resolver)
        modification_level = diff_result.modification_level
        if modification_level <= ModificationLevel.LTA_UPDATES:
            verdict = RevisionVerdict.ALLOWED_MAINTENANCE
        elif modification_level <= ModificationLevel.ANNOTATIONS:
            verdict = RevisionVerdict.UNKNOWN_MODIFICATION
        else:
            verdict = RevisionVerdict.SIGNATURE_BREAKING
    except SuspiciousModification as e:
        logger.debug(
            "Suspicious modification in revision %d", revision, exc_info=e
        )
        modification_level = None
        verdict = RevisionVerdict.SIGNATURE_BREAKING
        detail = str(e)
    except misc.PdfReadError as e:
        # the revision couldn't even be parsed/compared consistently;
        # it certainly can't be cleared as benign maintenance
        logger.debug(
            "Read error while analysing revision %d", revision, exc_info=e
        )
        modification_level = None
        verdict = RevisionVerdict.SIGNATURE_BREAKING
        detail = f"Error while analysing revision: {e}"

    return RevisionAttribution(
        revision=revision,
        new_objects=_sort_refs(new_refs),
        freed_objects=_sort_refs(freed_refs),
        metadata_objects=_sort_refs(metadata_objects),
        page_content_objects=_sort_refs(page_content_objects),
        signatures_introduced=introduced,
        covered_by_signatures=covered_by,
        modification_level=modification_level,
        verdict=verdict,
        detail=detail,
    )


def attribute_incremental_updates(
    reader: PdfFileReader,
    base_revision: int | None = None,
    diff_policy: DiffPolicy = DEFAULT_DIFF_POLICY,
) -> IncrementalAttributionReport:
    """
    Attribute every incremental revision after ``base_revision`` in the file
    read by ``reader``.

    Each revision is analysed independently of the others: the report
    contains one :class:`RevisionAttribution` per revision, each with its
    own verdict, so multi-revision update chains are not reduced to a single
    final judgment.

    :param reader:
        PDF reader representing the current state of the file.
    :param base_revision:
        The revision from which to start the analysis. If ``None``, the
        revision of the earliest embedded signature is used (i.e. all
        post-signing updates are attributed); if the document is not signed
        at all, the original revision (``0``) is used.
    :param diff_policy:
        The difference policy used to judge each revision. Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :return:
        An :class:`IncrementalAttributionReport`.
    """
    placements = _collect_signature_placements(reader)

    if base_revision is None:
        if placements:
            base_revision = min(p.signed_revision for p in placements)
        else:
            base_revision = 0
    if not 0 <= base_revision < reader.xrefs.total_revisions:
        raise misc.PdfReadError(
            f"Base revision {base_revision} is out of range for a file with "
            f"{reader.xrefs.total_revisions} revision(s)."
        )

    revisions = tuple(
        _attribute_revision(reader, revision, diff_policy, placements)
        for revision in range(base_revision + 1, reader.xrefs.total_revisions)
    )
    return IncrementalAttributionReport(
        base_revision=base_revision, revisions=revisions
    )
