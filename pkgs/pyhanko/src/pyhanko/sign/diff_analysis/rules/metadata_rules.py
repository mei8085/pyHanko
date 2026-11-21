"""
Difference analysis rules for the document's descriptive metadata.

A PDF document describes itself through two channels: the information
dictionary (``/Info``) and the XMP metadata stream (``/Metadata``). The same
identity-bearing fields -- title, author, subject and creation date -- are
typically duplicated in both.

The rules in this module adjudicate updates to those channels *jointly*.
Instead of treating the two channels as unrelated objects, they compare the
*identity semantics* of the metadata in both revisions (see
:mod:`pyhanko.pdf_utils.metadata.identity`), and classify the update as:

* a legitimate identity update, if the change is coherent across the channels
  that carry the affected fields (this is cleared at
  :attr:`~.ModificationLevel.LTA_UPDATES`),
* a contradiction, if the channels disagree about an identity field,
* a channel replacement, if a channel was redirected at an object that already
  existed and the change therefore falls outside the identity semantics the
  signature covers, or
* an unparseable metadata update, if the metadata can no longer be interpreted
  in the newer revision.

The latter three cases cannot be cleared at any level and result in
:class:`~.SuspiciousModification` exceptions. The exception records the
revision in which the problem was observed, along with the object references
that back the metadata in either revision.

.. versionchanged:: 0.39.0

    Metadata updates are now adjudicated jointly across the ``/Info``
    dictionary and the XMP ``/Metadata`` stream.
"""

from collections.abc import Iterable

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.decode_limits import DecodePurpose
from pyhanko.pdf_utils.metadata.identity import (
    MetadataIdentityReport,
    MetadataIdentityVerdict,
    analyse_metadata_identity,
)
from pyhanko.pdf_utils.reader import HistoricalResolver, RawPdfPath

from ..commons import safe_whitelist
from ..policy_api import ModificationLevel, SuspiciousModification
from ..rules_api import (
    Context,
    QualifiedWhitelistRule,
    ReferenceUpdate,
    WhitelistRule,
)

__all__ = [
    'DocInfoRule',
    'MetadataIdentityRule',
    'MetadataUpdateRule',
]


def _reject(
    report: MetadataIdentityReport, message: str
) -> SuspiciousModification:
    return SuspiciousModification(
        message,
        revision=report.revision,
        locations=report.locations,
        metadata_identity=(report,),
    )


def _require_acceptable_identity(report: MetadataIdentityReport):
    """
    Raise :class:`.SuspiciousModification` if the metadata identity report
    contains a problem that no policy can clear.
    """
    verdict = report.verdict
    if verdict == MetadataIdentityVerdict.CONTRADICTION:
        fields = ', '.join(
            cmp.field for cmp in report.newly_problematic_fields
        ) or ', '.join(cmp.field for cmp in report.problematic_fields)
        raise _reject(
            report,
            f"The metadata channels in revision {report.revision} "
            f"contradict each other on the following identity fields: "
            f"{fields}. {report.summary()}",
        )
    elif verdict == MetadataIdentityVerdict.UNPARSEABLE:
        raise _reject(
            report,
            f"The document metadata in revision {report.revision} could not "
            f"be interpreted consistently. {report.summary()}",
        )
    elif verdict == MetadataIdentityVerdict.CHANNEL_REPLACEMENT:
        channels = ', '.join(report.replaced_channels)
        raise _reject(
            report,
            f"Revision {report.revision} redirects the following metadata "
            f"channels to pre-existing objects instead of updating them: "
            f"{channels}. Such a replacement falls outside the metadata "
            f"semantics covered by the signature. {report.summary()}",
        )


class MetadataIdentityRule(QualifiedWhitelistRule):
    """
    Rule that adjudicates updates to the document's descriptive metadata as a
    single, two-channel identity.

    The rule compares the identity view of the old and new revisions, and

    * refuses the revision outright if the metadata channels contradict each
      other on an identity field, or if the metadata can no longer be parsed;
    * otherwise clears the objects backing both channels at
      :attr:`~.ModificationLevel.LTA_UPDATES`, provided the update is
      syntactically safe.

    Because the rule compares identity semantics rather than individual
    objects, a change that is applied consistently to the title, author,
    subject or creation date in both channels counts as one identity update,
    irrespective of whether it was written to one channel or both.

    .. note::
        This rule subsumes :class:`.DocInfoRule` and
        :class:`.MetadataUpdateRule`; those remain available for use in custom
        policies that only care about one channel.
    """

    def __init__(self, check_xml_syntax=True):
        self.check_xml_syntax = check_xml_syntax

    def apply_qualified(
        self, old: HistoricalResolver, new: HistoricalResolver
    ) -> Iterable[tuple[ModificationLevel, ReferenceUpdate]]:
        report = analyse_metadata_identity(old, new)
        _require_acceptable_identity(report)

        new_info_ref = _info_ref(new)
        old_info_ref = _info_ref(old)
        if new_info_ref is not None:
            _assert_info_is_dictionary(new, new_info_ref)
            yield from _cleared_refs(
                ModificationLevel.LTA_UPDATES,
                old,
                new,
                old_info_ref,
                new_info_ref,
                RawPdfPath('/Info'),
            )

        new_xmp_ref = _xmp_ref(new)
        old_xmp_ref = _xmp_ref(old)
        if new_xmp_ref is None:
            return
        if self.check_xml_syntax:
            MetadataUpdateRule.is_well_formed_xml(new_xmp_ref)
            if old_xmp_ref is not None:
                MetadataUpdateRule.is_well_formed_xml(old_xmp_ref)
        yield from _cleared_xmp_refs(
            ModificationLevel.LTA_UPDATES,
            old,
            new,
            old_xmp_ref,
            new_xmp_ref,
        )


def _cleared_xmp_refs(
    level: ModificationLevel,
    old: HistoricalResolver,
    new: HistoricalResolver,
    old_ref: generic.Reference | None,
    new_ref: generic.Reference,
) -> Iterable[tuple[ModificationLevel, ReferenceUpdate]]:
    # The XMP metadata is a stream, so safe_whitelist (which rejects streams)
    # does not apply. Instead, we mirror the historical behaviour of
    # MetadataUpdateRule: overriding the stream in place is fine (the syntax
    # of both versions has been validated), and so is pointing /Metadata at a
    # brand-new object. Pointing it at a pre-existing object that isn't the
    # old metadata stream would be an uncontrolled stream reuse.
    context = Context.from_absolute(old, RawPdfPath('/Root', '/Metadata'))
    if old_ref == new_ref or old.is_ref_unassignable(new_ref):
        yield level, ReferenceUpdate(new_ref, context_checked=context)
    else:
        raise SuspiciousModification(
            "/Metadata was redirected to a pre-existing object",
            revision=new.revision,
            locations=(
                (old_ref, new_ref) if old_ref is not None else (new_ref,)
            ),
        )


def _cleared_refs(
    level: ModificationLevel,
    old: HistoricalResolver,
    new: HistoricalResolver,
    old_ref: generic.Reference | None,
    new_ref: generic.Reference,
    path: RawPdfPath,
) -> Iterable[tuple[ModificationLevel, ReferenceUpdate]]:
    context = Context.from_absolute(old, path)
    try:
        refs = list(safe_whitelist(old, old_ref, new_ref))
    except SuspiciousModification as exc:
        raise _relocate(exc, new, old_ref, new_ref)
    for ref in refs:
        yield level, ReferenceUpdate(ref, context_checked=context)


def _relocate(
    exc: SuspiciousModification,
    new: HistoricalResolver,
    old_ref: generic.Reference | None,
    new_ref: generic.Reference,
) -> SuspiciousModification:
    if exc.revision is not None or exc.locations:
        return exc
    locations = (new_ref,) if old_ref is None else (old_ref, new_ref)
    return SuspiciousModification(
        *exc.args,
        revision=new.revision,
        locations=locations,
    )


def _info_ref(handler) -> generic.Reference | None:
    try:
        return handler.trailer_view.get_value_as_reference(
            '/Info', optional=True
        )
    except misc.IndirectObjectExpected:
        return None
    except (KeyError, misc.PdfError):
        return None


def _xmp_ref(handler) -> generic.Reference | None:
    try:
        return handler.root.get_value_as_reference('/Metadata', optional=True)
    except misc.IndirectObjectExpected:
        return None
    except (KeyError, misc.PdfError):
        return None


def _assert_info_is_dictionary(handler, info_ref: generic.Reference):
    try:
        info_obj = handler.get_object(info_ref)
    except misc.PdfError as e:  # pragma: nocover
        raise SuspiciousModification(
            f"The /Info dictionary could not be read: {e}",
            revision=getattr(handler, 'revision', None),
            locations=(info_ref,),
        )
    if not isinstance(info_obj, generic.DictionaryObject) or isinstance(
        info_obj, generic.StreamObject
    ):
        raise SuspiciousModification(
            "/Info should be a reference to a plain dictionary object",
            revision=getattr(handler, 'revision', None),
            locations=(info_ref,),
        )


class DocInfoRule(WhitelistRule):
    """
    Rule that allows the ``/Info`` dictionary in the trailer to be updated.

    The rule clears updates to the information dictionary at whatever level
    the caller qualifies them, after checking that the dictionary remains a
    dictionary and that the reference bookkeeping stays sane. It does not
    inspect the contents of the dictionary; use
    :class:`.MetadataIdentityRule` if you want the identity semantics of the
    update to be validated against the XMP channel as well.
    """

    def apply(
        self, old: HistoricalResolver, new: HistoricalResolver
    ) -> Iterable[ReferenceUpdate]:
        # updates to /Info are always OK (and must be through indirect objects)
        # Removing the /Info dictionary is no big deal, since most readers
        # will fall back to older revisions regardless
        new_info_ref = _info_ref(new)
        if new_info_ref is None:
            return
        _assert_info_is_dictionary(new, new_info_ref)
        old_info_ref = _info_ref(old)
        yield from map(
            ReferenceUpdate.curry_ref(
                context_checked=Context.from_absolute(old, RawPdfPath('/Info'))
            ),
            safe_whitelist(old, old_info_ref, new_info_ref),
        )


class MetadataUpdateRule(WhitelistRule):
    """
    Rule to adjudicate updates to the XMP metadata stream.

    The content of the metadata isn't actually validated in any significant way;
    this class only checks whether the XML is well-formed.

    :param check_xml_syntax:
        Do a well-formedness check on the XML syntax. Default ``True``.
    :param always_refuse_stream_override:
        Always refuse to override the metadata stream if its object ID existed
        in a prior revision, including if the new stream overrides the old
        metadata stream and the syntax check passes. Default ``False``.

        .. note::
            In other situations, pyHanko will reject stream overrides on
            general principle, since combined with the fault-tolerance of some
            PDF readers, these can allow an attacker to manipulate parts of the
            signed content in subtle but significant ways.

            In case of the metadata stream, the risk is significantly mitigated
            thanks to the XML syntax check on both versions of the stream,
            but if you're feeling extra paranoid, you can turn the default
            behaviour back on by setting ``always_refuse_stream_override``
            to ``True``.
    """

    def __init__(
        self, check_xml_syntax=True, always_refuse_stream_override=False
    ):
        self.check_xml_syntax = check_xml_syntax
        self.always_refuse_stream_override = always_refuse_stream_override

    @staticmethod
    def is_well_formed_xml(metadata_ref: generic.Reference):
        """
        Checks whether the provided stream consists of well-formed XML data.
        Note that this does not perform any more advanced XML or XMP validation,
        the check is purely syntactic.

        :param metadata_ref:
            A reference to a (purported) metadata stream.
        :raises SuspiciousModification:
            if there are indications that the reference doesn't point to an XML
            stream.
        """
        metadata_stream = metadata_ref.get_object()

        if not isinstance(metadata_stream, generic.StreamObject):
            raise SuspiciousModification(
                "/Metadata should be a reference to a stream object",
                locations=(metadata_ref,),
            )

        try:
            from lxml import etree

            parser = etree.XMLParser(resolve_entities=False, encoding='utf-8')
            root = etree.fromstring(
                metadata_stream.read_data(DecodePurpose.XMP_METADATA),
                parser=parser,
            )
        except Exception as e:  # noqa: BLE001
            raise SuspiciousModification(
                "/Metadata XML syntax could not be validated",
                e,
                locations=(metadata_ref,),
            )
        if any(1 for _ in root.iter(etree.Entity)):
            raise SuspiciousModification(
                "XML entities found in XMP metadata",
                locations=(metadata_ref,),
            )
        # forgo a full parse here
        if root.tag != "{adobe:ns:meta/}xmpmeta":
            raise SuspiciousModification(
                "Metadata does not look like XMP", locations=(metadata_ref,)
            )

    def apply(
        self, old: HistoricalResolver, new: HistoricalResolver
    ) -> Iterable[ReferenceUpdate]:
        # /Metadata points to a stream, so we have to be careful allowing
        # object overrides!
        # we only approve the change if the metadata consists of well-formed xml
        # (note: this doesn't validate any XML schemata)

        def grab_metadata(root):
            try:
                return root.get_value_as_reference('/Metadata')
            except misc.IndirectObjectExpected:
                raise SuspiciousModification(
                    "/Metadata should be an indirect reference",
                    revision=getattr(new, 'revision', None),
                )
            except KeyError:
                return

        new_metadata_ref = grab_metadata(new.root)
        if new_metadata_ref is None:
            return  # nothing to do

        if self.check_xml_syntax:
            MetadataUpdateRule.is_well_formed_xml(new_metadata_ref)

        old_metadata_ref = grab_metadata(old.root)

        if self.check_xml_syntax and old_metadata_ref is not None:
            MetadataUpdateRule.is_well_formed_xml(old_metadata_ref)

        same_ref_ok = (
            old_metadata_ref == new_metadata_ref
            and not self.always_refuse_stream_override
        )
        if same_ref_ok or old.is_ref_unassignable(new_metadata_ref):
            yield ReferenceUpdate(
                new_metadata_ref,
                context_checked=Context.from_absolute(
                    old, RawPdfPath('/Root', '/Metadata')
                ),
            )
