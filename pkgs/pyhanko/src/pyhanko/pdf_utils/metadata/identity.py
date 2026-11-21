"""
Two-channel view of a document's descriptive metadata.

PDF documents can carry descriptive metadata in two places:

* the document information dictionary (``/Info`` in the trailer), and
* the XMP metadata stream (``/Metadata`` in the document catalog).

Both channels are meant to describe the same document, and authorship
information such as the title, the author, the subject and the creation date
is routinely duplicated in both. Unsynchronised updates can make the channels
disagree, which leaves readers to guess which claim is authoritative.

The classes in this module put the two channels on the same footing and expose
a normalised *identity view* of a document revision. Difference analysis tools
use it to reason about identity-level changes rather than raw object changes:
a title that is updated in both channels is a single identity change, whereas
two channels that make different claims about the same field constitute a
contradiction.

Metadata that cannot be interpreted is not silently ignored: it is recorded
as such, so that callers can take a stable decision about it.

.. versionadded:: 0.39.0
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.decode_limits import DecodePurpose

from . import model, xmp_xml

__all__ = [
    'IDENTITY_FIELDS',
    'INFO_IDENTITY_KEYS',
    'META_VERDICT_OUT_OF_SCOPE',
    'META_VERDICT_REJECTING',
    'ChannelSnapshot',
    'DocumentIdentity',
    'IdentityChannel',
    'IdentityFieldComparison',
    'IdentityFieldStatus',
    'IdentityValue',
    'MetadataIdentityReport',
    'MetadataIdentityVerdict',
    'analyse_metadata_identity',
    'document_identity',
]

IDENTITY_FIELDS = ('title', 'author', 'subject', 'created')
"""
The identity-relevant metadata fields, in a stable order.

``title``, ``author`` and ``subject`` are text values, and ``created`` is the
document's creation date.
"""

INFO_IDENTITY_KEYS = {
    'title': '/Title',
    'author': '/Author',
    'subject': '/Subject',
    'created': '/CreationDate',
}
"""
Mapping of identity fields to their keys in the document information
dictionary.
"""


class IdentityChannel:
    """
    Names of the two metadata channels.

    This is a plain class with string constants (rather than an enum) so that
    channel names serialise naturally in reports.
    """

    INFO = 'info'
    """
    The document information dictionary in the trailer.
    """

    XMP = 'xmp'
    """
    The XMP metadata stream referenced from the document catalog.
    """


class IdentityFieldStatus(misc.OrderedEnum):
    """
    Status of a single identity field between two revisions.

    The members are ordered by increasing severity, so ``max`` can be used to
    aggregate statuses.
    """

    UNCHANGED = 0
    """
    The field makes the same claim in both revisions.
    """

    UPDATED = 1
    """
    The identity value changed. If both channels carry the field, they agree
    on the new value, so this is a single identity-level change.
    """

    PRE_EXISTING_ANOMALY = 2
    """
    The field could not be interpreted, or the channels disagreed, in the same
    way in both revisions. The anomaly is therefore not attributable to the
    newer revision.
    """

    CONTRADICTORY = 3
    """
    The two channels make different claims about the field in the newer
    revision, and did not do so in the older one.
    """

    UNPARSEABLE = 4
    """
    The metadata for this field could not be interpreted in the newer
    revision, whereas it could be (or was absent) before.
    """


class MetadataIdentityVerdict(misc.OrderedEnum):
    """
    Aggregate identity-level judgment for a pair of revisions.

    This is the "stable conclusion" that difference analysis should act on.
    Each identity-relevant scenario maps to exactly one of these values:

    * :attr:`NO_CHANGES`: nothing identity-relevant happened;
    * :attr:`CONSISTENT_UPDATE`: the identity changed, and the channels that
      carry the affected fields agree -- this is a legitimate update *within
      the signature's coverage*;
    * :attr:`PRE_EXISTING_ANOMALY`: the revision inherited a defect from its
      base, so it is not attributable to the update;
    * :attr:`CHANNEL_REPLACEMENT`: a channel's backing object was replaced by
      an object that already existed, which lies outside the identity
      semantics the signature covers;
    * :attr:`CONTRADICTION`: the channels disagree about an identity field,
      and this revision introduced (or altered) the disagreement;
    * :attr:`UNPARSEABLE`: the metadata can no longer be interpreted.

    The members are ordered by increasing severity. The verdicts that a
    difference policy cannot accept as an identity update are
    :attr:`CHANNEL_REPLACEMENT`, :attr:`CONTRADICTION` and
    :attr:`UNPARSEABLE`; see :data:`META_VERDICT_REJECTING` and
    :data:`META_VERDICT_OUT_OF_SCOPE`.
    """

    NO_CHANGES = 0
    """
    The document's identity is unchanged.
    """

    CONSISTENT_UPDATE = 1
    """
    The document's identity changed, but the change is coherent across the
    channels that carry the affected fields. This is the legitimate update
    that stays within the signature's coverage.
    """

    PRE_EXISTING_ANOMALY = 2
    """
    No new identity change, but the metadata contains a pre-existing anomaly
    (an unparseable field or a channel disagreement) that the revision
    inherited from its base. The anomaly is not attributable to this update.
    """

    CHANNEL_REPLACEMENT = 3
    """
    The revision replaces a metadata channel's backing object, rather than
    updating the identity it asserts. Examples: re-pointing ``/Metadata`` at
    an object that already existed in the base revision, or introducing a
    channel that is backed by a pre-existing object.

    This is not an identity change, so it falls outside the identity
    semantics covered by the signature.
    """

    CONTRADICTION = 4
    """
    The newer revision's metadata channels contradict each other on an
    identity field, and this contradiction is new or altered relative to the
    base revision.
    """

    UNPARSEABLE = 5
    """
    The newer revision's metadata cannot be interpreted, while the base
    revision's could (or the unparseable data differs from the inherited
    unparseable data).
    """


META_VERDICT_REJECTING = frozenset(
    {
        MetadataIdentityVerdict.CONTRADICTION,
        MetadataIdentityVerdict.UNPARSEABLE,
    }
)
"""
Verdicts that a difference policy cannot accept, regardless of the
modification level at which the change was submitted.
"""

META_VERDICT_OUT_OF_SCOPE = frozenset(
    {MetadataIdentityVerdict.CHANNEL_REPLACEMENT}
)
"""
Verdicts that describe a replacement outside the identity semantics that a
signature covers. Such a change may still be cleared by other rules, but not
as an identity update.
"""


@dataclass(frozen=True)
class IdentityValue:
    """
    A single identity field as extracted from one metadata channel.
    """

    value: str | tuple[str, ...] | datetime | None

    raw: str | None = None
    """
    A human-readable rendering of the value as found, for reporting purposes.
    """

    error: str | None = None
    """
    If not ``None``, the field was present but could not be interpreted.
    """

    fingerprint: bytes | None = field(default=None, repr=False)
    """
    An opaque fingerprint of the raw data, used to decide whether an
    unparseable value is inherited from an earlier revision.
    """

    @property
    def is_unparseable(self) -> bool:
        """
        Whether the field was present but could not be interpreted.
        """
        return self.error is not None

    def render(self) -> str | None:
        """
        Render the value for inclusion in a report.
        """
        if self.error is not None:
            return f"<unparseable: {self.error}>"
        if self.value is None:
            return None
        if isinstance(self.value, tuple):
            return ', '.join(self.value)
        if isinstance(self.value, datetime):
            return self.value.isoformat()
        return self.value


@dataclass(frozen=True)
class ChannelSnapshot:
    """
    The identity fields as asserted by one metadata channel in one revision.
    """

    channel: str
    """
    One of the :class:`IdentityChannel` constants.
    """

    present: bool
    """
    Whether the channel exists in the document at all.
    """

    fields: Mapping[str, IdentityValue] = field(default_factory=dict)
    """
    The identity fields asserted by the channel, keyed by field name.
    Missing keys mean that the channel makes no claim about that field.
    """

    error: str | None = None
    """
    If not ``None``, the channel exists but could not be interpreted as a
    whole (e.g. because the XMP stream is not well-formed).
    """

    ref: generic.Reference | None = None
    """
    The indirect reference backing the channel, if any.
    """

    fingerprint: bytes | None = field(default=None, repr=False)
    """
    An opaque fingerprint of the channel, used to decide whether an
    unparseable value or a channel rewrite is inherited from an earlier
    revision.

    For channels that could be interpreted, this is a fingerprint of the
    channel's identity claims (not of its raw bytes), so that mere rewrites
    are not confused with identity changes. For channels that could not be
    interpreted, it is a fingerprint of the raw (undecodable) data.
    """


@dataclass(frozen=True)
class DocumentIdentity:
    """
    The identity view of a document revision, across both metadata channels.
    """

    info: ChannelSnapshot
    """
    The document information dictionary view.
    """

    xmp: ChannelSnapshot
    """
    The XMP metadata stream view.
    """

    def snapshot(self, channel: str) -> ChannelSnapshot:
        """
        Look up the snapshot for a channel.
        """
        if channel == IdentityChannel.INFO:
            return self.info
        elif channel == IdentityChannel.XMP:
            return self.xmp
        raise ValueError(f"Unknown identity channel {channel!r}")

    @property
    def channels(self) -> tuple[ChannelSnapshot, ...]:
        """
        Both channel snapshots, in a stable order.
        """
        return self.info, self.xmp

    @property
    def locations(self) -> tuple[generic.Reference, ...]:
        """
        The object references backing the channels, in a stable order.
        """
        return tuple(
            sorted(
                {
                    snapshot.ref
                    for snapshot in self.channels
                    if snapshot.ref is not None
                },
                key=lambda ref: (ref.idnum, ref.generation),
            )
        )


@dataclass(frozen=True)
class IdentityFieldComparison:
    """
    Comparison of one identity field across two revisions.
    """

    field: str
    """
    The name of the identity field.
    """

    status: IdentityFieldStatus
    """
    The field-level status.
    """

    old_info: IdentityValue | None = None
    """
    The old value in the information dictionary.
    """

    old_xmp: IdentityValue | None = None
    """
    The old value in the XMP stream.
    """

    new_info: IdentityValue | None = None
    """
    The new value in the information dictionary.
    """

    new_xmp: IdentityValue | None = None
    """
    The new value in the XMP stream.
    """

    detail: str | None = None
    """
    Human-readable explanation, if any.
    """

    def as_dict(self) -> dict:
        """
        Return a JSON-serialisable representation of this comparison.
        """
        return {
            'field': self.field,
            'status': self.status.name,
            'old': {
                IdentityChannel.INFO: _render_value(self.old_info),
                IdentityChannel.XMP: _render_value(self.old_xmp),
            },
            'new': {
                IdentityChannel.INFO: _render_value(self.new_info),
                IdentityChannel.XMP: _render_value(self.new_xmp),
            },
            'detail': self.detail,
        }


@dataclass(frozen=True)
class MetadataIdentityReport:
    """
    Identity-level comparison of the metadata in two revisions.

    Unlike a raw object diff, the report describes *identity semantics*: one
    :class:`IdentityFieldComparison` per identity field, regardless of how
    many channels were touched.
    """

    base_revision: int
    """
    Revision index of the older revision.
    """

    revision: int
    """
    Revision index of the newer revision.
    """

    old: DocumentIdentity
    """
    The identity view of the older revision.
    """

    new: DocumentIdentity
    """
    The identity view of the newer revision.
    """

    fields: tuple[IdentityFieldComparison, ...]
    """
    Field-level comparisons, in the order of :data:`IDENTITY_FIELDS`.
    """

    channel_events: tuple[str, ...] = ()
    """
    Records channel-level events such as ``xmp:added`` or ``info:removed``.
    """

    replaced_channels: tuple[str, ...] = ()
    """
    Channels whose backing object was redirected to an object that already
    existed in the base revision, rather than being updated in place or
    replaced by a fresh object. Such a redirection is not an identity update;
    it is a replacement outside the signature's coverage.

    Reported in the order of :attr:`DocumentIdentity.channels`.
    """

    verdict: MetadataIdentityVerdict = MetadataIdentityVerdict.NO_CHANGES
    """
    The aggregate, decisive judgment for this pair of revisions.
    """

    @property
    def in_scope(self) -> bool:
        """
        Whether the change is something a difference policy can treat as a
        metadata update at all, i.e. not a contradiction, not unparseable, and
        not an out-of-scope channel replacement.
        """
        return not self.rejecting and not self.out_of_scope

    @property
    def out_of_scope(self) -> bool:
        """
        Whether the change is a replacement that falls outside the covered
        identity semantics.
        """
        return self.verdict in META_VERDICT_OUT_OF_SCOPE

    @property
    def rejecting(self) -> bool:
        """
        Whether the verdict cannot be accepted by a difference policy as an
        identity update: contradictions, unparseable metadata and out-of-scope
        channel replacements all qualify.
        """
        return self.verdict in (
            META_VERDICT_REJECTING | META_VERDICT_OUT_OF_SCOPE
        )

    @property
    def changed_fields(self) -> tuple[str, ...]:
        """
        The names of all fields whose status is :attr:`UPDATED`.
        """
        return tuple(
            cmp.field
            for cmp in self.fields
            if cmp.status == IdentityFieldStatus.UPDATED
        )

    @property
    def problematic_fields(self) -> tuple[IdentityFieldComparison, ...]:
        """
        The comparisons that are neither unchanged nor a clean update.
        """
        return tuple(
            cmp
            for cmp in self.fields
            if cmp.status
            not in (IdentityFieldStatus.UNCHANGED, IdentityFieldStatus.UPDATED)
        )

    @property
    def newly_problematic_fields(self) -> tuple[IdentityFieldComparison, ...]:
        """
        The comparisons whose problem is attributable to the newer revision,
        i.e. excluding anomalies that were inherited from the base revision.
        """
        return tuple(
            cmp
            for cmp in self.fields
            if cmp.status
            in (
                IdentityFieldStatus.CONTRADICTORY,
                IdentityFieldStatus.UNPARSEABLE,
            )
        )

    @property
    def locations(self) -> tuple[generic.Reference, ...]:
        """
        All object references that back the metadata in either revision,
        in a stable order.
        """
        return tuple(
            sorted(
                set(self.old.locations) | set(self.new.locations),
                key=lambda ref: (ref.idnum, ref.generation),
            )
        )

    def as_dict(self) -> dict:
        """
        Return a JSON-serialisable, deterministically ordered representation
        of this report.
        """
        return {
            'base_revision': self.base_revision,
            'revision': self.revision,
            'verdict': self.verdict.name,
            'channel_events': list(self.channel_events),
            'replaced_channels': list(self.replaced_channels),
            'locations': [
                f"{ref.idnum} {ref.generation} R" for ref in self.locations
            ],
            'fields': [cmp.as_dict() for cmp in self.fields],
        }

    def summary(self) -> str:
        """
        Return a deterministic, human-readable summary of this report.
        """
        fields = ', '.join(
            f"{cmp.field}={cmp.status.name}" for cmp in self.fields
        )
        events = (
            f"; channels: {', '.join(self.channel_events)}"
            if self.channel_events
            else ''
        )
        replaced = (
            f"; replaced: {', '.join(self.replaced_channels)}"
            if self.replaced_channels
            else ''
        )
        return (
            f"Metadata identity between revisions {self.base_revision} and "
            f"{self.revision}: {self.verdict.name} ({fields})"
            f"{events}{replaced}"
        )


def _render_value(value: IdentityValue | None) -> str | None:
    return value.render() if value is not None else None


def _normalise_text(text: str) -> str:
    # Whitespace differences between the channels are not identity-relevant;
    # XMP and Info producers routinely disagree about trailing spaces and
    # line folding.
    return ' '.join(text.split())


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).replace(microsecond=0)


def _decode_text_bytes(data: bytes) -> str | None:
    if data.startswith((b'\xfe\xff', b'\xff\xfe')):
        try:
            return data.decode('utf-16')
        except UnicodeDecodeError:
            return None
    elif data.startswith(b'\xef\xbb\xbf'):
        try:
            return data[3:].decode('utf-8')
        except UnicodeDecodeError:
            return None
    try:
        return generic.decode_pdfdocencoding(data)
    except UnicodeDecodeError:
        return None


def _text_value(obj, as_author=False) -> IdentityValue:
    text: str | None
    if isinstance(obj, generic.TextStringObject):
        text = str(obj)
    elif isinstance(obj, generic.ByteStringObject):
        text = _decode_text_bytes(bytes(obj))
        if text is None:
            return IdentityValue(None, error="undecodable string")
    else:
        return IdentityValue(None, error="not a text string")
    normalised = _normalise_text(text)
    # The info dictionary represents the author as a single string, whereas
    # XMP models it as a list of names. Normalise the info dictionary's
    # representation to a one-element tuple so the two are comparable.
    value: str | tuple[str, ...] = (normalised,) if as_author else normalised
    return IdentityValue(
        value,
        raw=text,
        fingerprint=repr(obj).encode('utf-8', 'replace'),
    )


def _date_value(obj) -> IdentityValue:
    if not isinstance(obj, generic.TextStringObject):
        return IdentityValue(None, error="not a date string")
    date_str = str(obj)
    try:
        dt = generic.parse_pdf_date(date_str, strict=False)
    except (misc.PdfReadError, TypeError, ValueError) as e:
        return IdentityValue(
            None,
            raw=date_str,
            error=str(e),
            fingerprint=date_str.encode('utf-8', 'replace'),
        )
    return IdentityValue(
        _to_utc(dt),
        raw=date_str,
        fingerprint=date_str.encode('utf-8', 'replace'),
    )


def _read_info_channel(resolver) -> ChannelSnapshot:
    try:
        trailer = resolver.trailer_view
    except misc.PdfError as e:  # pragma: nocover
        return ChannelSnapshot(
            IdentityChannel.INFO, present=True, error=f"unreadable trailer: {e}"
        )

    try:
        raw = trailer.raw_get('/Info')
    except KeyError:
        return ChannelSnapshot(IdentityChannel.INFO, present=False)

    ref = raw.reference if isinstance(raw, generic.IndirectObject) else None
    if ref is not None:
        try:
            info_obj = resolver.get_object(ref)
        except misc.PdfError as e:
            return ChannelSnapshot(
                IdentityChannel.INFO,
                present=True,
                ref=ref,
                error=f"unreadable /Info dictionary: {e}",
                fingerprint=repr(raw).encode('utf-8', 'replace'),
            )
    else:
        info_obj = raw

    if not isinstance(info_obj, generic.DictionaryObject) or isinstance(
        info_obj, generic.StreamObject
    ):
        return ChannelSnapshot(
            IdentityChannel.INFO,
            present=True,
            ref=ref,
            error="/Info is not a plain dictionary",
            fingerprint=repr(info_obj).encode('utf-8', 'replace'),
        )

    fields: dict[str, IdentityValue] = {}
    for name in IDENTITY_FIELDS:
        try:
            field_obj = info_obj.raw_get(INFO_IDENTITY_KEYS[name])
        except KeyError:
            continue
        if isinstance(field_obj, generic.IndirectObject):
            try:
                field_obj = resolver.get_object(field_obj.reference)
            except misc.PdfError as e:
                fields[name] = IdentityValue(
                    None, error=f"unreadable value: {e}"
                )
                continue
        if name == 'created':
            fields[name] = _date_value(field_obj)
        elif name == 'author':
            fields[name] = _text_value(field_obj, as_author=True)
        else:
            fields[name] = _text_value(field_obj)
    return ChannelSnapshot(
        IdentityChannel.INFO,
        present=True,
        ref=ref,
        fields=fields,
        fingerprint=_fields_fingerprint(fields),
    )


def _xmp_field(roots, name: model.ExpandedName):
    for root in roots:
        try:
            return root[name]
        except KeyError:
            continue
    return None


def _xmp_text_value(value: model.XmpValue) -> IdentityValue:
    text: str
    if isinstance(value.value, str):
        text = value.value
    elif isinstance(value.value, model.XmpArray):
        simple = [
            entry
            for entry in value.value.entries
            if isinstance(entry.value, str)
        ]
        if not simple:
            # An empty (or non-textual) alternative array makes no claim.
            return IdentityValue(None)
        focus = next(
            (entry for entry in simple if entry.qualifiers.lang == "x-default"),
            simple[0],
        )
        assert isinstance(focus.value, str)
        text = focus.value
    else:
        return IdentityValue(None, error="not a text value")
    return IdentityValue(
        _normalise_text(text),
        raw=text,
        fingerprint=text.encode('utf-8', 'replace'),
    )


def _xmp_author_value(value: model.XmpValue) -> IdentityValue:
    names: tuple[str, ...]
    if isinstance(value.value, str):
        names = (_normalise_text(value.value),)
    elif isinstance(value.value, model.XmpArray):
        names = tuple(
            _normalise_text(entry.value)
            for entry in value.value.entries
            if isinstance(entry.value, str)
        )
        if not names:
            return IdentityValue(None)
    else:
        return IdentityValue(None, error="not a text value")
    return IdentityValue(
        names,
        raw=', '.join(names),
        fingerprint='\x00'.join(names).encode('utf-8', 'replace'),
    )


def _xmp_date_value(value: model.XmpValue) -> IdentityValue:
    if not isinstance(value.value, str):
        return IdentityValue(None, error="not a date string")
    date_str = value.value
    try:
        dt = misc.isoparse(date_str)
    except (ValueError, OverflowError) as e:
        return IdentityValue(
            None,
            raw=date_str,
            error=str(e),
            fingerprint=date_str.encode('utf-8', 'replace'),
        )
    return IdentityValue(
        _to_utc(dt),
        raw=date_str,
        fingerprint=date_str.encode('utf-8', 'replace'),
    )


def _parse_xmp_data(data: bytes) -> list[model.XmpStructure]:
    return xmp_xml.parse_xmp(BytesIO(data))


def _read_xmp_channel(resolver) -> ChannelSnapshot:
    try:
        root = resolver.root
        raw = root.raw_get('/Metadata')
    except KeyError:
        return ChannelSnapshot(IdentityChannel.XMP, present=False)
    except misc.PdfError as e:  # pragma: nocover
        return ChannelSnapshot(
            IdentityChannel.XMP,
            present=True,
            error=f"unreadable document catalog: {e}",
        )

    if not isinstance(raw, generic.IndirectObject):
        return ChannelSnapshot(
            IdentityChannel.XMP,
            present=True,
            error="/Metadata is not an indirect reference",
            fingerprint=repr(raw).encode('utf-8', 'replace'),
        )

    ref = raw.reference
    try:
        metadata_stream = resolver.get_object(ref)
    except misc.PdfError as e:
        return ChannelSnapshot(
            IdentityChannel.XMP,
            present=True,
            ref=ref,
            error=f"unreadable /Metadata stream: {e}",
        )
    if not isinstance(metadata_stream, generic.StreamObject):
        return ChannelSnapshot(
            IdentityChannel.XMP,
            present=True,
            ref=ref,
            error="/Metadata does not point to a stream",
            fingerprint=repr(metadata_stream).encode('utf-8', 'replace'),
        )

    try:
        data = metadata_stream.read_data(DecodePurpose.XMP_METADATA)
    except (misc.PdfError, ValueError) as e:
        return ChannelSnapshot(
            IdentityChannel.XMP,
            present=True,
            ref=ref,
            error=f"could not decode /Metadata stream: {e}",
        )

    try:
        roots = _parse_xmp_data(data)
    except Exception as e:  # noqa: BLE001
        # Deliberately broad: the XMP parser processes untrusted input, and a
        # failure to interpret it must map to a stable "unparseable"
        # conclusion rather than an exception that escapes difference
        # analysis. (This mirrors the well-formedness check in
        # MetadataUpdateRule.)
        return ChannelSnapshot(
            IdentityChannel.XMP,
            present=True,
            ref=ref,
            error=f"could not interpret /Metadata: {e}",
            fingerprint=data,
        )

    fields: dict[str, IdentityValue] = {}
    title = _xmp_field(roots, model.DC_TITLE)
    if title is not None:
        fields['title'] = _xmp_text_value(title)
    author = _xmp_field(roots, model.DC_CREATOR)
    if author is not None:
        fields['author'] = _xmp_author_value(author)
    subject = _xmp_field(roots, model.DC_DESCRIPTION)
    if subject is not None:
        fields['subject'] = _xmp_text_value(subject)
    created = _xmp_field(roots, model.XMP_CREATEDATE)
    if created is not None:
        fields['created'] = _xmp_date_value(created)
    return ChannelSnapshot(
        IdentityChannel.XMP,
        present=True,
        ref=ref,
        fields=fields,
        fingerprint=_fields_fingerprint(fields),
    )


def document_identity(resolver) -> DocumentIdentity:
    """
    Extract the two-channel identity view of a document revision.

    The result is memoised on the resolver, since identity extraction involves
    decoding and parsing the XMP stream, and difference analysis routinely
    asks for the same revision more than once.

    :param resolver:
        A :class:`~pyhanko.pdf_utils.reader.HistoricalResolver` (or any
        handler exposing the same revision-scoped object access).
    :return:
        A :class:`DocumentIdentity` object.
    """
    # Only memoise on immutable revision views; a writer can change under our
    # feet, so caching its identity view would go stale.
    cacheable = getattr(resolver, 'revision', None) is not None
    if cacheable:
        cached = getattr(resolver, '_cached_document_identity', None)
        if cached is not None:
            return cached
    identity = DocumentIdentity(
        info=_read_info_channel(resolver), xmp=_read_xmp_channel(resolver)
    )
    if cacheable:
        try:
            resolver._cached_document_identity = identity
        except AttributeError:  # pragma: nocover
            pass
    return identity


_ABSENT = 'absent'
_VALUE = 'value'
_UNPARSEABLE = 'unparseable'


def _fields_fingerprint(fields: Mapping[str, IdentityValue]) -> bytes:
    """
    Fingerprint a channel's identity claims, so that channel-level events can
    distinguish an in-place update from a wholesale replacement.
    """
    parts = []
    for name in IDENTITY_FIELDS:
        value = fields.get(name)
        if value is None:
            parts.append(f"{name}=<absent>")
        else:
            parts.append(f"{name}={value.render() or ''}")
    return '\x00'.join(parts).encode('utf-8', 'replace')


def _field_state(
    snapshot: ChannelSnapshot, name: str
) -> tuple[str, object, bytes | None]:
    if snapshot.error is not None:
        return _UNPARSEABLE, None, snapshot.fingerprint
    value = snapshot.fields.get(name)
    if value is None:
        return _ABSENT, None, None
    if value.is_unparseable:
        return _UNPARSEABLE, None, value.fingerprint
    if value.value is None:
        return _ABSENT, None, None
    return _VALUE, value.value, value.fingerprint


def _author_values_match(one: tuple[str, ...], other: tuple[str, ...]) -> bool:
    # Authors are a set of names in XMP, but a single string in the info
    # dictionary. Accept the common flattenings so that perfectly ordinary
    # documents don't trip the contradiction check.
    if one == other or set(one) == set(other):
        return True
    for names, joined in ((one, other), (other, one)):
        if len(names) == 1:
            candidate = names[0]
            if candidate in (', '.join(joined), '; '.join(joined)):
                return True
    return False


def _values_match(name: str, one, other) -> bool:
    if name == 'author':
        if not isinstance(one, tuple) or not isinstance(other, tuple):
            return False
        return _author_values_match(one, other)
    return one == other


def _has_conflict(name: str, claims: list[tuple[str, object]]) -> bool:
    for ix, (_, one) in enumerate(claims):
        for _, other in claims[ix + 1 :]:
            if not _values_match(name, one, other):
                return True
    return False


def _same_claims(
    name: str,
    old_claims: list[tuple[str, object]],
    new_claims: list[tuple[str, object]],
) -> bool:
    """
    Check whether two sets of channel claims are equivalent, i.e. whether the
    same channel makes the same claim in both revisions.
    """
    if len(old_claims) != len(new_claims):
        return False
    remaining = list(new_claims)
    for channel, value in old_claims:
        for ix, (other_channel, other_value) in enumerate(remaining):
            if channel == other_channel and _values_match(
                name, value, other_value
            ):
                del remaining[ix]
                break
        else:
            return False
    return True


def _compare_field(
    name: str,
    old: DocumentIdentity,
    new: DocumentIdentity,
) -> IdentityFieldComparison:
    old_states = {
        snapshot.channel: _field_state(snapshot, name)
        for snapshot in old.channels
    }
    new_states = {
        snapshot.channel: _field_state(snapshot, name)
        for snapshot in new.channels
    }

    unparseable = {
        channel
        for channel, (state, _, _) in new_states.items()
        if state == _UNPARSEABLE
    }
    if unparseable:
        inherited = all(
            old_states[channel][0] == _UNPARSEABLE
            and old_states[channel][2] is not None
            and old_states[channel][2] == new_states[channel][2]
            for channel in unparseable
        )
        status = (
            IdentityFieldStatus.PRE_EXISTING_ANOMALY
            if inherited
            else IdentityFieldStatus.UNPARSEABLE
        )
        detail = (
            "unparseable metadata inherited from the base revision"
            if inherited
            else "metadata could not be interpreted"
        )
    else:
        old_claims = [
            (channel, value)
            for channel, (state, value, _) in old_states.items()
            if state == _VALUE
        ]
        new_claims = [
            (channel, value)
            for channel, (state, value, _) in new_states.items()
            if state == _VALUE
        ]
        old_conflict = _has_conflict(name, old_claims)
        new_conflict = _has_conflict(name, new_claims)
        if new_conflict:
            # A contradiction that was already present in the base revision
            # with exactly the same competing claims is an inherited defect,
            # not something this revision is responsible for.
            if old_conflict and _same_claims(name, old_claims, new_claims):
                status = IdentityFieldStatus.PRE_EXISTING_ANOMALY
                detail = (
                    "the metadata channels still disagree on this field "
                    "in the same way as in the base revision"
                )
            else:
                status = IdentityFieldStatus.CONTRADICTORY
                detail = "the metadata channels disagree on this field"
        elif old_conflict:
            status = IdentityFieldStatus.UPDATED
            detail = "the channels now agree, resolving an earlier conflict"
        elif not old_claims and not new_claims:
            status = IdentityFieldStatus.UNCHANGED
            detail = None
        elif len(old_claims) == 1 and len(new_claims) == 1:
            status = (
                IdentityFieldStatus.UNCHANGED
                if _values_match(name, old_claims[0][1], new_claims[0][1])
                else IdentityFieldStatus.UPDATED
            )
            detail = None
        else:
            # Channel sets differ, but every claim that survived matches.
            old_values = {value for _, value in old_claims}
            new_values = {value for _, value in new_claims}
            if old_values and new_values:
                unchanged = all(
                    any(_values_match(name, one, other) for other in new_values)
                    for one in old_values
                ) and all(
                    any(_values_match(name, one, other) for other in old_values)
                    for one in new_values
                )
            else:
                unchanged = not old_values and not new_values
            status = (
                IdentityFieldStatus.UNCHANGED
                if unchanged
                else IdentityFieldStatus.UPDATED
            )
            detail = None

    return IdentityFieldComparison(
        field=name,
        status=status,
        old_info=old.info.fields.get(name),
        old_xmp=old.xmp.fields.get(name),
        new_info=new.info.fields.get(name),
        new_xmp=new.xmp.fields.get(name),
        detail=detail,
    )


def _channel_events(old: DocumentIdentity, new: DocumentIdentity) -> tuple:
    events = []
    for old_snapshot, new_snapshot in zip(old.channels, new.channels):
        channel = new_snapshot.channel
        if old_snapshot.present and not new_snapshot.present:
            events.append(f"{channel}:removed")
        elif not old_snapshot.present and new_snapshot.present:
            events.append(f"{channel}:added")
        elif old_snapshot.present and new_snapshot.present:
            if (
                old_snapshot.fingerprint is not None
                and new_snapshot.fingerprint is not None
                and old_snapshot.fingerprint != new_snapshot.fingerprint
            ):
                events.append(f"{channel}:updated")
            elif (
                old_snapshot.ref is not None
                and new_snapshot.ref is not None
                and old_snapshot.ref != new_snapshot.ref
            ):
                # The channel was re-serialised without any identity-relevant
                # change.
                events.append(f"{channel}:rewritten")
    return tuple(events)


def _verdict_for(
    comparisons: tuple[IdentityFieldComparison, ...],
    replaced_channels: tuple[str, ...],
) -> MetadataIdentityVerdict:
    statuses = {cmp.status for cmp in comparisons}
    if replaced_channels:
        # The revision swapped out the object backing a channel for one that
        # already existed. Whatever the new data says, the channel was not
        # *updated* within the scope the signature covers; it was replaced
        # from outside that scope. This takes precedence over the
        # interpretation of the substituted data itself.
        return MetadataIdentityVerdict.CHANNEL_REPLACEMENT
    elif IdentityFieldStatus.UNPARSEABLE in statuses:
        return MetadataIdentityVerdict.UNPARSEABLE
    elif IdentityFieldStatus.CONTRADICTORY in statuses:
        return MetadataIdentityVerdict.CONTRADICTION
    elif IdentityFieldStatus.UPDATED in statuses:
        return MetadataIdentityVerdict.CONSISTENT_UPDATE
    elif IdentityFieldStatus.PRE_EXISTING_ANOMALY in statuses:
        return MetadataIdentityVerdict.PRE_EXISTING_ANOMALY
    else:
        return MetadataIdentityVerdict.NO_CHANGES


def _replaced_channels(
    old: DocumentIdentity,
    new: DocumentIdentity,
    was_unassignable,
) -> tuple[str, ...]:
    """
    Determine which channels were redirected at a pre-existing object.

    A channel is considered *replaced* if its backing reference in the new
    revision differs from the old one, and the new reference was already in
    scope before this revision. Updating a stream in place (same reference) or
    pointing a channel at a freshly allocated object is normal, and is not
    reported here.
    """
    replaced = []
    for old_snapshot, new_snapshot in zip(old.channels, new.channels):
        if not new_snapshot.present or new_snapshot.ref is None:
            continue
        if old_snapshot.present and old_snapshot.ref == new_snapshot.ref:
            continue
        if was_unassignable is not None and not was_unassignable(
            new_snapshot.ref
        ):
            replaced.append(new_snapshot.channel)
    return tuple(replaced)


def analyse_metadata_identity(old, new, was_unassignable=None):
    """
    Compare the descriptive metadata of two document revisions at the
    identity level.

    The comparison unifies the information dictionary and the XMP metadata
    stream: a change that is applied consistently in both channels is
    reported as a single :attr:`~IdentityFieldStatus.UPDATED` field, not as
    two independent object changes. Conversely, channels that make different
    claims about the same field are reported as a contradiction.

    :param old:
        The older revision, as a
        :class:`~pyhanko.pdf_utils.reader.HistoricalResolver`.
    :param new:
        The newer revision, as a
        :class:`~pyhanko.pdf_utils.reader.HistoricalResolver`.
    :param was_unassignable:
        Optional predicate that reports whether an object reference was
        already in scope in the base revision. When provided, the comparison
        can distinguish a metadata *update* from a channel that was
        *replaced* by a pre-existing object. Defaults to
        ``getattr(old, 'is_ref_unassignable', None)``.
    :return:
        A :class:`MetadataIdentityReport`.
    """
    if was_unassignable is None:
        was_unassignable = getattr(old, 'is_ref_unassignable', None)
    old_identity = document_identity(old)
    new_identity = document_identity(new)
    comparisons = tuple(
        _compare_field(name, old_identity, new_identity)
        for name in IDENTITY_FIELDS
    )
    replaced_channels = _replaced_channels(
        old_identity, new_identity, was_unassignable
    )
    return MetadataIdentityReport(
        base_revision=getattr(old, 'revision', -1),
        revision=getattr(new, 'revision', -1),
        old=old_identity,
        new=new_identity,
        fields=comparisons,
        channel_events=_channel_events(old_identity, new_identity),
        replaced_channels=replaced_channels,
        verdict=_verdict_for(comparisons, replaced_channels),
    )
