"""
Tests for two-channel document identity analysis in difference analysis.

The metadata of a signed PDF can be updated in two places: the information
dictionary (``/Info``) and the XMP metadata stream (``/Metadata``). These tests
check that the difference analysis interprets title, author, subject and
creation date changes as one identity semantics across both channels, and
that legitimate updates, out-of-scope replacements, contradictions and
unparseable metadata each receive a stable verdict with per-revision
location information.
"""

from datetime import UTC, datetime
from io import BytesIO

import pytest
from freezegun.api import freeze_time
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.metadata import model, xmp_xml
from pyhanko.pdf_utils.metadata.identity import (
    IdentityChannel,
    IdentityFieldStatus,
    MetadataIdentityVerdict,
    analyse_metadata_identity,
    document_identity,
)
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    MetadataIdentityRule,
    ModificationLevel,
    StandardDiffPolicy,
    SuspiciousModification,
    XrefStreamRule,
)
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_testing_commons.test_data.samples import simple_page
from pyhanko_testing_commons.test_utils.signing_commons import (
    FROM_CA,
    simple_v_context,
)

BASE_META = model.DocumentMetadata(
    title="Title A",
    author="Alice",
    subject="Subject A",
    created=datetime(2020, 1, 1, tzinfo=UTC),
    last_modified=None,
)

INFO = {
    '/Title': "Title A",
    '/Author': "Alice",
    '/Subject': "Subject A",
    '/CreationDate': "D:20200101000000Z",
}


def _with_info(w, values: dict):
    info = generic.DictionaryObject(
        {k: generic.pdf_string(v) for k, v in values.items()}
    )
    w.set_info(info)


def _build_two_channel_doc() -> bytes:
    """
    Build a minimal document that carries the same identity in its info
    dictionary and in its XMP metadata stream.
    """
    w = PdfFileWriter()
    w.insert_page(simple_page(w, 'Page 1'))
    w.output_version = (1, 7)
    _with_info(w, INFO)
    w.update_root()
    out = BytesIO()
    w.write(out)

    w = IncrementalPdfFileWriter(BytesIO(out.getvalue()))
    stream = xmp_xml.MetadataStream.from_xmp(
        xmp_xml.update_xmp_with_meta(BASE_META)
    )
    w.root['/Metadata'] = w.add_object(stream)
    w.update_root()
    # Suppress automated metadata management so the XMP packet stays exactly
    # as written; the test wants full control over both channels.
    w._update_meta = lambda: None
    out = BytesIO()
    w.write(out)
    return out.getvalue()


@freeze_time('2021-06-01')
def _sign(data: bytes) -> bytes:
    return signers.sign_pdf(
        IncrementalPdfFileWriter(BytesIO(data)),
        signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA,
    ).getvalue()


def _add_revision(
    data: bytes,
    info_updates: dict | None = None,
    xmp_meta: model.DocumentMetadata | None = None,
    corrupt_xmp: bool = False,
) -> bytes:
    """
    Append an incremental revision that updates the info dictionary and/or the
    XMP metadata stream.
    """
    w = IncrementalPdfFileWriter(BytesIO(data))
    w._update_meta = lambda: None
    changed = False
    if info_updates is not None:
        current = dict(w.trailer['/Info'].get_object())
        current.update(
            {k: generic.pdf_string(v) for k, v in info_updates.items()}
        )
        w.set_info(w.add_object(generic.DictionaryObject(current)))
        changed = True
    if xmp_meta is not None or corrupt_xmp:
        metadata_ref = w.root.get_value_as_reference('/Metadata')
        if corrupt_xmp:
            stream = metadata_ref.get_object()
            stream.strip_filters()
            stream._data = b'<x:xmpmeta'
            stream._encoded_data = None
            w.mark_update(metadata_ref)
        else:
            old_stream = w.prev.get_object(
                metadata_ref, as_metadata_stream=True
            )
            new_stream = xmp_xml.MetadataStream.from_xmp(
                xmp_xml.update_xmp_with_meta(xmp_meta, roots=old_stream.xmp)
            )
            w.root['/Metadata'] = w.add_object(new_stream)
        changed = True
    if changed:
        w.update_root()
    out = BytesIO()
    w.write(out)
    return out.getvalue()


def _latest_identity(data: bytes):
    reader = PdfFileReader(BytesIO(data))
    return reader, reader.get_historical_resolver(
        reader.xrefs.total_revisions - 1
    )


def _identity_report(data_a: bytes, data_b: bytes):
    _, old = _latest_identity(data_a)
    _, new = _latest_identity(data_b)
    return analyse_metadata_identity(old, new)


def _status(data: bytes, policy=None):
    reader = PdfFileReader(BytesIO(data))
    sig = reader.embedded_signatures[0]
    return (
        sig,
        validate_pdf_signature(
            sig, simple_v_context(), diff_policy=policy or DEFAULT_DIFF_POLICY
        ),
    )


def _meta(updated: model.DocumentMetadata) -> model.DocumentMetadata:
    # Fill in unchanged fields so the XMP update is complete.
    return model.DocumentMetadata(
        title=updated.title or BASE_META.title,
        author=updated.author or BASE_META.author,
        subject=updated.subject or BASE_META.subject,
        created=updated.created or BASE_META.created,
        last_modified=None,
    )


@freeze_time('2021-06-01')
def test_identity_extraction_reads_both_channels():
    data = _build_two_channel_doc()
    _, resolver = _latest_identity(data)
    identity = document_identity(resolver)
    assert identity.info.present and identity.xmp.present
    for snapshot in identity.channels:
        assert snapshot.error is None
        assert snapshot.fields['title'].value == "Title A"
        assert snapshot.fields['author'].value == ("Alice",)
        assert snapshot.fields['subject'].value == "Subject A"
        assert snapshot.fields['created'].value == datetime(
            2020, 1, 1, tzinfo=UTC
        )
    assert {snapshot.channel for snapshot in identity.channels} == {
        IdentityChannel.INFO,
        IdentityChannel.XMP,
    }


@freeze_time('2021-06-01')
def test_identity_cache_returns_same_view():
    data = _build_two_channel_doc()
    _, resolver = _latest_identity(data)
    assert document_identity(resolver) is document_identity(resolver)


@freeze_time('2021-06-01')
def test_consistent_identity_update_is_lta():
    signed = _sign(_build_two_channel_doc())
    updated_meta = _meta(
        model.DocumentMetadata(
            title="Title B",
            author="Bob",
            subject="Subject B",
            created=datetime(2021, 2, 2, tzinfo=UTC),
        )
    )
    updated = _add_revision(
        signed,
        {
            '/Title': "Title B",
            '/Author': "Bob",
            '/Subject': "Subject B",
            '/CreationDate': "D:20210202000000Z",
        },
        updated_meta,
    )

    report = _identity_report(signed, updated)
    assert report.verdict == MetadataIdentityVerdict.CONSISTENT_UPDATE
    assert set(report.changed_fields) == {
        'title',
        'author',
        'subject',
        'created',
    }
    assert all(
        cmp.status == IdentityFieldStatus.UPDATED for cmp in report.fields
    )

    sig, status = _status(updated)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert status.docmdp_ok
    # The per-revision identity finding is retained on the diff result, so the
    # revision in which the identity changed can be located.
    assert sig.diff_result.metadata_identity
    [finding] = sig.diff_result.metadata_identity
    assert finding.revision == sig.signed_revision + 1
    assert finding.verdict == MetadataIdentityVerdict.CONSISTENT_UPDATE


@freeze_time('2021-06-01')
def test_noop_channel_rewrites_are_not_identity_changes():
    signed = _sign(_build_two_channel_doc())
    rewritten_info = _add_revision(signed, dict(INFO))
    rewritten_xmp = _add_revision(signed, None, BASE_META)

    for data in (rewritten_info, rewritten_xmp):
        report = _identity_report(signed, data)
        assert report.verdict == MetadataIdentityVerdict.NO_CHANGES
        assert not report.replaced_channels
        _, status = _status(data)
        assert status.modification_level == ModificationLevel.LTA_UPDATES
        assert status.docmdp_ok


@freeze_time('2021-06-01')
def test_info_only_identity_change_is_contradiction():
    signed = _sign(_build_two_channel_doc())
    updated = _add_revision(signed, {'/Title': "Title B"})

    report = _identity_report(signed, updated)
    assert report.verdict == MetadataIdentityVerdict.CONTRADICTION
    [title] = [cmp for cmp in report.fields if cmp.field == 'title']
    assert title.status == IdentityFieldStatus.CONTRADICTORY

    sig, status = _status(updated)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok
    diff_result = sig.diff_result
    assert isinstance(diff_result, SuspiciousModification)
    # The conclusion pins down the offending revision and the metadata objects
    # backing both channels.
    assert diff_result.revision == sig.signed_revision + 1
    assert diff_result.locations
    assert any(
        finding.verdict == MetadataIdentityVerdict.CONTRADICTION
        for finding in diff_result.metadata_identity
    )


@freeze_time('2021-06-01')
def test_xmp_only_identity_change_is_contradiction():
    signed = _sign(_build_two_channel_doc())
    updated = _add_revision(
        signed, None, _meta(model.DocumentMetadata(subject="Subject B"))
    )

    report = _identity_report(signed, updated)
    assert report.verdict == MetadataIdentityVerdict.CONTRADICTION
    assert 'subject' in {cmp.field for cmp in report.problematic_fields}
    _, status = _status(updated)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok


@freeze_time('2021-06-01')
def test_corrupt_xmp_metadata_is_unparseable():
    signed = _sign(_build_two_channel_doc())
    updated = _add_revision(signed, corrupt_xmp=True)

    report = _identity_report(signed, updated)
    assert report.verdict == MetadataIdentityVerdict.UNPARSEABLE
    assert all(
        cmp.status == IdentityFieldStatus.UNPARSEABLE for cmp in report.fields
    )

    sig, status = _status(updated)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok
    assert isinstance(sig.diff_result, SuspiciousModification)
    assert sig.diff_result.revision == sig.signed_revision + 1


@freeze_time('2021-06-01')
def test_metadata_channel_redirect_is_out_of_scope():
    signed = _sign(_build_two_channel_doc())
    reader = PdfFileReader(BytesIO(signed))
    page = reader.root['/Pages']['/Kids'][0]
    page_contents = page.raw_get('/Contents')
    assert page_contents is not None

    w = IncrementalPdfFileWriter(BytesIO(signed))
    w._update_meta = lambda: None
    # Point /Metadata at a pre-existing object, outside the metadata stream.
    w.root['/Metadata'] = page_contents
    w.update_root()
    out = BytesIO()
    w.write(out)
    redirected = out.getvalue()

    report = _identity_report(signed, redirected)
    assert report.verdict == MetadataIdentityVerdict.CHANNEL_REPLACEMENT
    assert report.replaced_channels == (IdentityChannel.XMP,)
    assert report.out_of_scope and not report.in_scope

    sig, status = _status(redirected)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok
    assert isinstance(sig.diff_result, SuspiciousModification)
    assert sig.diff_result.revision == sig.signed_revision + 1


@freeze_time('2021-06-01')
def test_contradiction_repaired_in_later_revision_still_flagged():
    signed = _sign(_build_two_channel_doc())
    # First revision introduces a contradiction in the info dictionary.
    contradictory = _add_revision(signed, {'/Title': "Title B"})
    # Second revision repairs it by updating the XMP channel to match.
    repaired = _add_revision(
        contradictory, None, _meta(model.DocumentMetadata(title="Title B"))
    )

    report = _identity_report(contradictory, repaired)
    assert report.verdict == MetadataIdentityVerdict.CONSISTENT_UPDATE

    # A cumulative comparison between the signed revision and the latest one
    # would only see the end state, but the per-revision review must still
    # reject the document because revision 3 was contradictory.
    sig, status = _status(repaired)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok
    assert isinstance(sig.diff_result, SuspiciousModification)
    assert sig.diff_result.revision == sig.signed_revision + 1


@freeze_time('2021-06-01')
def test_sequential_consistent_updates_tracked_per_revision():
    signed = _sign(_build_two_channel_doc())
    first = _add_revision(
        signed,
        {'/Title': "Title B"},
        _meta(model.DocumentMetadata(title="Title B")),
    )
    second = _add_revision(
        first,
        {'/Title': "Title C"},
        _meta(model.DocumentMetadata(title="Title C")),
    )

    sig, status = _status(second)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert status.docmdp_ok
    findings = sig.diff_result.metadata_identity
    # One finding per incremental revision after the signed one.
    assert [finding.revision for finding in findings] == [
        sig.signed_revision + 1,
        sig.signed_revision + 2,
    ]
    assert all(
        finding.verdict == MetadataIdentityVerdict.CONSISTENT_UPDATE
        for finding in findings
    )
    assert all(finding.changed_fields == ('title',) for finding in findings)


@freeze_time('2021-06-01')
def test_preexisting_anomaly_is_inherited_not_new():
    # Build a document whose channels already disagree about the title before
    # signing.
    w = PdfFileWriter()
    w.insert_page(simple_page(w, 'Page 1'))
    w.output_version = (1, 7)
    _with_info(w, INFO)
    w.update_root()
    out = BytesIO()
    w.write(out)

    w = IncrementalPdfFileWriter(BytesIO(out.getvalue()))
    contradictory_meta = model.DocumentMetadata(
        title="Title X",
        author="Alice",
        subject="Subject A",
        created=datetime(2020, 1, 1, tzinfo=UTC),
        last_modified=None,
    )
    w.root['/Metadata'] = w.add_object(
        xmp_xml.MetadataStream.from_xmp(
            xmp_xml.update_xmp_with_meta(contradictory_meta)
        )
    )
    w.update_root()
    w._update_meta = lambda: None
    out = BytesIO()
    w.write(out)
    anomalous = out.getvalue()

    signed = _sign(anomalous)
    # A revision that touches only an unrelated (non-identity) info entry
    # must not be blamed for the pre-existing disagreement.
    later = _add_revision(signed, {'/Producer': "Other producer"})

    report = _identity_report(signed, later)
    assert report.verdict == MetadataIdentityVerdict.PRE_EXISTING_ANOMALY

    sig, status = _status(later)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert status.docmdp_ok
    [finding] = sig.diff_result.metadata_identity
    assert finding.verdict == MetadataIdentityVerdict.PRE_EXISTING_ANOMALY

    # A revision that *changes* the contradiction is new, and is rejected.
    changed = _add_revision(signed, {'/Title': "Title Y"})
    changed_report = _identity_report(signed, changed)
    assert changed_report.verdict == MetadataIdentityVerdict.CONTRADICTION


@freeze_time('2021-06-01')
def test_identity_rule_only_policy_still_detects_metadata_issues():
    """
    A policy that uses :class:`.MetadataIdentityRule` but no other metadata
    rules must still flag contradictions.
    """
    signed = _sign(_build_two_channel_doc())
    updated = _add_revision(signed, {'/Title': "Title B"})
    policy = StandardDiffPolicy(
        global_rules=[
            MetadataIdentityRule(),
            XrefStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
        ],
        form_rule=None,
    )
    sig, status = _status(updated, policy=policy)
    assert status.modification_level == ModificationLevel.OTHER
    assert isinstance(sig.diff_result, SuspiciousModification)
    assert sig.diff_result.revision == sig.signed_revision + 1


@freeze_time('2021-06-01')
def test_legacy_channel_rules_do_not_interfere():
    """
    The legacy per-channel rules remain usable in isolation; they do not
    perform identity analysis.
    """
    from pyhanko.sign.diff_analysis import DocInfoRule, MetadataUpdateRule

    signed = _sign(_build_two_channel_doc())
    updated = _add_revision(signed, {'/Title': "Title B"})
    policy = StandardDiffPolicy(
        global_rules=[
            DocInfoRule().as_qualified(ModificationLevel.LTA_UPDATES),
            MetadataUpdateRule().as_qualified(ModificationLevel.LTA_UPDATES),
        ],
        form_rule=None,
    )
    sig, status = _status(updated, policy=policy)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    # No identity findings are recorded by the legacy rules.
    assert not sig.diff_result.metadata_identity


@pytest.mark.parametrize(
    'author_variants',
    [
        (("Alice",), ("Alice",)),
        (("Alice Smith",), ("Alice Smith",)),
        # The info dictionary flattens a multi-author list; this should not
        # be mistaken for a contradiction.
        (("Alice, Bob",), ("Alice", "Bob")),
        (("Alice; Bob",), ("Alice", "Bob")),
    ],
)
def test_author_normalisation(author_variants):
    from pyhanko.pdf_utils.metadata.identity import _values_match

    info_author, xmp_author = author_variants
    assert _values_match('author', info_author, xmp_author)


def test_author_difference_detected():
    from pyhanko.pdf_utils.metadata.identity import _values_match

    assert not _values_match('author', ("Alice",), ("Bob",))
    assert not _values_match('author', ("Alice",), ("Alice", "Bob"))


@freeze_time('2021-06-01')
def test_per_revision_findings_span_multiple_updates():
    """
    Identity findings for accepted revisions are ordered and cover every
    incremental revision after signing, including revisions without metadata
    changes.
    """
    signed = _sign(_build_two_channel_doc())
    with_meta_update = _add_revision(
        signed,
        {'/Title': "Title B"},
        _meta(model.DocumentMetadata(title="Title B")),
    )
    # A revision that only touches a non-identity info entry.
    final = _add_revision(with_meta_update, {'/Producer': "Other"})

    sig, status = _status(final)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    findings = sig.diff_result.metadata_identity
    assert [finding.revision for finding in findings] == [
        sig.signed_revision + 1,
        sig.signed_revision + 2,
    ]
    assert findings[0].verdict == MetadataIdentityVerdict.CONSISTENT_UPDATE
    assert findings[1].verdict == MetadataIdentityVerdict.NO_CHANGES


@freeze_time('2021-06-01')
def test_identity_report_serialisation_is_stable():
    """
    The report's serialised form is deterministic and exposes the revision
    it describes.
    """
    signed = _sign(_build_two_channel_doc())
    updated = _add_revision(
        signed,
        {'/Title': "Title B"},
        _meta(model.DocumentMetadata(title="Title B")),
    )
    report = _identity_report(signed, updated)
    payload = report.as_dict()
    assert payload['verdict'] == 'CONSISTENT_UPDATE'
    assert payload['revision'] == report.revision
    assert payload['base_revision'] == report.base_revision
    assert [f['field'] for f in payload['fields']] == [
        'title',
        'author',
        'subject',
        'created',
    ]
    assert payload['fields'][0]['status'] == 'UPDATED'
    assert all(
        isinstance(loc, str) and loc.endswith('R')
        for loc in payload['locations']
    )
    # Running the analysis twice yields the same serialised output.
    assert payload == _identity_report(signed, updated).as_dict()
    assert report.summary() == _identity_report(signed, updated).summary()
