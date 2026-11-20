"""
Tests for the per-revision attribution API in
:mod:`pyhanko.sign.diff_analysis.attribution`.
"""

from datetime import UTC, datetime
from io import BytesIO

import pytest
from freezegun import freeze_time
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfTimeStamper, signers
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    ModificationLevel,
    RevisionVerdict,
    attribute_incremental_updates,
)
from pyhanko_testing_commons.test_data.samples import (
    MINIMAL,
    MINIMAL_ONE_FIELD,
    SIMPLE_FORM,
)
from pyhanko_testing_commons.test_utils.signing_commons import (
    DUMMY_TS,
    FROM_CA,
)

from .test_diff_analysis import set_text_field


def _sign(input_bytes: bytes, field_name='Sig1', **kwargs) -> BytesIO:
    w = IncrementalPdfFileWriter(BytesIO(input_bytes))
    meta = signers.PdfSignatureMetadata(field_name=field_name, **kwargs)
    return signers.sign_pdf(w, meta, signer=FROM_CA)


def _info_update(out: BytesIO):
    w = IncrementalPdfFileWriter(out)
    dt = generic.pdf_date(datetime(2020, 10, 10, tzinfo=UTC))
    w.set_info(generic.DictionaryObject({pdf_name('/CreationDate'): dt}))
    w.write_in_place()


@freeze_time('2020-11-01')
def test_maintenance_revision_is_allowed():
    out = _sign(MINIMAL_ONE_FIELD)
    _info_update(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)

    sig = r.embedded_signatures[0]
    assert report.base_revision == sig.signed_revision
    assert len(report.revisions) == 1

    rev = report.revisions[0]
    assert rev.revision == sig.signed_revision + 1
    assert rev.verdict == RevisionVerdict.ALLOWED_MAINTENANCE
    assert rev.modification_level == ModificationLevel.LTA_UPDATES
    assert rev.new_objects
    # the /Info update must be attributed to metadata
    assert rev.metadata_objects
    assert set(rev.metadata_objects) <= set(rev.new_objects)
    assert not rev.page_content_objects
    assert not rev.signatures_introduced
    # the only signature precedes this revision, so nothing covers it
    assert not rev.covered_by_signatures
    assert report.overall_verdict == RevisionVerdict.ALLOWED_MAINTENANCE
    assert not report.signature_breaking_revisions


@freeze_time('2020-11-01')
def test_form_fill_revision_is_unknown_modification():
    out = _sign(SIMPLE_FORM)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)

    assert len(report.revisions) == 1
    rev = report.revisions[0]
    assert rev.verdict == RevisionVerdict.UNKNOWN_MODIFICATION
    assert rev.modification_level == ModificationLevel.FORM_FILLING
    assert report.overall_verdict == RevisionVerdict.UNKNOWN_MODIFICATION


@freeze_time('2020-11-01')
def test_page_content_tamper_is_signature_breaking():
    out = _sign(MINIMAL)
    w = IncrementalPdfFileWriter(out)
    page_root = w.root['/Pages']
    page_root['/Kids'] = generic.ArrayObject()
    page_root['/Count'] = generic.NumberObject(0)
    w.update_container(page_root)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)

    assert len(report.revisions) == 1
    rev = report.revisions[0]
    assert rev.verdict == RevisionVerdict.SIGNATURE_BREAKING
    assert rev.modification_level is None
    assert rev.detail
    # the overwritten /Pages node must be attributed to page content
    assert rev.page_content_objects
    assert report.overall_verdict == RevisionVerdict.SIGNATURE_BREAKING
    assert report.signature_breaking_revisions == (rev.revision,)


@freeze_time('2020-11-01')
def test_multiple_revisions_get_individual_verdicts():
    # sign, then fill in a form field, then perform a metadata update:
    # the two post-signing revisions must be judged separately
    out = _sign(SIMPLE_FORM)

    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    _info_update(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)

    assert len(report.revisions) == 2
    fill_rev, meta_rev = report.revisions
    assert fill_rev.verdict == RevisionVerdict.UNKNOWN_MODIFICATION
    assert fill_rev.modification_level == ModificationLevel.FORM_FILLING
    assert meta_rev.verdict == RevisionVerdict.ALLOWED_MAINTENANCE
    assert meta_rev.modification_level == ModificationLevel.LTA_UPDATES
    assert meta_rev.metadata_objects
    # the rollup is the worst of the two, but the per-revision
    # judgments remain available
    assert report.overall_verdict == RevisionVerdict.UNKNOWN_MODIFICATION


@freeze_time('2020-11-01')
def test_breaking_revision_followed_by_maintenance_revision():
    # a signature-breaking revision must not mask (or be masked by)
    # a later legitimate maintenance revision
    out = _sign(MINIMAL)

    w = IncrementalPdfFileWriter(out)
    page_root = w.root['/Pages']
    page_root['/Kids'] = generic.ArrayObject()
    w.update_container(page_root)
    out = BytesIO()
    w.write(out)

    _info_update(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)

    assert len(report.revisions) == 2
    bad_rev, good_rev = report.revisions
    assert bad_rev.verdict == RevisionVerdict.SIGNATURE_BREAKING
    assert good_rev.verdict == RevisionVerdict.ALLOWED_MAINTENANCE
    assert report.overall_verdict == RevisionVerdict.SIGNATURE_BREAKING
    assert report.signature_breaking_revisions == (bad_rev.revision,)


@freeze_time('2020-11-01')
def test_signature_introduction_and_coverage():
    out = _sign(MINIMAL_ONE_FIELD, field_name='Sig1')
    out = _sign(out.getvalue(), field_name='Sig2')

    r = PdfFileReader(out)
    sig1, sig2 = r.embedded_signatures
    assert sig2.signed_revision == r.xrefs.total_revisions - 1

    report = attribute_incremental_updates(
        r, base_revision=sig1.signed_revision
    )
    assert len(report.revisions) == 1
    rev = report.revisions[0]
    assert rev.revision == sig2.signed_revision
    assert rev.signatures_introduced == ('Sig2',)
    # Sig2 covers its own revision; Sig1 does not
    assert rev.covered_by_signatures == ('Sig2',)


@freeze_time('2020-11-01')
def test_timestamp_revision_is_maintenance():
    out = _sign(MINIMAL)
    w = IncrementalPdfFileWriter(out)
    out = PdfTimeStamper(timestamper=DUMMY_TS).timestamp_pdf(
        w, md_algorithm='sha256'
    )

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)

    assert len(report.revisions) == 1
    rev = report.revisions[0]
    assert rev.verdict == RevisionVerdict.ALLOWED_MAINTENANCE
    # the document timestamp is a signature in its own right, introduced
    # by this revision and covering it
    assert len(rev.signatures_introduced) == 1
    assert rev.covered_by_signatures == rev.signatures_introduced


@freeze_time('2020-11-01')
def test_default_base_revision_is_earliest_signature():
    out = _sign(MINIMAL_ONE_FIELD, field_name='Sig1')
    out = _sign(out.getvalue(), field_name='Sig2')
    _info_update(out)

    r = PdfFileReader(out)
    sig1 = r.embedded_signatures[0]
    report = attribute_incremental_updates(r)
    assert report.base_revision == sig1.signed_revision
    assert len(report.revisions) == 2


@freeze_time('2020-11-01')
def test_explicit_base_revision():
    out = _sign(MINIMAL_ONE_FIELD, field_name='Sig1')
    out = _sign(out.getvalue(), field_name='Sig2')
    _info_update(out)

    r = PdfFileReader(out)
    sig2 = r.embedded_signatures[1]
    report = attribute_incremental_updates(
        r, base_revision=sig2.signed_revision
    )
    assert report.base_revision == sig2.signed_revision
    assert len(report.revisions) == 1
    assert report.revisions[0].metadata_objects


@freeze_time('2020-11-01')
def test_base_revision_out_of_range():
    out = _sign(MINIMAL)
    r = PdfFileReader(out)
    with pytest.raises(PdfReadError):
        attribute_incremental_updates(r, base_revision=42)


@freeze_time('2020-11-01')
def test_no_post_signing_revisions():
    out = _sign(MINIMAL)
    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)
    assert report.revisions == ()
    assert report.overall_verdict == RevisionVerdict.ALLOWED_MAINTENANCE
    assert report.signature_breaking_revisions == ()


@freeze_time('2020-11-01')
def test_embedded_signature_convenience_method():
    out = _sign(SIMPLE_FORM)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    sig = r.embedded_signatures[0]
    report = sig.attribute_post_signature_updates()
    assert report.base_revision == sig.signed_revision
    assert len(report.revisions) == 1
    assert report.revisions[0].verdict == RevisionVerdict.UNKNOWN_MODIFICATION


@freeze_time('2020-11-01')
def test_attribution_output_is_stable():
    out = _sign(SIMPLE_FORM)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)
    _info_update(out)

    def _report_dict():
        r = PdfFileReader(BytesIO(out.getvalue()))
        return attribute_incremental_updates(r).as_dict()

    first, second = _report_dict(), _report_dict()
    assert first == second

    # refs must be sorted by (idnum, generation)
    r = PdfFileReader(BytesIO(out.getvalue()))
    report = attribute_incremental_updates(r)
    for rev in report.revisions:
        keys = [(ref.idnum, ref.generation) for ref in rev.new_objects]
        assert keys == sorted(keys)

    # the summary contains one line per revision
    summary_lines = report.summary().splitlines()
    assert len(summary_lines) == 1 + len(report.revisions)
    assert 'verdict=UNKNOWN_MODIFICATION' in summary_lines[1]
    assert 'verdict=ALLOWED_MAINTENANCE' in summary_lines[2]

    # as_dict is JSON-serialisable
    import json

    json.dumps(first)


@freeze_time('2020-11-01')
def test_unsigned_file_attributes_all_revisions():
    # MINIMAL with an /Info update appended, no signatures
    dt = generic.pdf_date(datetime(2020, 10, 10, tzinfo=UTC))
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    w.set_info(generic.DictionaryObject({pdf_name('/CreationDate'): dt}))
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(r)
    assert report.base_revision == 0
    assert len(report.revisions) == r.xrefs.total_revisions - 1
    assert all(rev.covered_by_signatures == () for rev in report.revisions)


@freeze_time('2020-11-01')
def test_custom_diff_policy_is_respected():
    from pyhanko.sign.diff_analysis import NO_CHANGES_DIFF_POLICY

    out = _sign(MINIMAL_ONE_FIELD)
    _info_update(out)

    r = PdfFileReader(out)
    report = attribute_incremental_updates(
        r, diff_policy=NO_CHANGES_DIFF_POLICY
    )
    # the no-changes policy rejects even benign maintenance updates
    assert len(report.revisions) == 1
    assert report.revisions[0].verdict == RevisionVerdict.SIGNATURE_BREAKING
    assert report.revisions[0].detail

    # sanity check: the default policy accepts the same update
    r = PdfFileReader(BytesIO(out.getvalue()))
    report = attribute_incremental_updates(r, diff_policy=DEFAULT_DIFF_POLICY)
    assert report.revisions[0].verdict == RevisionVerdict.ALLOWED_MAINTENANCE
