"""
Tests for the DocMDP level 3 (annotation) support in the difference analysis
machinery.
"""

from io import BytesIO

from freezegun.api import freeze_time
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    AnnotationModificationRule,
    ModificationLevel,
    StandardDiffPolicy,
    SuspiciousModification,
)
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_testing_commons.test_data.samples import (
    MINIMAL,
    MINIMAL_ONE_FIELD,
    MINIMAL_ONE_FIELD_TAGGED,
    MINIMAL_TWO_PAGES,
)
from pyhanko_testing_commons.test_utils.signing_commons import (
    FROM_CA,
    simple_v_context,
)

ANNOTATE = fields.MDPPerm.ANNOTATE
FILL_FORMS = fields.MDPPerm.FILL_FORMS


def _sign_certifying(level, src=MINIMAL):
    w = IncrementalPdfFileWriter(BytesIO(src))
    return signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True, docmdp_permissions=level
        ),
        signer=FROM_CA,
    )


def _new_annot(writer, text='A note', subtype='/Text', extra=None):
    d = {
        pdf_name('/Type'): pdf_name('/Annot'),
        pdf_name('/Subtype'): pdf_name(subtype),
        pdf_name('/Rect'): generic.ArrayObject(
            map(generic.NumberObject, (10, 10, 20, 20))
        ),
        pdf_name('/Contents'): generic.pdf_string(text),
        pdf_name('/F'): generic.NumberObject(4),
    }
    if extra:
        d.update(extra)
    return writer.add_object(generic.DictionaryObject(d))


def _add_annot(writer, text='A note', page_ix=0, **kwargs):
    page_ref = writer.find_page_for_modification(page_ix)[0]
    annot_ref = _new_annot(writer, text=text, **kwargs)
    writer.register_annotation(page_ref, annot_ref)
    return annot_ref


def _validate(out, policy=None):
    r = PdfFileReader(BytesIO(out.getvalue()))
    s = r.embedded_signatures[0]
    status = validate_pdf_signature(
        s,
        simple_v_context(),
        diff_policy=policy,
    )
    return status, s


def _find_text_annot(writer, page_ix=0):
    """
    Locate the reference to the (single) text annotation we created on a page,
    ignoring widget annotations belonging to form fields.
    """
    page_ref = writer.find_page_for_modification(page_ix)[0]
    for annot_raw in page_ref.get_object()['/Annots']:
        annot_ref = annot_raw.reference
        annot = annot_ref.get_object()
        if annot.get('/Subtype') == '/Text':
            return annot_ref
    raise AssertionError('Text annotation not found')


@freeze_time('2020-11-01')
def test_add_text_annotation_annotate_level():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    result = BytesIO()
    w.write(result)

    status, _ = _validate(result)
    assert status.coverage.value >= 2
    assert status.modification_level == ModificationLevel.ANNOTATIONS
    assert status.docmdp_ok
    assert status.bottom_line


@freeze_time('2020-11-01')
def test_add_text_annotation_fill_forms_level_rejected():
    out = _sign_certifying(FILL_FORMS)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_modify_existing_annotation_annotate_level():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='original')
    intermediate = BytesIO()
    w.write(intermediate)

    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    annot_ref = _find_text_annot(w)
    annot_obj = annot_ref.get_object()
    annot_obj['/Contents'] = generic.pdf_string('updated')
    w.mark_update(annot_ref)
    result = BytesIO()
    w.write(result)

    status, _ = _validate(result)
    assert status.modification_level == ModificationLevel.ANNOTATIONS
    assert status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_with_content_change_rejected():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    contents_ref = (
        w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    )
    stm = contents_ref.get_object()
    stm._data = stm.data + b'\nq Q'
    stm._encoded_data = None
    w.mark_update(contents_ref)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert status.modification_level == ModificationLevel.OTHER
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_with_signature_field_change_rejected():
    out = _sign_certifying(ANNOTATE, src=MINIMAL_ONE_FIELD)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    # tamper with the signature field's value
    sig_field = w.root['/AcroForm']['/Fields'][0].get_object()
    sig_field['/T'] = generic.pdf_string('SomethingElse')
    w.update_container(sig_field)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_with_acroform_change_rejected():
    out = _sign_certifying(ANNOTATE, src=MINIMAL_ONE_FIELD)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    acroform = w.root['/AcroForm']
    acroform['/Evil'] = generic.pdf_string('hax')
    w.update_root()
    w.update_container(acroform)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_subtype_change_rejected():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    intermediate = BytesIO()
    w.write(intermediate)

    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    annot_ref = _find_text_annot(w)
    annot_obj = annot_ref.get_object()
    annot_obj['/Subtype'] = pdf_name('/Link')
    w.mark_update(annot_ref)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_delete_annotation_annotate_level():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    intermediate = BytesIO()
    w.write(intermediate)

    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    page_ref = w.find_page_for_modification(0)[0]
    page_obj = page_ref.get_object()
    annots = page_obj['/Annots']
    annot_ref = _find_text_annot(w)
    # remove the text annotation we added, keeping the signature widget
    for ix, raw in enumerate(annots):
        if raw.reference == annot_ref:
            del annots[ix]
            break
    else:  # pragma: nocover
        raise AssertionError('Text annotation not found')
    w.update_container(page_obj)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    # The annotation object itself is not freed; only the /Annots array
    # changes. That is legitimate at DocMDP level 3.
    assert status.docmdp_ok, s.diff_result
    assert status.modification_level == ModificationLevel.ANNOTATIONS


@freeze_time('2020-11-01')
def test_annotation_shared_appearance_rejected():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    # Two annotations that share an appearance stream
    page_ref = w.find_page_for_modification(0)[0]
    ap_stream = w.add_object(
        generic.StreamObject(
            {
                pdf_name('/Type'): pdf_name('/XObject'),
                pdf_name('/Subtype'): pdf_name('/Form'),
                pdf_name('/BBox'): generic.ArrayObject(
                    map(generic.NumberObject, (0, 0, 10, 10))
                ),
                pdf_name('/Resources'): generic.DictionaryObject(),
            },
            stream_data=b'q Q',
        )
    )
    annot1 = _new_annot(
        w,
        extra={
            pdf_name('/AP'): generic.DictionaryObject(
                {pdf_name('/N'): ap_stream}
            )
        },
    )
    annot2 = _new_annot(
        w,
        extra={
            pdf_name('/AP'): generic.DictionaryObject(
                {pdf_name('/N'): ap_stream}
            )
        },
    )
    w.register_annotation(page_ref, annot1)
    w.register_annotation(page_ref, annot2)
    intermediate = BytesIO()
    w.write(intermediate)

    # Try to override the shared appearance stream in place
    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    annot_ref = _find_text_annot(w)
    ap_stream_ref = annot_ref.get_object()['/AP'].get_value_as_reference('/N')
    stream = ap_stream_ref.get_object()
    assert isinstance(stream, generic.StreamObject)
    stream._data = b'q 1 0 0 1 0 0 cm Q'
    stream._encoded_data = None
    w.mark_update(ap_stream_ref)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_new_annotation_pointing_at_page_rejected():
    """An annotation must not be able to clear a page object override."""
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    page_ref = w.find_page_for_modification(0)[0]
    page_obj = page_ref.get_object()
    # Add a bogus key to the page and make the annotation point at it as
    # if it were an appearance stream.
    page_obj['/Elite'] = generic.pdf_string('hax')
    w.update_container(page_obj)
    annot = _new_annot(
        w,
        extra={pdf_name('/FS'): page_ref},
    )
    w.register_annotation(page_ref, annot)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_rule_not_consulted_without_annotate_level():
    """
    Even if an annotation rule is configured, it must not clear anything
    unless the DocMDP level is ANNOTATE.
    """
    policy = StandardDiffPolicy(
        global_rules=DEFAULT_DIFF_POLICY.global_rules,
        form_rule=DEFAULT_DIFF_POLICY.form_rule,
        annotation_rule=AnnotationModificationRule(),
    )
    out = _sign_certifying(FILL_FORMS)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result, policy=policy)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_multi_revision_reports_offending_revision():
    """
    Set up three incremental updates: a legitimate annotation, an illegal
    page content change, and another legitimate annotation. The diff analysis
    must report the revision in which the illegal change took place.
    """
    out = _sign_certifying(ANNOTATE)

    # rev 2: legitimate annotation
    w = IncrementalPdfFileWriter(out)
    _add_annot(w)
    rev2 = BytesIO()
    w.write(rev2)

    # rev 3: content change
    w = IncrementalPdfFileWriter(BytesIO(rev2.getvalue()))
    contents_ref = (
        w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    )
    stm = contents_ref.get_object()
    stm._data = stm.data + b'\nq Q'
    stm._encoded_data = None
    w.mark_update(contents_ref)
    rev3 = BytesIO()
    w.write(rev3)

    # rev 4: another legitimate annotation
    w = IncrementalPdfFileWriter(BytesIO(rev3.getvalue()))
    _add_annot(w, text='second')
    rev4 = BytesIO()
    w.write(rev4)

    r = PdfFileReader(BytesIO(rev4.getvalue()))
    s = r.embedded_signatures[0]
    s.compute_integrity_info(DEFAULT_DIFF_POLICY)
    assert isinstance(s.diff_result, SuspiciousModification)
    # The violation occurred in the change from revision 1 to 3.
    assert s.diff_result.revision == 3
    assert s.diff_result.locations


@freeze_time('2020-11-01')
def test_annotation_two_pages_annotation():
    out = _sign_certifying(ANNOTATE, src=MINIMAL_TWO_PAGES)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='page 1 note', page_ix=0)
    _add_annot(w, text='page 2 note', page_ix=1)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert status.docmdp_ok, s.diff_result
    assert status.modification_level == ModificationLevel.ANNOTATIONS


@freeze_time('2020-11-01')
def test_annotation_no_change_is_noop():
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    # Touch the page object without actually changing anything semantically.
    page_ref = w.find_page_for_modification(0)[0]
    w.update_container(page_ref.get_object())
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert status.docmdp_ok, s.diff_result


@freeze_time('2020-11-01')
def test_annotation_new_annotation_cannot_override_existing_object():
    """
    A "new" annotation must actually be a new object; reusing an existing
    object ID is rejected.
    """
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    page_ref = w.find_page_for_modification(0)[0]
    contents_ref = (
        w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    )
    # Register an existing object as the annotation
    w.register_annotation(page_ref, contents_ref)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_added_with_new_signature_field():
    """
    A revision that adds a (invisible) signature field and a text annotation
    at the same time must be accepted at DocMDP level 3. The form rules must
    not reject the annotation as "unrecognised", and the annotation rule must
    clear it.
    """
    out = _sign_certifying(ANNOTATE, src=MINIMAL_ONE_FIELD)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='annotation next to new sig field')
    fields.append_signature_field(w, fields.SigFieldSpec('SigNew'))
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert status.docmdp_ok, s.diff_result
    assert status.modification_level == ModificationLevel.ANNOTATIONS


@freeze_time('2020-11-01')
def test_annotation_delete_with_new_signature_field_rejected():
    """
    At DocMDP level 3, deleting a pre-existing annotation is fine on its own.
    However, when the same revision also adds a signature field, the form
    rules must not clear the page and /Annots bookkeeping in a way that would
    mask the (separately adjudicated) deletion. The annotation rule handles
    the deletion, so the revision should still be accepted -- and, crucially,
    the deletion must be attributable to the annotation rule rather than
    silently absorbed by the form rule.
    """
    out = _sign_certifying(ANNOTATE)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='to be deleted')
    intermediate = BytesIO()
    w.write(intermediate)

    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    page_ref = w.find_page_for_modification(0)[0]
    page_obj = page_ref.get_object()
    annots = page_obj['/Annots']
    annot_ref = _find_text_annot(w)
    for ix, raw in enumerate(annots):
        if raw.reference == annot_ref:
            del annots[ix]
            break
    else:  # pragma: nocover
        raise AssertionError('Text annotation not found')
    w.update_container(page_obj)
    fields.append_signature_field(w, fields.SigFieldSpec('SigNew'))
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert status.docmdp_ok, s.diff_result
    assert status.modification_level == ModificationLevel.ANNOTATIONS


@freeze_time('2020-11-01')
def test_annotation_added_with_new_signature_field_fill_forms_rejected():
    """
    At DocMDP level 2, a text annotation is not permitted even when it is
    added in the same revision that adds a signature field.
    """
    out = _sign_certifying(FILL_FORMS, src=MINIMAL_ONE_FIELD)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='not allowed here')
    fields.append_signature_field(w, fields.SigFieldSpec('SigNew'))
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
def test_annotation_tagged_document_annotation_allowed():
    """
    In a tagged document, an annotation object is also reachable through the
    structure tree (via the /Obj entry of a structure element). Modifying the
    annotation's contents is still a legitimate annotative change, and must not
    be rejected just because of that additional reference path.
    """
    out = _sign_certifying(ANNOTATE, src=MINIMAL_ONE_FIELD_TAGGED)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='tagged note')
    intermediate = BytesIO()
    w.write(intermediate)

    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    annot_ref = _find_text_annot(w)
    annot_obj = annot_ref.get_object()
    annot_obj['/Contents'] = generic.pdf_string('updated tagged note')
    w.mark_update(annot_ref)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert status.docmdp_ok, s.diff_result
    assert status.modification_level == ModificationLevel.ANNOTATIONS


@freeze_time('2020-11-01')
def test_annotation_structure_tree_change_rejected():
    """
    Modifying the structure tree (e.g. a structure element's /Obj entry) in
    the same revision as an annotation change must still be rejected.
    """
    out = _sign_certifying(ANNOTATE, src=MINIMAL_ONE_FIELD_TAGGED)
    w = IncrementalPdfFileWriter(out)
    _add_annot(w, text='tagged note')
    intermediate = BytesIO()
    w.write(intermediate)

    w = IncrementalPdfFileWriter(BytesIO(intermediate.getvalue()))
    annot_ref = _find_text_annot(w)
    annot_obj = annot_ref.get_object()
    annot_obj['/Contents'] = generic.pdf_string('updated tagged note')
    w.mark_update(annot_ref)
    # Also tamper with a structure element
    struct_root_ref = w.root.raw_get('/StructTreeRoot')
    struct_root = struct_root_ref.get_object()
    struct_root['/Evil'] = generic.pdf_string('hax')
    w.update_container(struct_root)
    result = BytesIO()
    w.write(result)

    status, s = _validate(result)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok
