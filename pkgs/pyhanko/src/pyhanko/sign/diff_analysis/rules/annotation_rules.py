"""
Rules for validating incremental updates that only touch annotations.

These rules are only relevant when the document modification policy in force
permits annotation changes, i.e. when the applicable ``/DocMDP`` level is
:attr:`~pyhanko.sign.fields.MDPPerm.ANNOTATE` (level 3).

The rule implemented here is deliberately narrow: it clears annotation
objects, the arrays that contain them and the appearance streams that belong to
them, but nothing else. In particular, page content, the document structure
tree, metadata streams and form fields (including signature fields) are *not*
cleared by this rule, even if they happen to be reachable from an annotation
that was added or modified. Such changes remain the responsibility of the
other rules in the policy, and will be rejected if no rule justifies them.

.. note::
    Although rules receive the signed (base) revision and the revision under
    review, the adjudication performed here is relative to the *immediately
    preceding* revision. This distinction matters: an annotation that was
    created by an earlier incremental update and is modified again by a later
    one must be judged as a modification, not as a new annotation. Otherwise,
    a document with multiple post-signing updates could be used to smuggle in
    changes to an annotation under the guise of creating it.
"""

from collections.abc import Iterable

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    StreamObject,
    pdf_name,
)
from pyhanko.pdf_utils.reader import HistoricalResolver, RawPdfPath

from ..annotation_rules_api import AnnotationUpdate, AnnotationUpdateRule
from ..commons import compare_dicts
from ..constants import ANNOTATION_MUTABLE_KEYS
from ..policy_api import ModificationLevel, SuspiciousModification
from ..rules_api import Context, RelativeContext
from .form_field_rules import _arr_to_refs, _extract_annots_from_page

__all__ = ['AnnotationModificationRule']

ANNOTATION_LEVEL = ModificationLevel.ANNOTATIONS

#: Dictionary types that must never be introduced (or overridden) by virtue of
#: an annotation update. If one of these shows up as a newly created
#: dependency of an annotation, the revision is rejected.
_FORBIDDEN_DEP_TYPES = frozenset(
    {
        '/Catalog',
        '/Page',
        '/Pages',
        '/StructTreeRoot',
        '/StructElem',
        '/Sig',
        '/DocTimeStamp',
        '/ObjStm',
        '/XRef',
        '/Metadata',
    }
)


def _annotation_subtype(annot) -> NameObject | None:
    try:
        subtype = annot.raw_get('/Subtype')
    except KeyError:
        return None
    if not isinstance(subtype, NameObject):
        return None
    return subtype


def _is_widget(annot) -> bool:
    return _annotation_subtype(annot) == '/Widget'


def _is_form_fieldish(obj) -> bool:
    """
    Heuristic check for objects that live in the form field / widget
    namespace. Such objects are never cleared by the annotation rule.
    """
    if not isinstance(obj, DictionaryObject):
        return False
    if '/FT' in obj:
        return True
    return _is_widget(obj)


def _raw_dict_type(obj):
    if not isinstance(obj, (DictionaryObject, StreamObject)):
        return None
    try:
        return obj.raw_get('/Type')
    except KeyError:
        return None


def _validate_annotation_dict(annot, exc_cls, page_ref=None):
    """
    Perform the structural checks that every annotation should satisfy,
    regardless of whether it's new or modified.
    """
    if not isinstance(annot, DictionaryObject) or isinstance(
        annot, StreamObject
    ):
        raise exc_cls("Annotations must be dictionary objects")

    subtype = _annotation_subtype(annot)
    if subtype is None:
        raise exc_cls("Annotation has no valid /Subtype entry")

    type_entry = _raw_dict_type(annot)
    if type_entry is not None and type_entry != pdf_name('/Annot'):
        raise exc_cls(f"Annotation has unexpected /Type entry {type_entry!r}")

    try:
        rect = annot['/Rect']
    except KeyError:
        raise exc_cls("Annotation has no /Rect entry")
    if not isinstance(rect, ArrayObject) or len(rect) != 4:
        raise exc_cls("Annotation /Rect should be an array of four numbers")
    for coord in rect:
        coord = coord.get_object()
        if not isinstance(coord, (generic.NumberObject, generic.FloatObject)):
            raise exc_cls("Annotation /Rect should be an array of four numbers")

    if page_ref is not None and '/P' in annot:
        p_entry = annot.raw_get('/P')
        if (
            not isinstance(p_entry, IndirectObject)
            or p_entry.reference != page_ref
        ):
            raise exc_cls(
                "Annotation /P entry does not point to the page on which the "
                "annotation is registered"
            )
    return subtype


def _check_dependency_obj(dep_ref, obj, subtype):
    """
    Make sure that a newly created object that hangs off an annotation is
    genuinely annotation-related, and not a(n) (overridden) piece of document
    structure that happens to be reachable from an annotation.
    """
    type_entry = _raw_dict_type(obj)
    if type_entry in _FORBIDDEN_DEP_TYPES:
        raise SuspiciousModification(
            f"Annotation of subtype {subtype!r} references {dep_ref}, which "
            f"is a {type_entry!r} object; such objects cannot be cleared by "
            "virtue of an annotation update."
        )
    if _is_form_fieldish(obj):
        raise SuspiciousModification(
            f"Annotation of subtype {subtype!r} references form field object "
            f"{dep_ref}; form field updates cannot be authorised by an "
            "annotation update."
        )


def _child_dependencies(prev, new, obj, subtype, page_ref):
    """
    Clear the newly introduced objects reachable from an annotation, subject
    to the constraints in :func:`_check_dependency_obj`.
    """
    deps = new.collect_dependencies(obj, since_revision=prev.revision + 1)
    for dep_ref in deps:
        _check_dependency_obj(dep_ref, new(dep_ref), subtype)
        yield AnnotationUpdate(
            updated_ref=dep_ref, subtype=subtype, page_ref=page_ref
        )


def _is_annotation_usage_path(path: RawPdfPath) -> bool:
    """
    Check whether a path through which an annotation object is reachable looks
    like an annotation usage, as opposed to a use of the same object in some
    other capacity (e.g. as page content or as a structure element).

    Acceptable shapes are:

    * ``.../Annots[i]``, i.e. registration as an annotation on a page;
    * ``.../Annots[i]/Popup`` and ``.../Annots[i]/IRT``, i.e. cross-references
      between annotations;
    * ``/Root/StructTreeRoot/.../Obj``, i.e. the annotation's association with
      a structure element in a tagged document. This is only the path *to* the
      annotation object: the structure element itself is a distinct object,
      and any change to it will be adjudicated elsewhere.

    Anything else means that the object is reachable from outside the
    annotation layer, in which case changing it could affect other parts of
    the document.
    """
    nodes = path.path
    if len(nodes) < 2:
        return False
    if nodes[-2] == '/Annots' and isinstance(nodes[-1], int):
        return True
    if nodes[-1] in ('/Popup', '/IRT') and len(nodes) >= 3:
        return nodes[-3] == '/Annots' and isinstance(nodes[-2], int)
    if nodes[-1] == '/Obj' and len(nodes) >= 4:
        # Structure tree association: /.Root.StructTreeRoot.../K.../Obj
        return nodes[0] == '/Root' and nodes[1] == '/StructTreeRoot'
    return False


def _annotation_usage_paths(prev, annot_ref):
    """
    Return the paths through which ``annot_ref`` is reachable in the prior
    revision, and raise :class:`.SuspiciousModification` if any of those paths
    does not correspond to annotation usage.
    """
    usages = prev._get_usages_of_ref(annot_ref)
    if not usages:
        raise SuspiciousModification(
            f"Annotation {annot_ref} was modified, but it could not be "
            "reached from the document trailer in the prior revision.",
            revision=prev.revision,
            locations=(annot_ref,),
        )
    non_annotation_usages = {
        path for path in usages if not _is_annotation_usage_path(path)
    }
    if non_annotation_usages:
        raise SuspiciousModification(
            f"Annotation {annot_ref} is also reachable through non-annotation "
            f"paths: {', '.join(str(p) for p in non_annotation_usages)}.",
            revision=prev.revision,
            locations=(annot_ref,),
        )
    return usages


def _appearance_stream_contexts(prev, annot_ref, prev_annot, key):
    """
    Compute the relative contexts under which the appearance stream in
    ``prev_annot[/AP][key]`` is expected to be reachable.

    This is used to allow appearance streams to be overridden in place, but
    only if they're not shared with other annotations or other parts of the
    document.
    """
    prev_ap_raw = prev_annot.raw_get('/AP')
    prev_ap = prev_ap_raw.get_object()
    if not isinstance(prev_ap, DictionaryObject):
        return set()
    try:
        ap_stream_raw = prev_ap.raw_get(key)
    except KeyError:
        return set()
    if not isinstance(ap_stream_raw, IndirectObject):
        return set()

    expected_paths = {
        annot_path + '/AP' + key
        for annot_path in prev._get_usages_of_ref(annot_ref)
    }
    if isinstance(prev_ap_raw, IndirectObject):
        expected_paths |= {
            ap_path + key
            for ap_path in prev._get_usages_of_ref(prev_ap_raw.reference)
        }

    actual_paths = prev._get_usages_of_ref(ap_stream_raw.reference)
    if not actual_paths or actual_paths - expected_paths:
        return set()

    if isinstance(prev_ap_raw, IndirectObject):
        return {RelativeContext(prev_ap_raw, RawPdfPath(key))}
    else:
        return {RelativeContext(annot_ref, RawPdfPath('/AP', key))}


def _clear_indirect_ap_dict(prev, annot_ref, prev_ap_raw):
    """
    Clear an in-place override of an indirect appearance dictionary, provided
    that it is used exclusively by the annotation in question.
    """
    ap_ref = prev_ap_raw.reference
    if prev.is_ref_unassignable(ap_ref):
        # new appearance dictionary; handled as an ordinary dependency
        return ()
    usages = prev._get_usages_of_ref(ap_ref)
    expected = {
        annot_path + '/AP' for annot_path in prev._get_usages_of_ref(annot_ref)
    }
    if not usages or usages - expected:
        raise SuspiciousModification(
            f"Appearance dictionary {ap_ref} of annotation {annot_ref} was "
            "overridden in place, but it is shared with other parts of the "
            "document."
        )
    return usages


def _allow_in_place_appearance_updates(
    prev, new, annot_ref, prev_annot, new_annot, subtype, page_ref
):
    """
    Allow an annotation's appearance streams to be overridden in place, but
    only when they're used exclusively by that annotation.
    """
    try:
        prev_ap_raw = prev_annot.raw_get('/AP')
        new_ap_raw = new_annot.raw_get('/AP')
    except KeyError:
        return

    prev_ap = prev_ap_raw.get_object()
    new_ap = new_ap_raw.get_object()
    if not isinstance(prev_ap, DictionaryObject) or not isinstance(
        new_ap, DictionaryObject
    ):
        return

    if (
        isinstance(prev_ap_raw, IndirectObject)
        and isinstance(new_ap_raw, IndirectObject)
        and prev_ap_raw.reference == new_ap_raw.reference
    ):
        for ap_path in _clear_indirect_ap_dict(prev, annot_ref, prev_ap_raw):
            yield AnnotationUpdate(
                updated_ref=prev_ap_raw.reference,
                context_checked=Context.from_absolute(prev, ap_path),
                subtype=subtype,
                page_ref=page_ref,
            )

    for key in ('/N', '/R', '/D'):
        try:
            prev_stream_raw = prev_ap.raw_get(key)
            new_stream_raw = new_ap.raw_get(key)
        except KeyError:
            continue
        if not isinstance(new_stream_raw, IndirectObject):
            continue
        new_stream_ref = new_stream_raw.reference
        if (
            not isinstance(prev_stream_raw, IndirectObject)
            or prev_stream_raw.reference != new_stream_ref
        ):
            # The annotation now points to a different stream; if it's new,
            # it will be cleared as a dependency, otherwise it's an
            # unexplained override that will be caught later.
            continue
        xrefs = prev.reader.xrefs
        try:
            last_change = xrefs.get_last_change(new_stream_ref)
        except KeyError:  # pragma: nocover
            continue
        if last_change == prev.revision:
            # The stream wasn't touched in this revision.
            continue
        contexts = _appearance_stream_contexts(prev, annot_ref, prev_annot, key)
        if not contexts:
            raise SuspiciousModification(
                f"Appearance stream {new_stream_ref} of annotation "
                f"{annot_ref} was overridden in place, but it is shared with "
                "other parts of the document."
            )
        for ctx in contexts:
            yield AnnotationUpdate(
                updated_ref=new_stream_ref,
                context_checked=ctx,
                subtype=subtype,
                page_ref=page_ref,
            )
        # pull in any newly created objects used by the appearance stream
        yield from _child_dependencies(
            prev, new, new_stream_raw, subtype, page_ref
        )


def _check_cross_annotation_references(prev, annot_ref, prev_annot, new_annot):
    """
    Make sure that /Popup and /IRT entries only point to annotations that
    already existed, or to objects newly created in the revision under review.
    """
    for key in ('/Popup', '/IRT'):
        try:
            new_raw = new_annot.raw_get(key)
        except KeyError:
            # Deletion of /Popup or /IRT is covered by compare_dicts.
            continue
        if not isinstance(new_raw, IndirectObject):
            raise SuspiciousModification(
                f"{key} entry of annotation {annot_ref} should be an "
                "indirect reference"
            )
        prev_raw = prev_annot.raw_get(key) if key in prev_annot else None
        if prev_raw == new_raw:
            continue
        if not prev.is_ref_unassignable(new_raw.reference):
            raise SuspiciousModification(
                f"{key} entry of annotation {annot_ref} points to "
                f"{new_raw.reference}, which already existed in a prior "
                "revision."
            )


def _process_new_annotation(prev, new, annot_ref, annot, page_ref):
    """
    Validate a newly created annotation, yielding the annotation objects to be
    cleared at :attr:`.ModificationLevel.ANNOTATIONS`.

    Widget annotations are out of scope: they are form fields, and are
    adjudicated by the form updating rules instead.
    """
    if not prev.is_ref_unassignable(annot_ref):
        raise SuspiciousModification(
            f"New annotation {annot_ref} in revision {new.revision} refers to "
            "an object that already existed in a prior revision.",
            revision=new.revision,
            locations=(annot_ref,),
        )
    if not isinstance(annot, DictionaryObject) or isinstance(
        annot, StreamObject
    ):
        raise SuspiciousModification(
            f"Annotation {annot_ref} in revision {new.revision} is not a "
            "dictionary object.",
            revision=new.revision,
            locations=(annot_ref,),
        )
    if _is_form_fieldish(annot):
        # Form fields (including widget annotations) are out of scope for
        # this rule; the form updating rules have to justify these.
        return
    subtype = _validate_annotation_dict(annot, SuspiciousModification, page_ref)
    yield AnnotationUpdate(
        updated_ref=annot_ref, subtype=subtype, page_ref=page_ref
    )
    yield from _child_dependencies(prev, new, annot, subtype, page_ref)


def _process_modified_annotation(
    prev, new, annot_ref, prev_annot, new_annot, page_ref
):
    """
    Validate an existing annotation whose object was overridden in the
    revision under review.
    """
    if _is_form_fieldish(prev_annot):
        # Widgets (form fields) are judged by the form rules, not by us.
        return
    if _is_form_fieldish(new_annot):
        # A non-form-field annotation must not be turned into a form field.
        raise SuspiciousModification(
            f"Annotation {annot_ref} in revision {new.revision} was turned "
            "into a form field or widget annotation.",
            revision=new.revision,
            locations=(annot_ref,),
        )
    prev_subtype = _annotation_subtype(prev_annot)
    new_subtype = _validate_annotation_dict(
        new_annot, SuspiciousModification, page_ref
    )
    if prev_subtype != new_subtype:
        raise SuspiciousModification(
            f"Annotation {annot_ref} in revision {new.revision} changed "
            f"subtype from {prev_subtype!r} to {new_subtype!r}.",
            revision=new.revision,
            locations=(annot_ref,),
        )
    # Everything outside the allowlist of annotation content keys must be
    # identical. This covers /P, /Subtype, /Type, /StructParent, ...
    compare_dicts(prev_annot, new_annot, ANNOTATION_MUTABLE_KEYS)
    _check_cross_annotation_references(prev, annot_ref, prev_annot, new_annot)

    # Clear the annotation object itself. We only clear the paths through
    # which it was reachable in the prior revision, and only if all of those
    # look like genuine annotation usage paths.
    usages = _annotation_usage_paths(prev, annot_ref)
    for path in usages:
        yield AnnotationUpdate(
            updated_ref=annot_ref,
            context_checked=Context.from_absolute(prev, path),
            subtype=new_subtype,
            page_ref=page_ref,
        )

    yield from _allow_in_place_appearance_updates(
        prev, new, annot_ref, prev_annot, new_annot, new_subtype, page_ref
    )
    yield from _child_dependencies(prev, new, new_annot, new_subtype, page_ref)


def _annot_object(resolver, ref, exc_cls):
    obj = resolver(ref)
    if not isinstance(obj, DictionaryObject) or isinstance(obj, StreamObject):
        raise exc_cls(f"Annotation {ref} is not a dictionary object")
    return obj


def _page_annots(page, exc_cls):
    try:
        return _extract_annots_from_page(page, exc_cls)
    except KeyError:
        return set(), None


def _process_page(prev, new, page_ref, new_xrefs):
    """
    Validate the changes to a single page.

    This generator yields ``(level, update)`` tuples, all qualified at
    :attr:`.ModificationLevel.ANNOTATIONS`.
    """
    prev_page = prev(page_ref)
    new_page = new(page_ref)
    if not isinstance(prev_page, DictionaryObject):
        raise misc.PdfReadError("Page objects should be dictionaries")
    if not isinstance(new_page, DictionaryObject):
        raise SuspiciousModification("Page objects should be dictionaries")

    prev_annots, _prev_annots_ref = _page_annots(prev_page, misc.PdfReadError)
    new_annots, new_annots_ref = _page_annots(new_page, SuspiciousModification)

    deleted = prev_annots - new_annots
    added = new_annots - prev_annots
    overridden = (prev_annots & new_annots) & new_xrefs

    page_changed = page_ref in new_xrefs
    annots_array_changed = (
        new_annots_ref is not None and new_annots_ref in new_xrefs
    )

    if not (
        deleted or added or overridden or page_changed or annots_array_changed
    ):
        return

    if page_changed:
        # No page content, resources or anything else may change; only the
        # annotation array is fair game.
        compare_dicts(prev_page, new_page, frozenset({'/Annots'}))

    annotation_level_activity = False

    # Deletions of ordinary (non-widget) annotations are permitted by DocMDP
    # level 3. We do not clear the deleted objects themselves: freeing objects
    # is governed by the policy-level setting, and the removal from the
    # /Annots array is all that is needed to make the change effective.
    for annot_ref in deleted:
        annot = _annot_object(prev, annot_ref, misc.PdfReadError)
        if _is_widget(annot):
            raise SuspiciousModification(
                f"Widget annotation {annot_ref} was removed from the "
                "annotation array of a page.",
                revision=new.revision,
                locations=(annot_ref,),
            )
        annotation_level_activity = True

    for annot_ref in added:
        annot = _annot_object(new, annot_ref, SuspiciousModification)
        if not _is_form_fieldish(annot):
            annotation_level_activity = True
        for upd in _process_new_annotation(
            prev, new, annot_ref, annot, page_ref
        ):
            yield ANNOTATION_LEVEL, upd

    for annot_ref in overridden:
        prev_annot = _annot_object(prev, annot_ref, misc.PdfReadError)
        new_annot = _annot_object(new, annot_ref, SuspiciousModification)
        if prev_annot == new_annot:
            # No-op override; the identical-object logic deals with this.
            continue
        if not _is_form_fieldish(prev_annot) and not _is_form_fieldish(
            new_annot
        ):
            annotation_level_activity = True
        for upd in _process_modified_annotation(
            prev, new, annot_ref, prev_annot, new_annot, page_ref
        ):
            yield ANNOTATION_LEVEL, upd

    if not annotation_level_activity:
        # Nothing in this revision falls within this rule's scope. Widget
        # annotations are handled by the form updating rules, and any other
        # changes will be flagged by the xref crawler. Do not clear anything
        # here, so as to avoid weakening the more specialised rules.
        return

    # Clear the page object as a whole. Page objects are reachable through a
    # lot of paths (structure tree /Pg, annotation /P, link destinations, ...),
    # so path-level approval would be impractical. This is safe: we verified
    # above that only /Annots was touched.
    if page_changed:
        yield (
            ANNOTATION_LEVEL,
            AnnotationUpdate(
                updated_ref=page_ref,
                subtype=None,
                page_ref=page_ref,
                context_checked=None,
            ),
        )

    if annots_array_changed:
        yield (
            ANNOTATION_LEVEL,
            AnnotationUpdate(
                updated_ref=new_annots_ref,
                context_checked=RelativeContext(
                    page_ref, RawPdfPath('/Annots')
                ),
                subtype=None,
                page_ref=page_ref,
            ),
        )


def _walk_page_tree(old, prev, new, node_ref, new_xrefs):
    old_node = old(node_ref)
    new_node = new(node_ref)
    if not isinstance(old_node, DictionaryObject):
        raise misc.PdfReadError("Page tree nodes should be dictionaries")
    if not isinstance(new_node, DictionaryObject):
        raise SuspiciousModification("Page tree nodes should be dictionaries")

    try:
        node_type = old_node['/Type']
    except (KeyError, TypeError) as e:  # pragma: nocover
        raise misc.PdfReadError("Invalid page tree node") from e

    if node_type == '/Pages':
        # Page tree structure changes are never acceptable after signing,
        # regardless of the DocMDP level.
        compare_dicts(old_node, new_node, frozenset({'/Kids'}))
        try:
            old_kids = _arr_to_refs(
                old_node['/Kids'], misc.PdfReadError, collector=list
            )
            new_kids = _arr_to_refs(
                new_node['/Kids'], SuspiciousModification, collector=list
            )
        except KeyError:  # pragma: nocover
            raise misc.PdfReadError("No /Kids in /Pages entry")
        if old_kids != new_kids:
            raise SuspiciousModification(
                "Unexpected change to page tree structure."
            )
        for kid_ref in old_kids:
            yield from _walk_page_tree(old, prev, new, kid_ref, new_xrefs)
    elif node_type == '/Page':
        yield from _process_page(prev, new, node_ref, new_xrefs)
    else:  # pragma: nocover
        raise SuspiciousModification(
            f"Unexpected page tree node type {node_type!r}"
        )


class AnnotationModificationRule(AnnotationUpdateRule):
    """
    Rule that adjudicates annotation creation, deletion and modification
    after a certification signature that permits annotation changes
    (``/DocMDP`` level :attr:`~pyhanko.sign.fields.MDPPerm.ANNOTATE`).

    The rule is intentionally limited in scope. It clears:

    * the annotation objects themselves, if they were newly created in the
      revision under review, along with the appearance resources (and other
      objects) that they introduce;
    * the contents of existing annotations, but only for the keys that
      constitute annotation content or presentation (see
      :const:`.ANNOTATION_MUTABLE_KEYS`);
    * appearance streams overridden in place, provided that they are used by
      the annotation in question and nowhere else;
    * the ``/Annots`` arrays of the pages involved, and the page objects
      themselves, to the extent needed to register the change.

    Everything else is left for other rules to adjudicate. In particular:

    * form fields and widget annotations are *not* cleared by this rule;
    * additions, deletions or in-place overrides of page content are rejected;
    * modifications to the structure tree and the ``/ParentTree`` are
      rejected, even when they would be needed to make an annotation
      accessible in a tagged document;
    * metadata streams and signature fields cannot be cleared by virtue of an
      annotation update;
    * newly created objects reachable from an annotation are checked to
      ensure that they don't impersonate structural objects or form fields.

    The adjudication is performed relative to the revision immediately
    preceding the one under review, so that an annotation created by an
    earlier incremental update and subsequently modified is judged as a
    modification.
    """

    def apply(
        self, old: HistoricalResolver, new: HistoricalResolver
    ) -> Iterable[tuple[ModificationLevel, AnnotationUpdate]]:
        new_xrefs = new.explicit_refs_in_revision()
        try:
            old_pages_ref = old.root.get_value_as_reference('/Pages')
            new_pages_ref = new.root.get_value_as_reference('/Pages')
        except (KeyError, misc.IndirectObjectExpected) as e:
            raise SuspiciousModification(
                "Could not locate the page tree root"
            ) from e
        if old_pages_ref != new_pages_ref:
            raise SuspiciousModification(
                "The document catalog points to a different page tree root."
            )

        if new.revision <= 0:  # pragma: nocover
            prev = new
        else:
            prev = new.reader.get_historical_resolver(new.revision - 1)

        yield from _walk_page_tree(old, prev, new, new_pages_ref, new_xrefs)
