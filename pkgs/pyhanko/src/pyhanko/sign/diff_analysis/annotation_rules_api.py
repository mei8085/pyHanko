"""
Module defining API types for rules that adjudicate annotation changes.

These types are only relevant to the difference analysis machinery; they are
not part of the high-level validation API.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pyhanko.pdf_utils.generic import Reference
from pyhanko.pdf_utils.reader import HistoricalResolver

from .policy_api import ModificationLevel
from .rules_api import ReferenceUpdate

__all__ = [
    'AnnotationUpdate',
    'AnnotationUpdateRule',
]


@dataclass(frozen=True)
class AnnotationUpdate(ReferenceUpdate):
    """
    Container for a reference together with (optional) metadata about the
    annotation it belongs to.

    The metadata is used for diagnostics and for attributing a modification
    to a particular annotation subtype, but does not influence the judgment of
    the diff policy itself.
    """

    subtype: str | None = None
    """
    The annotation's ``/Subtype``, if known.
    """

    page_ref: Reference | None = None
    """
    Reference to the page on which the annotation lives, if known.
    """


class AnnotationUpdateRule:
    """
    Abstract base class for rules that validate changes to annotations
    (as opposed to form fields).

    Annotation update rules are only consulted when the document modification
    policy in force actually permits annotation changes, i.e. when the
    applicable ``/DocMDP`` level is
    :attr:`~pyhanko.sign.fields.MDPPerm.ANNOTATE`.

    Implementations are expected to be conservative: they should only clear
    the annotation objects (and the resources that are directly tied to them,
    such as appearance streams) whose modification is both permitted by the
    specification and justified by the revision being reviewed. In particular,
    an annotation rule must not clear modifications to page content, the
    document structure tree, metadata streams or signature fields; those
    remain the responsibility of other rules.

    Rules may raise :class:`.SuspiciousModification` to veto an entire
    revision.
    """

    def apply(
        self, old: HistoricalResolver, new: HistoricalResolver
    ) -> Iterable[tuple[ModificationLevel, AnnotationUpdate]]:
        """
        Apply the rule to the changes between two revisions.

        :param old:
            The older, base revision.
        :param new:
            The newer revision to be vetted.
        :return:
            An iterable of :class:`.AnnotationUpdate` objects, qualified with
            an appropriate :class:`.ModificationLevel`.
        """
        raise NotImplementedError
