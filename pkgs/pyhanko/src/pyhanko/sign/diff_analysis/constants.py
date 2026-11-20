"""
Internal constants for the difference analysis sub-package.
"""

import re

__all__ = [
    'ACROFORM_EXEMPT_STRICT_COMPARISON',
    'ANNOTATION_MUTABLE_KEYS',
    'FORMFIELD_ALWAYS_MODIFIABLE',
    'ROOT_EXEMPT_STRICT_COMPARISON',
    'VALUE_UPDATE_KEYS',
    'VRI_KEY_PATTERN',
]

# /Type: dictionary type (can always be added if correct)
# /Ff: Form field flags
FORMFIELD_ALWAYS_MODIFIABLE = frozenset({'/Ff', '/Type'})

# /AP: appearance dictionary
# /AS: current appearance state
# /V: field value
# /F: (widget) annotation flags
# /DA: default appearance
# /Q: quadding
VALUE_UPDATE_KEYS = FORMFIELD_ALWAYS_MODIFIABLE | frozenset(
    {
        '/AP',
        '/AS',
        '/V',
        '/F',
        '/DA',
        '/Q',
    }
)

VRI_KEY_PATTERN = re.compile('/[A-Z0-9]{40}')

ACROFORM_EXEMPT_STRICT_COMPARISON = frozenset(
    {
        '/Fields',
        '/DR',
        '/DA',
        '/Q',
        '/NeedAppearances',
    }
)

ROOT_EXEMPT_STRICT_COMPARISON = frozenset(
    {
        '/AcroForm',
        '/DSS',
        '/Extensions',
        '/Metadata',
        '/MarkInfo',
        '/Version',
    }
)

# Keys in an annotation dictionary that may change as part of an ordinary
# annotation update, i.e. without the annotation being replaced wholesale.
#
# These cover the annotation's content, state and presentation. Structural
# keys such as /Type, /Subtype, /P, /StructParent, /Parent, /Kids and /Obj are
# deliberately omitted: allowing those to change would let an annotation update
# smuggle in changes to the page tree, the structure tree or the form field
# hierarchy.
ANNOTATION_MUTABLE_KEYS = frozenset(
    {
        # content
        '/Contents',
        '/C',
        '/IC',
        '/CA',
        '/RC',
        '/RD',
        '/Q',
        '/Lang',
        '/NM',
        # presentation
        '/AP',
        '/AS',
        '/F',
        '/Rect',
        '/BS',
        '/BE',
        '/MK',
        '/Border',
        '/DA',
        '/DS',
        '/FontSize',
        '/BM',
        # action / interaction
        '/A',
        '/AA',
        '/Open',
        '/H',
        # annotation state
        '/State',
        '/StateModel',
        '/Subj',
        '/M',
        '/CreationDate',
        # text markup geometry
        '/InkList',
        '/L',
        '/LE',
        '/Vertices',
        '/QuadPoints',
        '/CL',
        '/Coords',
        '/IT',
        '/RT',
        # replies and popups (references to other annotations are checked
        # separately)
        '/IRT',
        '/Popup',
        # attachments / media
        '/FS',
        '/Sound',
        '/Movie',
        # measurement
        '/Measure',
    }
)
