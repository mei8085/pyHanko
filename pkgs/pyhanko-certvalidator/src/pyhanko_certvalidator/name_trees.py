import enum
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

from asn1crypto import x509
from uritools import urisplit

logger = logging.getLogger(__name__)


class NameConstraintError(ValueError):
    """
    Raised when a name constraint cannot be evaluated, or when a name cannot
    be interpreted in the context of the applicable constraints.

    In the context of path validation, this error is always converted into a
    rejection of the certificate under scrutiny, never into an unhandled
    exception. See :class:`.MalformedNameConstraintError` and
    :class:`.UnsupportedNameTypeError` for the two specific subclasses.
    """


class MalformedNameConstraintError(NameConstraintError):
    """
    Raised when a name constraint (or a name occurring in a certificate) is
    structurally invalid in a way that makes evaluating it unsafe.
    """


class UnsupportedNameTypeError(NameConstraintError, NotImplementedError):
    """
    Raised when a name constraint of a name form without defined containment
    semantics is encountered.

    Per :rfc:`5280`, an application that cannot process a constraint on a
    particular name form must reject the certificate if such a name occurs.
    Inheriting from :class:`NotImplementedError` as well as
    :class:`.NameConstraintError` is a compatibility measure.
    """

    def __init__(self, name_type: 'GeneralNameType', reason: str | None = None):
        msg = f"Unsupported name constraint for {name_type.name.lower()}"
        if reason:
            msg = f"{msg}: {reason}"
        super().__init__(msg)
        self.name_type = name_type
        self.reason = reason


# RFC 4343 § 3
_ASCII_CASE_FOLD = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'
)


def _normalise_host(host: str) -> str:
    # strip trailing . for notation including the root zone,
    # apply RFC 4343 case folding rule
    if len(host) > 1 and host[-1] == '.':
        host = host[:-1]
    return host.translate(_ASCII_CASE_FOLD)


def host_tree_contains(base_host: str, other_host: str) -> bool:
    base_host = _normalise_host(base_host)
    other_host = _normalise_host(other_host)
    if not base_host:
        raise NameConstraintError(
            "A constraint with an empty host name is undefined."
        )
    # if the constraint starts with '.', it specifies a domain, and must be
    # expanded with one or more labels, otherwise it refers to a single host.
    if base_host[0] == '.':
        pre, _, post = other_host.rpartition(base_host)
        return bool(pre) and not bool(post)
    else:
        return other_host == base_host


def _host_regname(cand_uri):
    cand_host = urisplit(cand_uri).gethost()
    if not cand_host or isinstance(cand_host, (IPv4Address, IPv6Address)):
        host_err = (
            f'has host {cand_host}.'
            if cand_host is not None
            else ('is not a well-formed URI.')
        )
        msg = (
            "URI constraints require URIs with a host specified as a FQDN; "
            f"URI '{cand_uri}' {host_err}."
        )
        logger.warning(msg)
        raise NameConstraintError(msg)
    return cand_host


def uri_tree_contains(base: str, other: str) -> bool:
    # The constraint applies to the host part
    other_host: str = _host_regname(other)
    return host_tree_contains(base, other_host)


def dns_tree_contains(base: str, other: str):
    # check if 'other' consists of adding zero or more labels to 'base'
    #  (from the left)
    base_labels = _normalise_host(base).split('.')
    other_labels = _normalise_host(other).split('.')
    if len(other_labels) < len(base_labels):
        return False
    return len(other_labels) >= len(base_labels) and all(
        x == y for x, y in zip(reversed(other_labels), reversed(base_labels))
    )


def email_tree_contains(base: str, other: str):
    # use rpartition instead of rsplit to deal with the case where there's no @
    # uniformly
    base_mailbox, _, base_host_or_domain = base.rpartition('@')
    other_mailbox, _, other_host_or_domain = other.rpartition('@')

    if base_mailbox:
        # only exact match (modulo case folding/normalisation rules)
        base_norm = _normalise_host(base_host_or_domain)
        other_norm = _normalise_host(other_host_or_domain)
        return base_mailbox == other_mailbox and base_norm == other_norm
    else:
        return host_tree_contains(base_host_or_domain, other_host_or_domain)


def dirname_tree_contains(base: x509.Name, other: x509.Name):
    base_rdn_sequence = base.chosen
    other_rdn_sequence = other.chosen

    return len(other_rdn_sequence) >= len(base_rdn_sequence) and all(
        x == y for x, y in zip(base_rdn_sequence, other_rdn_sequence)
    )


# Name constraints on iPAddress values are encoded as a fixed-length octet
# string containing an address immediately followed by a netmask (RFC 5280,
# § 4.2.1.10). For IPv4, both parts are 4 octets long; for IPv6, 16 octets.
_IP_CONSTRAINT_OCTET_LENGTHS = {8: 4, 32: 16}


def _decode_ip_constraint(raw: bytes) -> IPv4Network | IPv6Network:
    """
    Interpret the raw contents of an ``iPAddress`` name constraint.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise MalformedNameConstraintError(
            f"The IP address constraint {raw!r} is not encoded as an octet "
            "string."
        )
    raw = bytes(raw)
    addr_len = _IP_CONSTRAINT_OCTET_LENGTHS.get(len(raw))
    if addr_len is None:
        raise MalformedNameConstraintError(
            "IP address name constraints must contain 8 (IPv4) or 32 (IPv6) "
            f"octets, but this one contains {len(raw)}."
        )
    addr_bytes, mask_bytes = raw[:addr_len], raw[addr_len:]
    nbits = addr_len * 8
    full_mask = (1 << nbits) - 1
    mask = int.from_bytes(mask_bytes, 'big')
    # RFC 4632 style CIDR: the mask must consist of a contiguous run of
    # high-order 1 bits. Anything else cannot be interpreted as a range, and
    # evaluating it as one would be unsafe.
    host_bits = (mask ^ full_mask).bit_length()
    prefix_len = nbits - host_bits
    expected_mask = (full_mask << host_bits) & full_mask if prefix_len else 0
    if mask != expected_mask:
        raise MalformedNameConstraintError(
            "The netmask in an IP address name constraint is not a valid "
            "CIDR mask."
        )
    addr_int = int.from_bytes(addr_bytes, 'big')
    # The address in the constraint must be the network address of the range
    # it describes; any other address in the range would silently widen the
    # constraint, which is unsafe.
    if prefix_len and addr_int & ((1 << host_bits) - 1):
        raise MalformedNameConstraintError(
            "The address in an IP address name constraint has host bits set."
        )
    if addr_len == 4:
        return IPv4Network((IPv4Address(addr_int), prefix_len), strict=False)
    else:
        return IPv6Network((IPv6Address(addr_int), prefix_len), strict=False)


def _decode_ip_name(raw: bytes) -> IPv4Address | IPv6Address:
    """
    Interpret the raw contents of an ``iPAddress`` subject alternative name.

    Unlike name constraints, plain IP SANs contain a bare address, with no
    netmask.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise MalformedNameConstraintError(
            f"The IP address name {raw!r} is not encoded as an octet string."
        )
    raw = bytes(raw)
    if len(raw) == 4:
        return IPv4Address(raw)
    elif len(raw) == 16:
        return IPv6Address(raw)
    else:
        raise MalformedNameConstraintError(
            "IP address names must contain 4 (IPv4) or 16 (IPv6) octets, "
            f"but this one contains {len(raw)}."
        )


def _parse_ip_constraint(value) -> IPv4Network | IPv6Network:
    if isinstance(value, (IPv4Network, IPv6Network)):
        return value
    if isinstance(value, (IPv4Address, IPv6Address)):
        return ip_network(f'{value}/{value.max_prefixlen}')
    if isinstance(value, (bytes, bytearray)):
        return _decode_ip_constraint(value)
    if isinstance(value, str):
        try:
            # A bare address is interpreted as a single-host range. As with
            # the DER encoding, a range whose address has host bits set is
            # rejected rather than silently widened.
            return ip_network(value, strict=True)
        except ValueError as e:
            raise MalformedNameConstraintError(
                f"'{value}' is not a valid IP address constraint."
            ) from e
    raise MalformedNameConstraintError(
        f"'{value}' is not a valid IP address constraint."
    )


def _parse_ip_name(value) -> IPv4Address | IPv6Address:
    if isinstance(value, (IPv4Address, IPv6Address)):
        return value
    # A plain network object is not a valid name, but callers that supply
    # one almost certainly meant the corresponding host address; rejecting
    # it outright would be unhelpful.
    if isinstance(value, (IPv4Network, IPv6Network)):
        if value.prefixlen != value.max_prefixlen:
            raise MalformedNameConstraintError(
                f"'{value}' is an IP address range, not an IP address name."
            )
        return value.network_address
    if isinstance(value, (bytes, bytearray)):
        return _decode_ip_name(value)
    if isinstance(value, str):
        try:
            return ip_address(value)
        except ValueError as e:
            raise MalformedNameConstraintError(
                f"'{value}' is not a valid IP address name."
            ) from e
    raise MalformedNameConstraintError(
        f"'{value}' is not a valid IP address name."
    )


def ip_tree_contains(base, other) -> bool:
    """
    Determine whether an IP address name is contained in an IP address
    constraint subtree.

    The constraint is interpreted as a CIDR range, and the name as a single
    address. IPv4 and IPv6 address spaces are disjoint: an address is never
    contained in a constraint of the other address family.

    :param base:
        The constraint. Can be an :class:`ipaddress.IPv4Network`,
        :class:`ipaddress.IPv6Network`, an address, a CIDR string, or the raw
        octet string contents of an ``iPAddress`` constraint.
    :param other:
        The name to test. Can be an :class:`ipaddress.IPv4Address`,
        :class:`ipaddress.IPv6Address`, an address string, or the raw octet
        string contents of an ``iPAddress`` name.
    :raises MalformedNameConstraintError:
        If either value cannot be interpreted safely.
    """
    network = _parse_ip_constraint(base)
    address = _parse_ip_name(other)
    return network.version == address.version and address in network


class GeneralNameType(enum.Enum):
    OTHER_NAME = enum.auto()
    RFC822_NAME = enum.auto()
    DNS_NAME = enum.auto()
    X400_ADDRESS = enum.auto()
    DIRECTORY_NAME = enum.auto()
    EDI_PARTY_NAME = enum.auto()
    UNIFORM_RESOURCE_IDENTIFIER = enum.auto()
    IP_ADDRESS = enum.auto()
    REGISTERED_ID = enum.auto()

    @property
    def check_membership(self) -> Callable[[object, object], bool] | None:
        return _name_type_checkers.get(self, None)

    @classmethod
    def from_choice(cls, choice) -> 'GeneralNameType':
        return getattr(cls, choice.upper())


_name_type_checkers: dict[
    GeneralNameType, Callable[[object, object], bool]
] = {
    GeneralNameType.DIRECTORY_NAME: dirname_tree_contains,
    GeneralNameType.RFC822_NAME: email_tree_contains,
    GeneralNameType.DNS_NAME: dns_tree_contains,
    GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER: uri_tree_contains,
    GeneralNameType.IP_ADDRESS: ip_tree_contains,
}


class _InvalidName:
    """
    Marker for a name (or constraint) that could not be interpreted safely.
    """

    __slots__ = ('error',)

    def __init__(self, error: NameConstraintError):
        self.error = error

    def __repr__(self):
        return f'<_InvalidName: {self.error}>'


def _string_native(name_type: 'GeneralNameType', chosen) -> str:
    try:
        value = chosen.native
    except Exception as e:  # noqa: BLE001
        raise MalformedNameConstraintError(
            f"Could not interpret a name of type "
            f"{name_type.name.lower()}: {e}"
        ) from e
    if not isinstance(value, str):
        raise MalformedNameConstraintError(
            f"The {name_type.name.lower()} name does not have a string "
            "representation."
        )
    return value


def _unsupported_name_value(gname) -> bytes:
    # For name forms without defined containment semantics, we only need a
    # stable, hashable representation; it is never used to match anything.
    try:
        return gname.dump()
    except Exception as e:  # noqa: BLE001
        raise MalformedNameConstraintError(
            "Could not interpret the name."
        ) from e


def _canonical_name_value(name_type: GeneralNameType, chosen, gname=None):
    """
    Convert a general name occurring in a certificate into a canonical value
    for matching against constraints.
    """
    if name_type == GeneralNameType.DIRECTORY_NAME:
        return chosen
    elif name_type == GeneralNameType.IP_ADDRESS:
        # Keep the raw octets; they are decoded lazily by the IP address
        # containment checker. That way a malformed IP name only causes a
        # rejection if an IP address constraint actually applies to it.
        raw = getattr(chosen, 'contents', None)
        if not isinstance(raw, (bytes, bytearray)):
            raise MalformedNameConstraintError(
                f"The IP address name {raw!r} is not encoded as an octet "
                "string."
            )
        return bytes(raw)
    elif name_type in _name_type_checkers:
        return _string_native(name_type, chosen)
    else:
        return _unsupported_name_value(gname)


def _canonical_constraint_value(name_type: GeneralNameType, chosen, gname=None):
    """
    Convert the base of a general subtree into a canonical constraint value.
    """
    if name_type == GeneralNameType.DIRECTORY_NAME:
        return chosen
    elif name_type == GeneralNameType.IP_ADDRESS:
        return _decode_ip_constraint(getattr(chosen, 'contents', None))
    elif name_type in _name_type_checkers:
        return _string_native(name_type, chosen)
    else:
        return _unsupported_name_value(gname)


def _interpret_general_name(gname: x509.GeneralName, *, is_constraint: bool):
    try:
        gname_type = GeneralNameType.from_choice(gname.name)
    except Exception as e:  # noqa: BLE001
        raise MalformedNameConstraintError(
            f"Could not determine the type of a general name: {e}"
        ) from e
    if gname_type.check_membership is None:
        # No containment semantics are defined for this name form. We won't
        # ever need to match it, so it is enough to keep a stable
        # representation of the raw encoding.
        return gname_type, _unsupported_name_value(gname)
    try:
        chosen = gname.chosen
    except Exception as e:  # noqa: BLE001
        return gname_type, _InvalidName(
            MalformedNameConstraintError(
                f"Could not interpret a name of type "
                f"{gname_type.name.lower()}: {e}"
            )
        )
    try:
        # note: IP address names and IP address constraints share the same
        # ASN.1 type, but have a different encoding; see RFC 5280 § 4.2.1.10.
        if is_constraint:
            value = _canonical_constraint_value(gname_type, chosen, gname)
        else:
            value = _canonical_name_value(gname_type, chosen, gname)
    except NameConstraintError as e:
        value = _InvalidName(e)
    except Exception as e:  # noqa: BLE001
        value = _InvalidName(
            MalformedNameConstraintError(
                f"Could not interpret a name of type "
                f"{gname_type.name.lower()}: {e}"
            )
        )
    return gname_type, value


def _enumerate_names_in_cert(cert: x509.Certificate):
    # start with the subject's distinguished name, if it is non-empty
    if len(cert.subject.chosen):
        yield GeneralNameType.DIRECTORY_NAME, cert.subject

    subject_alt_names: x509.GeneralNames = cert.subject_alt_name_value
    if subject_alt_names is None:
        # if the subject has email address component(s) and no subjectAltName
        # name constraints for rfc822Name-type names should also apply to those
        # addresses
        name_pair: x509.NameTypeAndValue
        for rdn in cert.subject.chosen:
            for name_pair in rdn:
                if name_pair['type'].native == 'email_address':
                    yield GeneralNameType.RFC822_NAME, name_pair['value'].native
    else:
        for name in subject_alt_names:
            yield _interpret_general_name(name, is_constraint=False)


class _StringOrName:
    # Wrapper class for hashing purposes. Not for external use.

    def __init__(self, value):
        self.value = value

    @property
    def _code(self):
        val = self.value
        if isinstance(val, x509.Name):
            return 0, val.dump()
        elif isinstance(val, (IPv4Network, IPv6Network)):
            return 2, val.version, int(val.network_address), val.prefixlen
        elif isinstance(val, (IPv4Address, IPv6Address)):
            return 3, val.version, int(val)
        elif isinstance(val, bytes):
            return 4, val
        elif isinstance(val, _InvalidName):
            return 5, str(val.error)
        else:
            return 1, val

    def __hash__(self):
        return hash(self._code)

    def __eq__(self, other):
        return isinstance(other, _StringOrName) and self._code == other._code


@dataclass(frozen=True)
class NameSubtree:
    name_type: GeneralNameType
    tree_base: _StringOrName | None
    min: int = 0
    max: int | None = None
    _invalid: NameConstraintError | None = None

    def __contains__(self, item) -> bool:
        # A name that could not be interpreted safely is never contained in
        # anything, not even a universal acceptor: we cannot tell whether it
        # would be permitted, so the certificate must be rejected.
        if isinstance(item, _InvalidName):
            raise item.error

        if self.tree_base is None:  # special value: accept all certs
            return True

        if self._invalid is not None:
            raise self._invalid

        # min / max are not meaningful in the PKIX (RFC 5280) profile; per
        # RFC 5280 § 4.2.1.10 we must either process them or reject the
        # certificate. We do the latter, safely.
        if self.min != 0 or self.max is not None:
            raise UnsupportedNameTypeError(
                self.name_type,
                "the minimum/maximum fields are not processed",
            )
        checker = self.name_type.check_membership
        if checker is None:
            # No containment semantics are defined for this name form; per
            # RFC 5280, a constraint on it must lead to rejection of the
            # certificate if a name of that form occurs.
            raise UnsupportedNameTypeError(
                self.name_type,
                "no containment semantics are defined for this name form",
            )
        try:
            return checker(self.tree_base.value, item)
        except NameConstraintError:
            raise
        except Exception as e:  # noqa: BLE001
            raise MalformedNameConstraintError(
                f"Could not evaluate a {self.name_type.name.lower()} "
                f"name constraint: {e}"
            ) from e

    @classmethod
    def from_name(cls, name_type: GeneralNameType, name: str | x509.Name):
        return NameSubtree(name_type=name_type, tree_base=_StringOrName(name))

    @classmethod
    def from_general_subtree(cls, subtree) -> 'NameSubtree':
        try:
            gname = subtree['base']
            minimum = subtree['minimum'].native
            maximum = subtree['maximum'].native
        except Exception as e:  # noqa: BLE001
            raise MalformedNameConstraintError(
                f"Could not parse a name constraint subtree: {e}"
            ) from e
        name_type, name_obj = _interpret_general_name(
            gname, is_constraint=True
        )
        invalid = name_obj.error if isinstance(name_obj, _InvalidName) else None
        if isinstance(minimum, int) and minimum < 0:
            invalid = MalformedNameConstraintError(
                "A name constraint has a negative minimum."
            )
        return NameSubtree(
            name_type,
            _StringOrName(name_obj),
            min=minimum,
            max=maximum,
            _invalid=invalid,
        )

    @classmethod
    def universal_tree(cls, name_type: GeneralNameType) -> 'NameSubtree':
        """
        Tree that contains all names of a given type.

        :param name_type:
            The name type to use.
        :return:
        """
        return NameSubtree(name_type=name_type, tree_base=None)

    @classmethod
    def reject_all(
        cls, name_type: GeneralNameType, error: NameConstraintError
    ) -> 'NameSubtree':
        """
        Tree that rejects every name of a given type, because the constraint
        it stands in for could not be processed safely.
        """
        return NameSubtree(
            name_type=name_type,
            tree_base=_StringOrName(b''),
            _invalid=error,
        )


# a subtree collection as used in the PKIX validation algorithm
PKIXSubtrees = dict[GeneralNameType, set[NameSubtree]]


def x509_names_to_subtrees(names: Iterable[x509.Name]) -> PKIXSubtrees:
    def _subtree(name: x509.Name):
        return NameSubtree.from_name(
            name_type=GeneralNameType.DIRECTORY_NAME, name=name
        )

    return {GeneralNameType.DIRECTORY_NAME: {_subtree(n) for n in names}}


def _group_subtrees(trees: Iterable[NameSubtree]) -> PKIXSubtrees:
    # This should NOT be a defaultdict, because the semantics of a tree
    # type not being present vs. the set being empty are very different!
    # If necessary, the caller can do a setdefault()
    result: PKIXSubtrees = {}
    for tree in trees:
        try:
            result[tree.name_type].add(tree)
        except KeyError:
            result[tree.name_type] = {tree}
    return result


def process_general_subtrees(subtrees: x509.GeneralSubtrees) -> PKIXSubtrees:
    """
    Convert an ASN.1 ``GeneralSubtrees`` value into a mapping of name types to
    constraint trees.

    This function never raises for malformed input: a subtree that cannot be
    parsed is turned into a tree that rejects every name of its type, so that
    path validation fails safely instead of crashing during path building.
    """
    trees = []
    for subtree in subtrees:
        try:
            trees.append(NameSubtree.from_general_subtree(subtree))
        except NameConstraintError as e:
            try:
                name_type = GeneralNameType.from_choice(subtree['base'].name)
                trees.append(NameSubtree.reject_all(name_type, e))
            except Exception:  # noqa: BLE001
                # We cannot even tell which name form is constrained; be
                # conservative and reject every name form.
                trees.extend(
                    NameSubtree.reject_all(name_type, e)
                    for name_type in GeneralNameType
                )
    return _group_subtrees(trees)


class NameConstraintValidationResult:
    def __init__(
        self,
        failing_name_type: GeneralNameType | None = None,
        failing_name: str | x509.Name | None = None,
        reason: NameConstraintError | None = None,
        structural_error: NameConstraintError | None = None,
    ):
        self.failing_name_type: GeneralNameType | None = failing_name_type
        self.failing_name: str | x509.Name | None = failing_name
        self.reason: NameConstraintError | None = reason
        # Set when the failure is not tied to an individual name (e.g. a
        # constraint that could not be parsed at all).
        self.structural_error: NameConstraintError | None = structural_error

    @classmethod
    def from_error(cls, error: NameConstraintError):
        """
        Build a failing result from a structural error, i.e. one that occurs
        before a particular name can even be identified.
        """
        return cls(structural_error=error)

    def __bool__(self):
        return self.failing_name_type is None and self.structural_error is None

    @property
    def error_message(self):
        if self.structural_error is not None:
            return (
                "The name constraints could not be evaluated: "
                f"{self.structural_error}"
            )
        assert self.failing_name_type is not None
        name_str = self.failing_name
        if isinstance(name_str, x509.Name):
            name_str = name_str.human_friendly
        elif isinstance(name_str, (IPv4Address, IPv6Address)):
            name_str = str(name_str)
        elif (
            isinstance(name_str, (bytes, bytearray))
            and self.failing_name_type == GeneralNameType.IP_ADDRESS
        ):
            # IP names are carried around as raw octets until they are
            # checked against a constraint; decode them for display.
            try:
                name_str = str(_decode_ip_name(name_str))
            except NameConstraintError:
                name_str = name_str.hex()

        name_type = self.failing_name_type.name.lower()
        msg = f"The name '{name_str}' of type {name_type} is not allowed."
        if self.reason is not None:
            msg = f"{msg} Reason: {self.reason}"
        return msg


def _evaluate_names(cert, predicate) -> NameConstraintValidationResult:
    """
    Run ``predicate`` over all names in ``cert`` and report the first failure.

    Any structural problem (a malformed name, an unsupported constraint type,
    an unparseable extension, ...) is surfaced as a failing result rather than
    as an exception, so that callers always end up rejecting the certificate
    with a validation error.
    """
    try:
        names = _enumerate_names_in_cert(cert)
        for name_type, name in names:
            failing, reason = predicate(name_type, name)
            if failing:
                return NameConstraintValidationResult(
                    failing_name_type=name_type,
                    failing_name=name,
                    reason=reason,
                )
    except NameConstraintError as e:
        return NameConstraintValidationResult.from_error(e)
    except Exception as e:  # noqa: BLE001
        return NameConstraintValidationResult.from_error(
            MalformedNameConstraintError(
                f"Could not process the subject names of the certificate: {e}"
            )
        )
    return NameConstraintValidationResult()


def _contains_in_any(trees, name) -> tuple[bool, NameConstraintError | None]:
    """
    Evaluate a name against a collection of trees.

    Every tree is evaluated (no short-circuiting), so that a malformed or
    unsupported constraint cannot be silently skipped depending on set
    iteration order. If evaluating any tree fails, that failure is reported
    instead of a containment result: the caller must treat it as a rejection.
    """
    contained = False
    for tree in trees:
        try:
            if name in tree:
                contained = True
        except NameConstraintError as e:
            return False, e
    return contained, None


class PermittedSubtrees:
    def __init__(self, initial_permitted_subtrees: PKIXSubtrees):
        # The structure of self._trees is name_type -> list[tree set]
        # where each tree set in the list denotes a generation
        # For each "generation", there must be at least one tree that accepts
        # the name (i.e. later certificates can only restrict existing
        # constraints).
        # note: if the set of applicable trees is empty,
        # we reject the cert.
        # However, initial-permitted-subtrees (by default) includes a
        # universal acceptor for each name type in our implementation,
        # which seems to be what most implementations do.

        # We deep-copy the initial permitted subtrees
        trees: dict[GeneralNameType, list[set[NameSubtree]]] = {
            name_type: [set(initial_permitted_subtrees.get(name_type, ()))]
            for name_type in GeneralNameType
        }
        self._trees = trees

    def intersect_with(self, trees: PKIXSubtrees):
        # only change the values that appear in the new tree set!
        for name_type, new_permitted in trees.items():
            self._trees[name_type].append(new_permitted)

    def _evaluate(self, name_type: GeneralNameType, name):
        if isinstance(name, _InvalidName):
            return True, name.error
        generations = self._trees.get(name_type, ())
        # make sure that the name is contained in the intersection of all
        # whitelist filters we accumulated.
        # Run through the list in reverse order (newest first) to apply the
        # (generally) strictest conditions first.
        for trees_in_generation in reversed(generations):
            contained, error = _contains_in_any(trees_in_generation, name)
            if error is not None:
                return True, error
            if not contained:
                return True, None
        return False, None

    def accept_name(self, name_type: GeneralNameType, name) -> bool:
        failing, _ = self._evaluate(name_type, name)
        return not failing

    def accept_cert(
        self, cert: x509.Certificate
    ) -> NameConstraintValidationResult:
        return _evaluate_names(cert, self._evaluate)


class ExcludedSubtrees:
    def __init__(self, initial_excluded_subtrees: PKIXSubtrees):
        # The situation is not fully symmetric with the whitelist case:
        # here, we don't need to remember individual generations of blacklists,
        # we can just take unions to strictify conditions as we move along the
        # path under scrutiny.
        self._trees: PKIXSubtrees = {
            name_type: set(tree_set)
            for name_type, tree_set in initial_excluded_subtrees.items()
        }

    def union_with(self, trees: PKIXSubtrees):
        # only change the values that appear in the new tree set!
        for name_type, new_excluded in trees.items():
            self._trees[name_type].update(new_excluded)

    def _evaluate(self, name_type: GeneralNameType, name):
        if isinstance(name, _InvalidName):
            return True, name.error
        contained, error = _contains_in_any(
            self._trees.get(name_type, ()), name
        )
        if error is not None:
            return True, error
        return contained, None

    def reject_name(self, name_type: GeneralNameType, name) -> bool:
        failing, _ = self._evaluate(name_type, name)
        return failing

    def accept_cert(
        self, cert: x509.Certificate
    ) -> NameConstraintValidationResult:
        return _evaluate_names(cert, self._evaluate)


def default_permitted_subtrees() -> PKIXSubtrees:
    return {
        name_type: {NameSubtree.universal_tree(name_type)}
        for name_type in GeneralNameType
    }


def default_excluded_subtrees() -> PKIXSubtrees:
    return {name_type: set() for name_type in GeneralNameType}
