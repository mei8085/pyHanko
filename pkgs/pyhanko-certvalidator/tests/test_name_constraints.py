"""
Tests for name constraint processing in path validation, with a focus on
the handling of ``iPAddress`` constraints and on safely rejecting
constraints/name forms that cannot be processed.
"""

import datetime
import ipaddress

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from pyhanko_certvalidator import validate as validate_mod
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.errors import PathValidationError
from pyhanko_certvalidator.name_trees import (
    GeneralNameType,
    MalformedNameConstraintError,
    NameConstraintError,
    PermittedSubtrees,
    process_general_subtrees,
)

NOW = datetime.datetime(2024, 1, 1)
MOMENT = datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)


def _ip(addr: str, prefix: int) -> x509.IPAddress:
    return x509.IPAddress(ipaddress.ip_network(f'{addr}/{prefix}'))


def _make_cert(
    subject_cn,
    issuer_name,
    issuer_key,
    subject_key,
    *,
    serial,
    ca,
    permitted=None,
    excluded=None,
    sans=None,
):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=False
        )
    )
    if permitted is not None or excluded is not None:
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=permitted, excluded_subtrees=excluded
            ),
            critical=False,
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _load(cert) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(
        cert.public_bytes(serialization.Encoding.DER)
    )


def _build_chain(root_permitted=None, root_excluded=None,
                 interm_chain=(), ee_sans=None):
    """
    Build a chain. ``interm_chain`` is a list of (permitted, excluded)
    constraint tuples for successive intermediate CAs.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Root')])
    root = _make_cert(
        'Root',
        root_name,
        root_key,
        root_key,
        serial=1,
        ca=True,
        permitted=root_permitted,
        excluded=root_excluded,
    )
    issuer_name = root_name
    issuer_key = root_key
    int_certs = []
    for idx, (permitted, excluded) in enumerate(interm_chain):
        interm_key = ec.generate_private_key(ec.SECP256R1())
        interm = _make_cert(
            f'Interm{idx}',
            issuer_name,
            issuer_key,
            interm_key,
            serial=10 + idx,
            ca=True,
            permitted=permitted,
            excluded=excluded,
        )
        int_certs.append(interm)
        issuer_name = interm.subject
        issuer_key = interm_key
    ee_key = ec.generate_private_key(ec.SECP256R1())
    ee = _make_cert(
        'EE',
        issuer_name,
        issuer_key,
        ee_key,
        serial=99,
        ca=False,
        sans=ee_sans,
    )
    return root, int_certs, ee


async def _validate(root, int_certs, ee):
    context = ValidationContext(
        trust_roots=[_load(root)],
        other_certs=[_load(c) for c in int_certs],
        revocation_mode='soft-fail',
        moment=MOMENT,
    )
    (path,) = await context.path_builder.async_build_paths(_load(ee))
    await validate_mod.async_validate_path(context, path)


async def _expect_valid(root, int_certs, ee):
    await _validate(root, int_certs, ee)


async def _expect_rejected(root, int_certs, ee, *, match):
    with pytest.raises(PathValidationError, match=match):
        await _validate(root, int_certs, ee)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'constraint,ee_addr,valid',
    [
        ('192.0.2.0/24', '192.0.2.1', True),
        ('192.0.2.0/24', '192.0.2.255', True),
        ('192.0.2.0/24', '192.0.3.1', False),
        ('192.0.2.1/32', '192.0.2.1', True),
        ('192.0.2.1/32', '192.0.2.2', False),
    ],
)
async def test_permitted_ip_constraint(constraint, ee_addr, valid):
    root, ints, ee = _build_chain(
        interm_chain=[
            ([x509.IPAddress(ipaddress.ip_network(constraint))], None)
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address(ee_addr))],
    )
    if valid:
        await _expect_valid(root, ints, ee)
    else:
        await _expect_rejected(
            root, ints, ee, match='not all names.*permitted'
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'ee_addr,valid',
    [
        ('192.0.2.1', False),
        ('192.0.2.255', False),
        ('192.0.3.1', True),
    ],
)
async def test_excluded_ip_constraint(ee_addr, valid):
    root, ints, ee = _build_chain(
        interm_chain=[(None, [_ip('192.0.2.0', 24)])],
        ee_sans=[x509.IPAddress(ipaddress.ip_address(ee_addr))],
    )
    if valid:
        await _expect_valid(root, ints, ee)
    else:
        await _expect_rejected(root, ints, ee, match='some names.*excluded')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'constraint,ee_addr,valid',
    [
        ('2001:db8::/32', '2001:db8::1', True),
        ('2001:db8::/32', '2001:db8:ffff::1', True),
        ('2001:db8::/32', '2001:db9::1', False),
        ('2001:db8::/128', '2001:db8::', True),
        ('2001:db8::/128', '2001:db8::1', False),
    ],
)
async def test_permitted_ipv6_constraint(constraint, ee_addr, valid):
    root, ints, ee = _build_chain(
        interm_chain=[
            ([x509.IPAddress(ipaddress.ip_network(constraint))], None)
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address(ee_addr))],
    )
    if valid:
        await _expect_valid(root, ints, ee)
    else:
        await _expect_rejected(
            root, ints, ee, match='not all names.*permitted'
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'constraint,v4_name,v6_name',
    [
        ('192.0.2.0/24', '192.0.2.1', '2001:db8::1'),
        ('2001:db8::/32', '192.0.2.1', '2001:db8::1'),
    ],
)
async def test_ip_constraints_are_address_family_specific(
    constraint, v4_name, v6_name
):
    # The name of the same family as the constraint is in range ...
    root, ints, ee = _build_chain(
        interm_chain=[
            ([x509.IPAddress(ipaddress.ip_network(constraint))], None)
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address(v4_name))],
    )
    if ipaddress.ip_network(constraint).version == 4:
        await _expect_valid(root, ints, ee)
    else:
        await _expect_rejected(
            root, ints, ee, match='not all names.*permitted'
        )
    # ... but an address of the other family is never in range.
    root, ints, ee = _build_chain(
        interm_chain=[
            ([x509.IPAddress(ipaddress.ip_network(constraint))], None)
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address(v6_name))],
    )
    if ipaddress.ip_network(constraint).version == 6:
        await _expect_valid(root, ints, ee)
    else:
        await _expect_rejected(
            root, ints, ee, match='not all names.*permitted'
        )


@pytest.mark.asyncio
async def test_ip_constraint_does_not_affect_other_name_types():
    # A constraint on IP addresses must not restrict DNS names below the
    # same CA.
    root, ints, ee = _build_chain(
        interm_chain=[([_ip('192.0.2.0', 24)], None)],
        ee_sans=[x509.DNSName('example.com')],
    )
    await _expect_valid(root, ints, ee)


@pytest.mark.asyncio
async def test_permitted_constraints_narrow_across_chain():
    # Intermediate permits 192.0.2.0/24; sub-CA narrows to 192.0.2.128/25.
    root, ints, ee = _build_chain(
        interm_chain=[
            ([_ip('192.0.2.0', 24)], None),
            ([_ip('192.0.2.128', 25)], None),
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address('192.0.2.200'))],
    )
    await _expect_valid(root, ints, ee)

    # 192.0.2.10 is within the outer /24 but outside the inner /25.
    root, ints, ee = _build_chain(
        interm_chain=[
            ([_ip('192.0.2.0', 24)], None),
            ([_ip('192.0.2.128', 25)], None),
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address('192.0.2.10'))],
    )
    await _expect_rejected(root, ints, ee, match='not all names.*permitted')


@pytest.mark.asyncio
async def test_permitted_constraint_does_not_widen_across_chain():
    # A sub-CA that tries to widen a permitted subtree to a superset must not
    # be able to do so; the outer restriction still applies.
    root, ints, ee = _build_chain(
        interm_chain=[
            ([_ip('192.0.2.128', 25)], None),
            ([_ip('192.0.2.0', 24)], None),
        ],
        ee_sans=[x509.IPAddress(ipaddress.ip_address('192.0.2.10'))],
    )
    await _expect_rejected(root, ints, ee, match='not all names.*permitted')


@pytest.mark.asyncio
async def test_excluded_constraints_accumulate_across_chain():
    # The outer CA excludes one range and the inner CA another; both must
    # remain excluded.
    outer = x509.IPAddress(ipaddress.ip_network('192.0.2.0/24'))
    inner = x509.IPAddress(ipaddress.ip_network('198.51.100.0/24'))
    for addr in ('192.0.2.1', '198.51.100.1'):
        root, ints, ee = _build_chain(
            interm_chain=[(None, [outer]), (None, [inner])],
            ee_sans=[x509.IPAddress(ipaddress.ip_address(addr))],
        )
        await _expect_rejected(root, ints, ee, match='some names.*excluded')
    # An address outside both ranges is fine.
    root, ints, ee = _build_chain(
        interm_chain=[(None, [outer]), (None, [inner])],
        ee_sans=[x509.IPAddress(ipaddress.ip_address('203.0.113.1'))],
    )
    await _expect_valid(root, ints, ee)


@pytest.mark.asyncio
async def test_interspersed_non_ip_constraint_keeps_ip_restriction():
    # A sub-CA that constrains DNS names should not reset the inherited IP
    # restriction imposed by an ancestor.
    root, ints, ee = _build_chain(
        interm_chain=[
            ([_ip('192.0.2.0', 24)], None),
            ([x509.DNSName('example.com')], None),
        ],
        ee_sans=[
            x509.IPAddress(ipaddress.ip_address('198.51.100.1')),
            x509.DNSName('www.example.com'),
        ],
    )
    await _expect_rejected(root, ints, ee, match='not all names.*permitted')


@pytest.mark.asyncio
async def test_unsupported_name_form_constraint_is_rejected():
    # Constraint on registeredID, matching registeredID SAN. RFC 5280 does
    # not define containment semantics for this name form, so the
    # certificate must be rejected rather than accepted or crashing.
    rid = x509.RegisteredID(ObjectIdentifier('1.2.3.4'))
    root, ints, ee = _build_chain(
        interm_chain=[([rid], None)], ee_sans=[rid]
    )
    await _expect_rejected(root, ints, ee, match='not allowed')


@pytest.mark.asyncio
async def test_unsupported_name_form_constraint_without_matching_name():
    # No registeredID name occurs in the certificate, so the constraint on
    # that name form is never applied.
    rid = x509.RegisteredID(ObjectIdentifier('1.2.3.4'))
    root, ints, ee = _build_chain(
        interm_chain=[([rid], None)], ee_sans=[x509.DNSName('example.com')]
    )
    await _expect_valid(root, ints, ee)


@pytest.mark.asyncio
async def test_excluded_unsupported_name_form_is_rejected():
    rid = x509.RegisteredID(ObjectIdentifier('1.2.3.4'))
    root, ints, ee = _build_chain(
        interm_chain=[(None, [rid])], ee_sans=[rid]
    )
    await _expect_rejected(root, ints, ee, match='not allowed')


def _malformed_ip_subtree(raw: bytes):
    ip = asn1_x509.IPAddress()
    ip.contents = raw
    gname = asn1_x509.GeneralName(name='ip_address', value=ip)
    return asn1_x509.GeneralSubtree({'base': gname})


@pytest.mark.parametrize(
    'raw',
    [
        # too short for a constraint
        bytes([192, 0, 2, 0]),
        # non-contiguous netmask
        bytes([192, 0, 2, 0, 255, 0, 255, 0]),
        # host bits set in the constraint address
        bytes([192, 0, 2, 99, 255, 255, 255, 0]),
    ],
)
def test_malformed_ip_constraint_becomes_rejecting_tree(raw):
    subtree = _malformed_ip_subtree(raw)
    trees = process_general_subtrees([subtree])
    (tree,) = trees[GeneralNameType.IP_ADDRESS]
    with pytest.raises(MalformedNameConstraintError):
        ipaddress.ip_address('192.0.2.1') in tree


def test_minimum_on_constraint_is_safely_rejected():
    gname = asn1_x509.GeneralName(name='ip_address', value='192.0.2.0/24')
    subtree = asn1_x509.GeneralSubtree({'base': gname, 'minimum': 1})
    trees = process_general_subtrees([subtree])
    (tree,) = trees[GeneralNameType.IP_ADDRESS]
    # Evaluating the constraint must fail rather than silently accepting or
    # ignoring the unsupported minimum.
    with pytest.raises(Exception) as excinfo:
        ipaddress.ip_address('192.0.2.1') in tree
    assert isinstance(excinfo.value, NameConstraintError)


def test_permitted_subtrees_reports_malformed_constraint_as_failure():
    gname = asn1_x509.GeneralName(
        name='ip_address', value=_malformed_ip_subtree(
            bytes([192, 0, 2, 0, 255, 0, 255, 0])
        )['base'].chosen
    )
    subtree = asn1_x509.GeneralSubtree({'base': gname})
    trees = process_general_subtrees([subtree])
    permitted = PermittedSubtrees(trees)
    # A malformed constraint in a permitted set must not be silently ignored:
    # any IP address name causes a rejection.
    assert not permitted.accept_name(
        GeneralNameType.IP_ADDRESS, ipaddress.ip_address('192.0.2.1')
    )
