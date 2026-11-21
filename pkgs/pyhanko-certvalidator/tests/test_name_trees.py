import pytest
from pyhanko_certvalidator.name_trees import (
    MalformedNameConstraintError,
    NameConstraintError,
    dns_tree_contains,
    email_tree_contains,
    host_tree_contains,
    ip_tree_contains,
    uri_tree_contains,
)


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('example.com', 'example.com', True),
        ('example.com', 'www.example.com', True),
        ('example.com', 'notexample.com', False),
        ('example.com', 'example.org', False),
        ('www.example.com', 'example.com', False),
        # case folding (RFC 4343)
        ('example.com', 'EXAMPLE.COM', True),
        ('EXAMPLE.COM', 'example.com', True),
        ('example.com', 'WWW.Example.CoM', True),
        ('ExAmPlE.com', 'sub.example.COM', True),
        ('example.com', 'EXAMPLE.ORG', False),
        # trailing (root) dot is not significant
        ('example.com', 'example.com.', True),
        ('example.com.', 'example.com', True),
        ('example.com.', 'example.com.', True),
        ('example.com', 'WWW.EXAMPLE.COM.', True),
        # only ASCII case is folded; RFC 4343 s 3 gives 0xDD/0xFD as a
        # pair that must not match, though str.lower() would fold it
        ('ýexample.com', 'Ýexample.com', False),
    ],
)
def test_dns_tree_contains(base, other, expected):
    assert dns_tree_contains(base, other) is expected


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('example.com', 'example.com', True),
        ('example.com', 'www.example.com', False),
        ('.example.com', 'www.example.com', True),
        ('.example.com', 'example.com', False),
        ('.example.com', 'a.b.example.com', True),
        # case folding
        ('example.com', 'EXAMPLE.COM', True),
        ('EXAMPLE.com', 'example.COM', True),
        ('.example.com', 'WWW.Example.Com', True),
        ('.EXAMPLE.COM', 'www.example.com', True),
        ('example.com', 'example.org', False),
        # trailing (root) dot is not significant
        ('example.com', 'example.com.', True),
        ('example.com.', 'example.com', True),
        ('.example.com', 'WWW.EXAMPLE.COM.', True),
        ('.example.com.', 'www.example.com', True),
    ],
)
def test_host_tree_contains(base, other, expected):
    assert host_tree_contains(base, other) is expected


def test_host_tree_contains_rejects_empty_base():
    with pytest.raises(NameConstraintError, match='with an empty'):
        host_tree_contains('', 'example.com')


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('user@example.com', 'user@example.com', True),
        ('user@example.com', 'other@example.com', False),
        ('user@example.com', 'example.com', False),
        ('example.com', 'user@example.com', True),
        ('.example.com', 'user@www.example.com', True),
        ('.example.com', 'user@example.com', False),
        # the host part folds case, the local part does not
        ('user@example.com', 'user@EXAMPLE.COM', True),
        ('user@EXAMPLE.COM', 'user@example.com', True),
        ('user@example.com', 'USER@example.com', False),
        ('example.com', 'user@EXAMPLE.COM', True),
        ('EXAMPLE.COM', 'user@example.com', True),
        ('.example.com', 'user@WWW.EXAMPLE.COM', True),
        # trailing (root) dot is not significant
        ('user@example.com', 'user@example.com.', True),
        ('user@example.com.', 'user@example.com', True),
        ('example.com', 'user@example.com.', True),
    ],
)
def test_email_tree_contains(base, other, expected):
    assert email_tree_contains(base, other) is expected


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('example.com', 'http://example.com/foo', True),
        ('example.com', 'http://www.example.com/foo', False),
        ('.example.com', 'http://www.example.com/foo', True),
        # case folding and trailing dot, inherited from host_tree_contains
        ('example.com', 'http://EXAMPLE.COM/foo', True),
        ('.example.com', 'https://WWW.Example.Com:8443/foo', True),
        ('example.com', 'http://example.com./foo', True),
        ('example.com', 'http://example.org/foo', False),
    ],
)
def test_uri_tree_contains(base, other, expected):
    assert uri_tree_contains(base, other) is expected


@pytest.mark.parametrize('uri', ['http://192.0.2.1/foo', 'not a uri'])
def test_uri_tree_contains_requires_fqdn(uri):
    with pytest.raises(NameConstraintError, match='require URIs'):
        uri_tree_contains('example.com', uri)


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('192.0.2.0/24', '192.0.2.1', True),
        ('192.0.2.0/24', '192.0.2.255', True),
        ('192.0.2.0/24', '192.0.3.1', False),
        ('192.0.2.0/24', '198.51.100.1', False),
        # a single-host range
        ('192.0.2.1/32', '192.0.2.1', True),
        ('192.0.2.1/32', '192.0.2.2', False),
        # a bare address is a single host
        ('192.0.2.1', '192.0.2.1', True),
        ('192.0.2.1', '192.0.2.2', False),
        # 'all addresses' ranges
        ('0.0.0.0/0', '10.1.2.3', True),
        ('::/0', '2001:db8::1', True),
        # IPv6
        ('2001:db8::/32', '2001:db8::1', True),
        ('2001:db8::/32', '2001:db8:ffff::1', True),
        ('2001:db8::/32', '2001:db9::1', False),
        ('2001:db8::/128', '2001:db8::', True),
        ('2001:db8::/128', '2001:db8::1', False),
        # address families are disjoint
        ('192.0.2.0/24', '2001:db8::1', False),
        ('2001:db8::/32', '192.0.2.1', False),
    ],
)
def test_ip_tree_contains_strings(base, other, expected):
    assert ip_tree_contains(base, other) is expected


@pytest.mark.parametrize(
    'base,other,expected',
    [
        # IPv4 /24: 192.0.2.0/24
        (bytes([192, 0, 2, 0, 255, 255, 255, 0]), bytes([192, 0, 2, 1]), True),
        (bytes([192, 0, 2, 0, 255, 255, 255, 0]), bytes([192, 0, 3, 1]), False),
        # IPv4 /0
        (bytes(8), bytes([10, 0, 0, 1]), True),
        # IPv6 /32: 2001:db8::/32
        (
            bytes([0x20, 0x01, 0x0D, 0xB8]) + bytes(12) + bytes([0xFF] * 4)
            + bytes(12),
            bytes([0x20, 0x01, 0x0D, 0xB8]) + bytes(12),
            True,
        ),
        # IPv6 /128
        (bytes(16) + bytes([0xFF] * 16), bytes(16), True),
        (bytes(16) + bytes([0xFF] * 16), bytes(15) + b'\x01', False),
    ],
)
def test_ip_tree_contains_raw_octets(base, other, expected):
    assert ip_tree_contains(base, other) is expected


@pytest.mark.parametrize(
    'base,other',
    [
        # constraints must be 8 (IPv4) or 32 (IPv6) octets long
        (bytes([192, 0, 2, 0]), bytes([192, 0, 2, 1])),
        (bytes(9), bytes([192, 0, 2, 1])),
        # names must be 4 (IPv4) or 16 (IPv6) octets long
        ('192.0.2.0/24', bytes([192, 0, 2])),
        ('192.0.2.0/24', bytes(8)),
        # non-CIDR (non-contiguous) netmask
        (bytes([192, 0, 2, 0, 255, 0, 255, 0]), bytes([192, 0, 2, 1])),
        # address with host bits set in the constraint
        (bytes([192, 0, 2, 99, 255, 255, 255, 0]), bytes([192, 0, 2, 1])),
        # malformed string representations
        ('192.0.2.99/24', '192.0.2.1'),
        ('not-an-ip', '192.0.2.1'),
        ('192.0.2.0/24', 'not-an-ip'),
        ('192.0.2.0/33', '192.0.2.1'),
    ],
)
def test_ip_tree_contains_rejects_malformed_input(base, other):
    with pytest.raises(MalformedNameConstraintError):
        ip_tree_contains(base, other)


def test_ip_tree_contains_rejects_range_as_name():
    import ipaddress

    network = ipaddress.ip_network('192.0.2.77/24', strict=False)
    with pytest.raises(MalformedNameConstraintError):
        ip_tree_contains('192.0.2.0/24', network)