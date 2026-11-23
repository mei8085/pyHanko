"""
Tests for the selection of delta CRLs to combine with complete CRLs.

The public entry points under test are
:func:`~pyhanko_certvalidator.revinfo.validate_crl.find_applicable_delta_crls`
and
:func:`~pyhanko_certvalidator.revinfo.validate_crl.select_applicable_delta_crl`,
together with the observable behaviour of end-to-end path validation.
"""

import asyncio
import datetime
import hashlib
import os
from datetime import UTC

import pytest
from asn1crypto import core, crl, x509
from freezegun import freeze_time
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.errors import (
    InsufficientRevinfoError,
    RevokedError,
)
from pyhanko_certvalidator.registry import CertificateRegistry
from pyhanko_certvalidator.revinfo._err_gather import Errors
from pyhanko_certvalidator.revinfo.archival import CRLContainer
from pyhanko_certvalidator.revinfo.manager import RevinfoManager
from pyhanko_certvalidator.revinfo.validate_crl import (
    _CRLErrs,
    _maybe_get_delta_crl,
    find_applicable_delta_crls,
    select_applicable_delta_crl,
)
from pyhanko_certvalidator.validate import (
    async_validate_path,
    validate_path,
)

from .common import FIXTURES_DIR as TESTS_FIXTURES
from .common import load_cert_object, load_nist_cert, load_nist_crl

CA1 = load_nist_cert('deltaCRLCA1Cert.crt')
ROOT = load_nist_cert('TrustAnchorRootCertificate.crt')


def _ext(number, base_number=None, *, idp=None, aki=None, critical=True):
    exts = [
        crl.TBSCertListExtension(
            {
                'extn_id': 'authority_key_identifier',
                'critical': False,
                'extn_value': x509.AuthorityKeyIdentifier(
                    {
                        'key_identifier': aki
                        if aki is not None
                        else CA1.key_identifier
                    }
                ),
            }
        ),
        crl.TBSCertListExtension(
            {
                'extn_id': 'crl_number',
                'critical': False,
                'extn_value': core.Integer(number),
            }
        ),
    ]
    if base_number is not None:
        exts.append(
            crl.TBSCertListExtension(
                {
                    'extn_id': 'delta_crl_indicator',
                    'critical': critical,
                    'extn_value': core.Integer(base_number),
                }
            )
        )
    if idp is not None:
        exts.append(
            crl.TBSCertListExtension(
                {
                    'extn_id': 'issuing_distribution_point',
                    'critical': True,
                    'extn_value': idp,
                }
            )
        )
    return exts


def make_crl(
    number,
    *,
    base_number=None,
    idp=None,
    aki=None,
    issuer=None,
    this_update='2011-01-01',
    next_update='2030-12-31',
    critical=True,
    extra_exts=(),
) -> crl.CertificateList:
    """
    Build a minimal, syntactically valid CRL with the given numbering info.

    The signature is a dummy; the tests that exercise signature checking use
    the real NIST fixtures instead.
    """

    exts = _ext(
        number, base_number, idp=idp, aki=aki, critical=critical
    ) + list(extra_exts)
    tbs = crl.TbsCertList(
        {
            'version': 'v2',
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': issuer if issuer is not None else CA1.subject,
            'this_update': {
                'utc_time': datetime.datetime.fromisoformat(
                    this_update
                ).replace(tzinfo=UTC)
            },
            'next_update': {
                'utc_time': datetime.datetime.fromisoformat(
                    next_update
                ).replace(tzinfo=UTC)
            },
            'revoked_certificates': [],
            'crl_extensions': exts,
        }
    )
    return crl.CertificateList(
        {
            'tbs_cert_list': tbs,
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature': b'\x00' * 16,
        }
    )


def _cont(number, **kwargs) -> CRLContainer:
    return CRLContainer(make_crl(number, **kwargs))


def _numbers(containers) -> list[int]:
    return [c.crl_data.crl_number_value.native for c in containers]


REASONS_IDP = crl.IssuingDistributionPoint(
    {'only_some_reasons': x509.ReasonFlags({'key_compromise'})}
)


# ---------------------------------------------------------------------------
# RFC 5280 §5.2.4 combination conditions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'complete_number,base_number,delta_number,expected',
    [
        # complete CRL starts at the base delta's reference point
        (1, 1, 5, True),
        # complete CRL is newer than the base, but still older than the delta
        (3, 1, 5, True),
        # delta references itself: not allowed (condition (d))
        (5, 5, 5, False),
        # complete CRL is newer than the delta: ordering violated
        (6, 1, 5, False),
        # complete CRL predates what the delta builds on
        (0, 1, 5, False),
        # delta number is not greater than its own base number
        (1, 5, 3, False),
    ],
)
def test_combination_numbering(
    complete_number, base_number, delta_number, expected
):
    complete = _cont(complete_number)
    delta = _cont(delta_number, base_number=base_number)
    assert (
        select_applicable_delta_crl(complete, [delta]) is not None
    ) is expected


def test_combination_requires_same_issuer():
    complete = _cont(1)
    other_ca = load_nist_cert('deltaCRLCA2Cert.crt')
    delta = _cont(
        5, base_number=1, issuer=other_ca.subject, aki=other_ca.key_identifier
    )
    assert select_applicable_delta_crl(complete, [delta]) is None


def test_combination_requires_matching_idp():
    plain_complete = _cont(1)
    uses_reasons = _cont(5, base_number=1, idp=REASONS_IDP)
    assert select_applicable_delta_crl(plain_complete, [uses_reasons]) is None
    # ... and the other way around
    scoped_complete = _cont(1, idp=REASONS_IDP)
    plain_delta = _cont(5, base_number=1)
    assert select_applicable_delta_crl(scoped_complete, [plain_delta]) is None
    # identical IDPs are fine
    matching_delta = _cont(5, base_number=1, idp=REASONS_IDP)
    assert select_applicable_delta_crl(scoped_complete, [matching_delta])


def test_combination_requires_matching_aki():
    complete = _cont(1)
    delta = _cont(5, base_number=1, aki=b'\x01' * 20)
    assert select_applicable_delta_crl(complete, [delta]) is None


def test_non_delta_crl_never_combines():
    complete = _cont(1)
    # No delta CRL indicator at all -> not a delta CRL.
    not_a_delta = _cont(5)
    assert select_applicable_delta_crl(complete, [not_a_delta]) is None


@pytest.mark.parametrize('drop', ['complete_number', 'delta_number'])
def test_missing_crl_number_rejects_combination(drop):
    complete = _cont(1)
    delta = _cont(5, base_number=1)
    if drop == 'complete_number':
        complete = CRLContainer(
            crl.CertificateList.load(
                _strip_extension(complete.crl_data, 'crl_number').dump()
            )
        )
    else:
        delta = CRLContainer(
            crl.CertificateList.load(
                _strip_extension(delta.crl_data, 'crl_number').dump()
            )
        )
    assert select_applicable_delta_crl(complete, [delta]) is None


def _strip_extension(crl_data: crl.CertificateList, ext_name: str):
    tbs = crl_data['tbs_cert_list']
    tbs['crl_extensions'] = crl.TBSCertListExtensions(
        [
            ext
            for ext in tbs['crl_extensions']
            if ext['extn_id'].native != ext_name
        ]
    )
    return crl.CertificateList.load(crl_data.dump(force=True))


def test_malformed_delta_indicator_is_rejected_not_raised():
    # A delta CRL indicator with a non-integer payload cannot be interpreted;
    # the pairing must be rejected cleanly instead of raising.
    bad_ext = crl.TBSCertListExtension.load(
        # deltaCRLIndicator (2.5.29.27), critical, extnValue = UTF8String
        bytes.fromhex('300f0603551d1b0101ff04050c03616263')
    )
    complete = _cont(1)
    broken_delta = CRLContainer(
        make_crl(5, base_number=None, extra_exts=[bad_ext])
    )
    assert select_applicable_delta_crl(complete, [broken_delta]) is None


# ---------------------------------------------------------------------------
# Selection among multiple applicable delta CRLs
# ---------------------------------------------------------------------------


def test_selection_prefers_most_recent_delta():
    complete = _cont(1)
    older = _cont(4, base_number=1, this_update='2011-01-01')
    newer = _cont(7, base_number=1, this_update='2011-06-01')
    assert select_applicable_delta_crl(complete, [older, newer]) is newer
    # ... independent of input order
    assert select_applicable_delta_crl(complete, [newer, older]) is newer


def test_selection_orders_by_number_not_issuance_date():
    # A higher CRL number denotes more recent information, even if the
    # thisUpdate field suggests otherwise (clock skew, re-issuance, ...).
    complete = _cont(1)
    stale_number = _cont(4, base_number=1, this_update='2012-01-01')
    fresh_number = _cont(9, base_number=1, this_update='2011-01-01')
    assert (
        select_applicable_delta_crl(complete, [stale_number, fresh_number])
        is fresh_number
    )


def test_selection_is_deterministic_for_equal_numbers():
    complete = _cont(1)
    a = _cont(5, base_number=1)
    b = _cont(5, base_number=1, this_update='2011-02-01')
    first = select_applicable_delta_crl(complete, [a, b])
    second = select_applicable_delta_crl(complete, [b, a])
    assert first.crl_data.dump() == second.crl_data.dump()


def test_find_applicable_orders_and_deduplicates():
    complete = _cont(1)
    older = _cont(4, base_number=1)
    newer = _cont(7, base_number=1)
    # Duplicate (same DER) should only be reported once
    duplicate = CRLContainer(newer.crl_data)
    result = find_applicable_delta_crls(
        complete, [older, newer, duplicate, older]
    )
    assert _numbers(result) == [7, 4]


def test_find_applicable_ignores_unrelated_deltas():
    complete = _cont(1)
    applies = _cont(5, base_number=1)
    ahead = _cont(9, base_number=6)  # complete CRL too old for this base
    result = find_applicable_delta_crls(complete, [applies, ahead])
    assert _numbers(result) == [5]


def test_select_handles_empty_candidate_list():
    assert select_applicable_delta_crl(_cont(1), []) is None
    assert find_applicable_delta_crls(_cont(1), []) == []


def test_select_is_safe_with_malformed_candidates_mixed_in():
    complete = _cont(1)
    good = _cont(5, base_number=1)
    bad_ext = crl.TBSCertListExtension.load(
        bytes.fromhex('300f0603551d1b0101ff04050c03616263')
    )
    malformed = CRLContainer(
        make_crl(6, base_number=None, extra_exts=[bad_ext])
    )
    # The malformed candidate must be skipped, not abort the whole search.
    assert select_applicable_delta_crl(complete, [malformed, good]) is good


def test_select_tolerates_unparseable_issuance_date():
    complete = _cont(1)
    good = _cont(5, base_number=1)

    class _NoIssuanceDate(CRLContainer):
        @property
        def issuance_date(self):
            raise ValueError("unparseable time")

    no_dates = _NoIssuanceDate(make_crl(7, base_number=1))
    # The recency key must not raise on unparseable metadata; ordering falls
    # back to the CRL number.
    result = find_applicable_delta_crls(complete, [no_dates, good])
    assert result == [no_dates, good]


def test_find_applicable_does_not_mutate_inputs():
    complete = _cont(1)
    older = _cont(4, base_number=1)
    newer = _cont(7, base_number=1)
    before = [c.crl_data.dump() for c in (complete, older, newer)]
    find_applicable_delta_crls(complete, [older, newer])
    after = [c.crl_data.dump() for c in (complete, older, newer)]
    assert before == after


# ---------------------------------------------------------------------------
# End-to-end behaviour through path validation
# ---------------------------------------------------------------------------


def _nist_context(crls, *, allow_fetching=False):
    return ValidationContext(
        trust_roots=[ROOT],
        other_certs=[
            load_nist_cert('deltaCRLCA1Cert.crt'),
            load_nist_cert('deltaCRLCA2Cert.crt'),
        ],
        crls=crls,
        allow_fetching=allow_fetching,
        revocation_mode='require',
        weak_hash_algos={'md2', 'md5'},
    )


def _validate(cert_name, crls, *, allow_fetching=False):
    cert = load_nist_cert(cert_name)
    context = _nist_context(crls, allow_fetching=allow_fetching)
    (path,) = context.path_builder.build_paths(cert)
    validate_path(context, path)


@freeze_time('2022-05-01')
def test_delta_revocation_detected_when_delta_present():
    # The certificate is only listed on the delta CRL.
    with pytest.raises(RevokedError, match='2010-06-01.*compromised key'):
        _validate(
            'InvaliddeltaCRLTest4EE.crt',
            [
                load_nist_crl('deltaCRLCA1CRL.crl'),
                load_nist_crl('deltaCRLCA1deltaCRL.crl'),
                load_nist_crl('TrustAnchorRootCRL.crl'),
            ],
        )


@freeze_time('2022-05-01')
def test_delta_not_combined_when_numbering_rules_it_out():
    # Sanity check on the NIST fixtures themselves: the delta CRL for CA1 has
    # number 5 with BaseCRLNumber 1, so it combines with CA1's CRL number 1.
    base = CRLContainer(load_nist_crl('deltaCRLCA1CRL.crl'))
    delta = CRLContainer(load_nist_crl('deltaCRLCA1deltaCRL.crl'))
    assert select_applicable_delta_crl(base, [delta]) is delta

    # If we tell the delta CRL that it builds on a newer base than what we
    # have, the combination becomes invalid, and the certificate should no
    # longer be reported revoked on the basis of the delta alone.
    doctored = CRLContainer(
        make_crl(
            5,
            base_number=3,
            issuer=CA1.subject,
            aki=CA1.key_identifier,
            this_update='2011-01-01',
            next_update='2030-12-31',
        )
    )
    assert select_applicable_delta_crl(base, [doctored]) is None


@freeze_time('2022-05-01')
def test_required_delta_missing_fails_closed():
    with pytest.raises(InsufficientRevinfoError, match='Delta CRL'):
        _validate(
            'InvaliddeltaCRLTest4EE.crt',
            [
                load_nist_crl('deltaCRLCA1CRL.crl'),
                load_nist_crl('TrustAnchorRootCRL.crl'),
            ],
        )


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_repeated_operations_are_independent():
    # A failing validation attempt must not poison a subsequent, independent
    # one that has the delta CRL available.
    cert = load_nist_cert('InvaliddeltaCRLTest4EE.crt')
    base_crl = load_nist_crl('deltaCRLCA1CRL.crl')
    delta_crl = load_nist_crl('deltaCRLCA1deltaCRL.crl')
    root_crl = load_nist_crl('TrustAnchorRootCRL.crl')

    (path,) = await _nist_context(
        [base_crl, root_crl]
    ).path_builder.async_build_paths(cert)
    with pytest.raises(InsufficientRevinfoError):
        await async_validate_path(_nist_context([base_crl, root_crl]), path)

    # The same path object, validated in a fresh context with the delta CRL,
    # must now produce the revocation verdict from the delta CRL.
    with pytest.raises(RevokedError, match='2010-06-01.*compromised key'):
        await async_validate_path(
            _nist_context([base_crl, delta_crl, root_crl]), path
        )


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_concurrent_validations_do_not_interfere():
    cert_with_delta = load_nist_cert('InvaliddeltaCRLTest4EE.crt')
    cert_valid = load_nist_cert('ValiddeltaCRLTest2EE.crt')
    base_crl = load_nist_crl('deltaCRLCA1CRL.crl')
    delta_crl = load_nist_crl('deltaCRLCA1deltaCRL.crl')
    root_crl = load_nist_crl('TrustAnchorRootCRL.crl')

    async def _run(cert, crls):
        ctx = _nist_context(crls)
        (path,) = await ctx.path_builder.async_build_paths(cert)
        try:
            await async_validate_path(ctx, path)
            return 'valid'
        except RevokedError:
            return 'revoked'
        except InsufficientRevinfoError:
            return 'insufficient'

    results = await asyncio.gather(
        _run(cert_with_delta, [base_crl, delta_crl, root_crl]),
        _run(cert_valid, [base_crl, delta_crl, root_crl]),
        _run(cert_with_delta, [base_crl, root_crl]),
        _run(cert_with_delta, [base_crl, delta_crl, root_crl]),
    )
    assert results == ['revoked', 'valid', 'insufficient', 'revoked']


# ---------------------------------------------------------------------------
# End-to-end behaviour with properly signed CRLs
# ---------------------------------------------------------------------------

FRESHNESS_DIR = ('freshness', 'certs')
SIGNED_ROOT = load_cert_object(*FRESHNESS_DIR, 'root.crt')
SIGNED_INTERM = load_cert_object(*FRESHNESS_DIR, 'interm.crt')
FRESHNESS_KEYS = ('freshness', 'keys')


def _root_private_key():
    from cryptography.hazmat.primitives import serialization

    with open(
        os.path.join(TESTS_FIXTURES, *FRESHNESS_KEYS, 'root.key.pem'), 'rb'
    ) as inf:
        return serialization.load_pem_private_key(inf.read(), None)


def _signed_crl(
    number,
    *,
    base_number=None,
    entries=(),
    announce_delta=False,
    this_update=(2020, 12, 1),
    next_update=(2021, 12, 1),
):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    exts = [
        crl.TBSCertListExtension(
            {
                'extn_id': 'authority_key_identifier',
                'critical': False,
                'extn_value': x509.AuthorityKeyIdentifier(
                    {'key_identifier': SIGNED_ROOT.key_identifier}
                ),
            }
        ),
        crl.TBSCertListExtension(
            {
                'extn_id': 'crl_number',
                'critical': False,
                'extn_value': core.Integer(number),
            }
        ),
    ]
    if base_number is not None:
        exts.append(
            crl.TBSCertListExtension(
                {
                    'extn_id': 'delta_crl_indicator',
                    'critical': True,
                    'extn_value': core.Integer(base_number),
                }
            )
        )
    if announce_delta:
        exts.append(_freshest_ext())
    tbs = crl.TbsCertList(
        {
            'version': 'v2',
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': SIGNED_ROOT.subject,
            'this_update': {
                'utc_time': datetime.datetime(*this_update, tzinfo=UTC)
            },
            'next_update': {
                'utc_time': datetime.datetime(*next_update, tzinfo=UTC)
            },
            'revoked_certificates': list(entries),
            'crl_extensions': exts,
        }
    )
    signature = _root_private_key().sign(
        tbs.dump(), padding.PKCS1v15(), hashes.SHA256()
    )
    return crl.CertificateList(
        {
            'tbs_cert_list': tbs,
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature': signature,
        }
    )


def _revocation_entry(serial, reason='key_compromise'):
    return crl.RevokedCertificate(
        {
            'user_certificate': core.Integer(serial),
            'revocation_date': {
                'utc_time': datetime.datetime(2020, 11, 1, tzinfo=UTC)
            },
            'crl_entry_extensions': [
                crl.CRLEntryExtension(
                    {
                        'extn_id': 'crl_reason',
                        'critical': False,
                        'extn_value': crl.CRLReason(reason),
                    }
                )
            ],
        }
    )


def _signed_context(crls):
    return ValidationContext(
        trust_roots=[SIGNED_ROOT],
        other_certs=[SIGNED_INTERM],
        crls=crls,
        revocation_mode='require',
    )


def _run_signed(cert, crls):
    context = _signed_context(crls)
    (path,) = context.path_builder.build_paths(cert)
    validate_path(context, path)


@freeze_time('2020-12-15')
def test_signed_delta_applies_revocation():
    base = _signed_crl(10, announce_delta=True)
    delta = _signed_crl(12, base_number=10, entries=[_revocation_entry(4097)])
    with pytest.raises(RevokedError, match='compromised key'):
        _run_signed(SIGNED_INTERM, [base, delta])


@freeze_time('2020-12-15')
def test_signed_delta_with_wrong_base_number_is_ignored():
    # The only available "delta" builds on a base CRL that we do not have
    # (11 > 10), so it must not be combined with the complete CRL. Since the
    # complete CRL announces a delta, this fails closed.
    base = _signed_crl(10, announce_delta=True)
    unrelated_delta = _signed_crl(
        12, base_number=11, entries=[_revocation_entry(4097)]
    )
    with pytest.raises(InsufficientRevinfoError):
        _run_signed(SIGNED_INTERM, [base, unrelated_delta])


@freeze_time('2020-12-15')
def test_signed_delta_with_equal_number_is_ignored():
    # Condition (d): the delta's CRL number must be strictly greater than the
    # complete CRL's number.
    base = _signed_crl(10, announce_delta=True)
    same_number = _signed_crl(
        10, base_number=10, entries=[_revocation_entry(4097)]
    )
    with pytest.raises(InsufficientRevinfoError):
        _run_signed(SIGNED_INTERM, [base, same_number])


@freeze_time('2020-12-15')
def test_signed_delta_newer_than_base_still_combines():
    # Condition (c): the complete CRL may be newer than the referenced base,
    # as long as it is still older than the delta.
    base = _signed_crl(11, announce_delta=True)
    delta = _signed_crl(12, base_number=10, entries=[_revocation_entry(4097)])
    with pytest.raises(RevokedError, match='compromised key'):
        _run_signed(SIGNED_INTERM, [base, delta])


@freeze_time('2020-12-15')
def test_signed_most_recent_applicable_delta_wins():
    # Two applicable deltas revoke the cert with different reasons; the one
    # with the highest CRL number must be used.
    base = _signed_crl(10, announce_delta=True)
    older = _signed_crl(
        11, base_number=10, entries=[_revocation_entry(4097, 'superseded')]
    )
    newer = _signed_crl(
        13, base_number=10, entries=[_revocation_entry(4097, 'key_compromise')]
    )
    with pytest.raises(RevokedError, match='compromised key'):
        _run_signed(SIGNED_INTERM, [base, older, newer])
    # ... regardless of the order in which they are supplied
    with pytest.raises(RevokedError, match='compromised key'):
        _run_signed(SIGNED_INTERM, [base, newer, older])


@freeze_time('2020-12-15')
def test_signed_remove_from_crl_on_delta_unrevokes():
    base = _signed_crl(
        10,
        announce_delta=True,
        entries=[_revocation_entry(4097, 'certificate_hold')],
    )
    delta = _signed_crl(
        12, base_number=10, entries=[_revocation_entry(4097, 'remove_from_crl')]
    )
    # No exception: the delta takes the certificate off hold.
    _run_signed(SIGNED_INTERM, [base, delta])


@freeze_time('2020-12-15')
@pytest.mark.asyncio
async def test_signed_failure_does_not_poison_later_attempt():
    base = _signed_crl(10, announce_delta=True)
    delta = _signed_crl(12, base_number=10, entries=[_revocation_entry(4097)])

    cert = SIGNED_INTERM
    ctx_without_delta = _signed_context([base])
    (path,) = await ctx_without_delta.path_builder.async_build_paths(cert)
    with pytest.raises(InsufficientRevinfoError):
        await async_validate_path(ctx_without_delta, path)

    ctx_with_delta = _signed_context([base, delta])
    with pytest.raises(RevokedError, match='compromised key'):
        await async_validate_path(ctx_with_delta, path)


# ---------------------------------------------------------------------------
# Internal helper behaviour: error isolation
# ---------------------------------------------------------------------------


def _revinfo_manager(crls):
    registry = CertificateRegistry()
    return RevinfoManager(
        certificate_registry=registry,
        poe_manager=__import__(
            'pyhanko_certvalidator.ltv.poe', fromlist=['POEManager']
        ).POEManager(),
        crls=crls,
        ocsps=(),
    )


def _delta_map(*crls):
    result = {}
    for cont in crls:
        result.setdefault(cont.crl_data.issuer.hashable, []).append(cont)
    return result


def test_maybe_get_delta_crl_returns_none_without_freshest_extension():
    complete = CRLContainer(make_crl(1))
    delta = _cont(5, base_number=1)
    errs = _CRLErrs()
    assert (
        _maybe_get_delta_crl(
            certificate_list=complete.crl_data,
            crl_issuer=CA1,
            delta_lists_by_issuer=_delta_map(delta),
            errs=errs,
            complete_crl_cont=complete,
        )
        is None
    )
    assert not errs.failures


def _freshest_ext(url='http://example.com/delta.crl'):
    dp = x509.DistributionPoint(
        {
            'distribution_point': x509.DistributionPointName(
                name='full_name',
                value=[
                    x509.GeneralName(
                        name='uniform_resource_identifier', value=url
                    )
                ],
            )
        }
    )
    return crl.TBSCertListExtension(
        {
            'extn_id': 'freshest_crl',
            'critical': False,
            'extn_value': x509.CRLDistributionPoints([dp]),
        }
    )


def test_maybe_get_delta_crl_prefers_recent_delta_through_internal_helper():
    complete = CRLContainer(make_crl(1, extra_exts=[_freshest_ext()]))
    older = _cont(4, base_number=1)
    newer = _cont(7, base_number=1)
    errs = _CRLErrs()
    selected = _maybe_get_delta_crl(
        certificate_list=complete.crl_data,
        crl_issuer=CA1,
        delta_lists_by_issuer=_delta_map(older, newer),
        errs=errs,
        complete_crl_cont=complete,
    )
    assert selected is newer
    assert not errs.failures


def test_maybe_get_delta_crl_raises_when_no_candidate_combines():
    complete = CRLContainer(make_crl(1, extra_exts=[_freshest_ext()]))
    unrelated = _cont(9, base_number=6)
    errs = _CRLErrs()
    from pyhanko_certvalidator.errors import CRLValidationIndeterminateError

    with pytest.raises(CRLValidationIndeterminateError):
        _maybe_get_delta_crl(
            certificate_list=complete.crl_data,
            crl_issuer=CA1,
            delta_lists_by_issuer=_delta_map(unrelated),
            errs=errs,
            complete_crl_cont=complete,
        )
    # The failed lookup must not leak errors into the caller's buffer.
    assert not errs.failures


def test_maybe_get_delta_crl_failure_does_not_leak_between_calls():
    complete = CRLContainer(make_crl(1, extra_exts=[_freshest_ext()]))
    errs = _CRLErrs()
    from pyhanko_certvalidator.errors import CRLValidationIndeterminateError

    with pytest.raises(CRLValidationIndeterminateError):
        _maybe_get_delta_crl(
            certificate_list=complete.crl_data,
            crl_issuer=CA1,
            delta_lists_by_issuer={},
            errs=errs,
            complete_crl_cont=complete,
        )
    # A subsequent, independent call with a usable delta CRL succeeds and
    # leaves the caller's error buffer clean.
    good_delta = _cont(5, base_number=1)
    selected = _maybe_get_delta_crl(
        certificate_list=complete.crl_data,
        crl_issuer=CA1,
        delta_lists_by_issuer=_delta_map(good_delta),
        errs=errs,
        complete_crl_cont=complete,
    )
    assert selected is good_delta
    assert not errs.failures


def test_maybe_get_delta_crl_accepted_candidate_leaves_no_errors():
    # A stale, less recent candidate is skipped in favour of a usable one.
    # The stale candidate's freshness notes must not end up in the caller's
    # error buffer, since the operation succeeded.
    from pyhanko_certvalidator.policy_decl import (
        CertRevTrustPolicy,
        FreshnessReqType,
        RevocationCheckingPolicy,
    )

    policy = CertRevTrustPolicy(
        revocation_checking_policy=RevocationCheckingPolicy.from_legacy(
            'require'
        ),
        freshness=datetime.timedelta(days=1),
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    from pyhanko_certvalidator.ltv.types import (
        ValidationTimingInfo,
        ValidationTimingParams,
    )

    timing = ValidationTimingParams(
        timing_info=ValidationTimingInfo(
            validation_time=datetime.datetime(2020, 1, 1, tzinfo=UTC),
            best_signature_time=datetime.datetime(2020, 1, 1, tzinfo=UTC),
            point_in_time_validation=True,
        ),
        time_tolerance=datetime.timedelta(0),
    )
    complete = CRLContainer(
        make_crl(1, extra_exts=[_freshest_ext()], this_update='2019-12-01')
    )
    # Stale (issued long before the validation time), but otherwise valid
    stale = _cont(4, base_number=1, this_update='2010-01-01')
    errs = _CRLErrs()
    selected = _maybe_get_delta_crl(
        certificate_list=complete.crl_data,
        crl_issuer=CA1,
        delta_lists_by_issuer=_delta_map(stale),
        errs=errs,
        complete_crl_cont=complete,
        policy=policy,
        timing_params=timing,
    )
    # The only candidate is unusable due to staleness; the failure is reported.
    assert selected is None
    assert any('not recent enough' in msg for msg, _ in errs.failures)


def test_errors_merge_preserves_freshness_state():
    a = _CRLErrs()
    a.append('stale base', None, is_freshness_failure=True)
    a.update_stale(datetime.datetime(2020, 1, 1, tzinfo=UTC))
    b = _CRLErrs()
    b.append('bad delta', None, is_freshness_failure=False)
    a.merge(b)
    assert [msg for msg, _ in a.failures] == ['stale base', 'bad delta']
    assert not a.freshness_failures_only
    assert a.stale_last_usable_at == datetime.datetime(2020, 1, 1, tzinfo=UTC)


def test_errors_merge_is_stable_for_stale_timestamps():
    a = Errors()
    a.update_stale(datetime.datetime(2021, 1, 1, tzinfo=UTC))
    b = Errors()
    b.update_stale(datetime.datetime(2020, 1, 1, tzinfo=UTC))
    a.merge(b)
    assert a.stale_last_usable_at == datetime.datetime(2021, 1, 1, tzinfo=UTC)
    assert a.freshness_failures_only


# ---------------------------------------------------------------------------
# Attribute certificates: public collection API remains usable
# ---------------------------------------------------------------------------


def test_collection_result_shape_is_unchanged():
    from pyhanko_certvalidator.revinfo.validate_crl import (
        CRLCollectionResult,
        CRLOfInterest,
        ProvisionalCRLTrust,
    )

    complete = _cont(1)
    delta = _cont(5, base_number=1)
    interest = CRLOfInterest(
        crl=complete,
        prov_paths=[
            ProvisionalCRLTrust(path=None, delta=delta)  # type: ignore[arg-type]
        ],
        is_indirect=False,
    )
    result = CRLCollectionResult(crls=[interest], failure_msgs=[])
    assert result.crls[0].prov_paths[0].delta is delta


def test_public_selection_helpers_are_importable():
    import pyhanko_certvalidator.revinfo.validate_crl as mod

    assert callable(mod.find_applicable_delta_crls)
    assert callable(mod.select_applicable_delta_crl)
    # hashing helper used for fixture sanity
    assert hashlib.sha256(CA1.dump()).digest()
