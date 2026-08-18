"""
Unit tests for ML-DSA-44 (DNSSEC algorithm 18) dispatch in reslib.dnssec.
Offline and deterministic; no network. The capability-gated behavior is
exercised in both directions by patching reslib.mldsa.available.
"""

import base64
import unittest
from unittest import mock

import dns.rrset

from reslib import mldsa
from reslib import dnssec
from reslib.dnssec import (load_keys, verify_sig_with_keys,
                           supported_algorithm_present, algorithm_is_verifiable)


def make_dnskey_rrset(algorithm, key_bytes, name="mldsa.huque.com.",
                      flags=257):
    """Build a DNSKEY RRset with the given algorithm and raw key bytes."""
    b64 = base64.b64encode(key_bytes).decode()
    return dns.rrset.from_text(name, 3600, "IN", "DNSKEY",
                               "{} 3 {} {}".format(flags, algorithm, b64))


class FakeDsRdata:
    def __init__(self, algorithm):
        self.algorithm = algorithm


class FakeDs:
    def __init__(self, algorithm):
        self.rdata = FakeDsRdata(algorithm)


class FakeSigRdata:
    def __init__(self, key_tag):
        self.key_tag = key_tag


class FakeSig:
    def __init__(self, key_tag):
        self.rdata = FakeSigRdata(key_tag)


class TestVerifiableAlgorithm(unittest.TestCase):

    def test_classic_algorithms_verifiable(self):
        for alg in (8, 13, 15, 16):
            self.assertTrue(algorithm_is_verifiable(alg))

    def test_alg18_follows_mldsa_availability(self):
        with mock.patch("reslib.mldsa.available", return_value=True):
            self.assertTrue(algorithm_is_verifiable(18))
        with mock.patch("reslib.mldsa.available", return_value=False):
            self.assertFalse(algorithm_is_verifiable(18))

    def test_unknown_algorithm_not_verifiable(self):
        self.assertFalse(algorithm_is_verifiable(99))


class TestSupportedAlgorithmPresent(unittest.TestCase):

    def test_alg18_only_gated_by_availability(self):
        dslist = [FakeDs(18)]
        with mock.patch("reslib.mldsa.available", return_value=True):
            self.assertTrue(supported_algorithm_present(dslist))
        with mock.patch("reslib.mldsa.available", return_value=False):
            self.assertFalse(supported_algorithm_present(dslist))

    def test_dual_signed_true_regardless_of_mldsa(self):
        dslist = [FakeDs(8), FakeDs(18)]
        with mock.patch("reslib.mldsa.available", return_value=False):
            self.assertTrue(supported_algorithm_present(dslist))


class TestDnskeyParsing(unittest.TestCase):

    def test_alg18_loads_without_error(self):
        rrset = make_dnskey_rrset(18, b"\x01" * 1312)
        keys, errors = load_keys(rrset)
        self.assertEqual(errors, [])
        self.assertEqual(len(keys), 1)

    def test_alg18_repr_shows_mldsa_name(self):
        rrset = make_dnskey_rrset(18, b"\x01" * 1312)
        keys, _ = load_keys(rrset)
        self.assertIn("MLDSA44 (18)", repr(keys[0]))

    def test_alg18_supported_when_available(self):
        rrset = make_dnskey_rrset(18, b"\x01" * 1312)
        with mock.patch("reslib.mldsa.available", return_value=True):
            keys, _ = load_keys(rrset)
        self.assertTrue(keys[0].supported)
        self.assertIsNotNone(keys[0].key)

    def test_alg18_unsupported_when_unavailable(self):
        rrset = make_dnskey_rrset(18, b"\x01" * 1312)
        with mock.patch("reslib.mldsa.available", return_value=False):
            keys, _ = load_keys(rrset)
        self.assertFalse(keys[0].supported)
        self.assertIsNone(keys[0].key)

    def test_alg18_malformed_key_when_available_is_load_error(self):
        # When alg 18 IS supported, a malformed (wrong-length) key is a
        # genuine load error -> recorded in errors, excluded from keys. A
        # zone signed only with it then goes BOGUS (check_self_signature
        # raises on no verified key), NOT degraded to insecure.
        rrset = make_dnskey_rrset(18, b"\x01" * 100)
        with mock.patch("reslib.mldsa.available", return_value=True):
            keys, errors = load_keys(rrset)
        self.assertEqual(len(errors), 1)
        self.assertEqual(keys, [])


class TestVerifySkipsUnsupported(unittest.TestCase):

    def test_unsupported_alg18_key_is_skipped(self):
        rrset = make_dnskey_rrset(18, b"\x01" * 1312)
        with mock.patch("reslib.mldsa.available", return_value=False):
            keys, _ = load_keys(rrset)
        sig = FakeSig(keys[0].keytag)
        verified, failed = verify_sig_with_keys(sig, keys)
        self.assertEqual(verified, [])
        self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
