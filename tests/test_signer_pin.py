"""
Unit tests for RRSIG signer pinning (RFC 4035 Section 5.3.1) in
reslib.dnssec. An RRSIG is only usable if its signer is the zone
authoritative for the RRset: the owner name must be at or below the
signer's zone (signer == owner's zone or an ancestor of it). This blocks
an on-path attacker's own securely-delegated but off-path zone from
signing records it has no authority over. Offline and deterministic; no
network.
"""

import unittest

import dns.name
import dns.rrset

from reslib import dnssec
from reslib.dnssec import signer_on_path
from reslib.exception import ResError
from reslib.resolver import Resolver


# A syntactically valid RRSIG whose signer field is substituted per test.
# The signature bytes are dummy: off-path sigs are discarded before any
# crypto, and the on-path case fails earlier on an empty key cache.
DUMMY_SIG = ("A 8 2 3600 20990101000000 20200101000000 12345 {} "
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


def make_rrsig(owner, signer):
    return dns.rrset.from_text(owner, 3600, "IN", "RRSIG",
                               DUMMY_SIG.format(signer))


def _n(text):
    return dns.name.from_text(text)


class TestSignerOnPath(unittest.TestCase):

    def test_same_zone_ok(self):
        self.assertTrue(signer_on_path(_n("www.example."), _n("example.")))

    def test_owner_equals_signer_ok(self):
        self.assertTrue(signer_on_path(_n("example."), _n("example.")))

    def test_ancestor_signer_ok(self):
        # DS-style: owner = child zone, signer = parent zone.
        self.assertTrue(signer_on_path(_n("child.example."), _n("example.")))

    def test_root_signer_ok(self):
        self.assertTrue(signer_on_path(_n("example."), _n(".")))

    def test_offpath_signer_rejected(self):
        self.assertFalse(signer_on_path(_n("victim.example."),
                                        _n("evil.example.")))

    def test_sibling_signer_rejected(self):
        self.assertFalse(signer_on_path(_n("a.example."), _n("b.example.")))


class TestValidateAllSignerPin(unittest.TestCase):

    def test_offpath_signer_skipped_before_key_lookup(self):
        # An off-path signer is discarded with no key fetch and no crypto:
        # validate_all returns no verified keys and does NOT raise the
        # "No DNSSEC keys found" error (which would prove it attempted a
        # key lookup for the attacker's zone).
        rrset = dns.rrset.from_text("victim.example.", 3600, "IN", "A",
                                    "192.0.2.1")
        rrsig = make_rrsig("victim.example.", "evil.example.")
        resolver = Resolver()
        verified, failed = dnssec.validate_all(resolver, rrset, rrsig)
        self.assertEqual(verified, [])
        self.assertTrue(failed)
        self.assertIn("evil.example", str(failed))

    def test_onpath_signer_reaches_key_lookup(self):
        # An on-path signer is NOT rejected by the pin; with an empty key
        # cache it proceeds to the key lookup and raises the existing
        # "No DNSSEC keys found" error. Proves the guard does not
        # over-reject a legitimate in-zone signer.
        rrset = dns.rrset.from_text("www.example.", 3600, "IN", "A",
                                    "192.0.2.1")
        rrsig = make_rrsig("www.example.", "example.")
        resolver = Resolver()
        with self.assertRaises(ResError):
            dnssec.validate_all(resolver, rrset, rrsig)


if __name__ == "__main__":
    unittest.main()
