"""
Unit tests for the root trust anchors (reslib.rootkey / KeyCache bootstrap).
Offline and deterministic; no network.

Verifies that both the active (KSK-2017) and pre-published (KSK-2024)
root KSKs are configured and load into the KeyCache. The key material
itself is verified out-of-band against IANA's published DS digests; here
we assert identity (key tags, flags) and that the bootstrap installs them.
"""

import unittest

import dns.name

from reslib.rootkey import RootKeyData
from reslib.dnssec import get_root_keys, KeyCache

KSK_2017_TAG = 20326
KSK_2024_TAG = 38696


class TestRootTrustAnchors(unittest.TestCase):

    def test_two_anchors_configured(self):
        self.assertEqual(len(RootKeyData), 2)

    def test_get_root_keys_returns_both(self):
        keys = get_root_keys()
        tags = sorted(k.keytag for k in keys)
        self.assertEqual(tags, sorted([KSK_2017_TAG, KSK_2024_TAG]))

    def test_anchors_are_sep_ksks(self):
        for key in get_root_keys():
            self.assertEqual(key.algorithm, 8)
            self.assertTrue(key.sep_flag, "trust anchor must have SEP flag")
            self.assertTrue(key.zone_flag, "trust anchor must be a zone key")
            self.assertFalse(key.revoke_flag)

    def test_keycache_installs_both_anchors_at_root(self):
        kc = KeyCache()
        rootkeys = kc.get_keys(dns.name.root)
        self.assertIsNotNone(rootkeys)
        tags = sorted(k.keytag for k in rootkeys)
        self.assertEqual(tags, sorted([KSK_2017_TAG, KSK_2024_TAG]))


if __name__ == "__main__":
    unittest.main()
