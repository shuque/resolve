"""
Tests for the Prefs dataclass and its module-level singleton.
"""

import dataclasses
import unittest

from reslib.prefs import Prefs, prefs


class TestPrefs(unittest.TestCase):

    def test_is_dataclass(self):
        self.assertTrue(dataclasses.is_dataclass(Prefs))

    def test_singleton_is_instance(self):
        self.assertIsInstance(prefs, Prefs)

    def test_defaults(self):
        self.assertEqual(prefs.MINIMIZE, False)
        self.assertEqual(prefs.TCPONLY, False)
        self.assertEqual(prefs.VERBOSE, 0)
        self.assertEqual(prefs.JSON, False)
        self.assertEqual(prefs.VIOLATE, False)
        self.assertEqual(prefs.STATS, False)
        self.assertEqual(prefs.NSRESOLVE, False)
        self.assertEqual(prefs.PAYLOAD, 1460)
        self.assertEqual(prefs.DNSSEC, False)
        self.assertEqual(prefs.DUMPCACHE, False)
        self.assertEqual(prefs.V4_ONLY, False)
        self.assertEqual(prefs.V6_ONLY, False)
        self.assertIsNone(prefs.BATCHFILE)
        self.assertEqual(prefs.TIMEOUT, 3)
        self.assertEqual(prefs.RETRIES, 2)
        self.assertEqual(prefs.RETRY, 1)
        self.assertEqual(prefs.MAX_CNAME, 15)
        self.assertEqual(prefs.MAX_QUERY, 600)
        self.assertEqual(prefs.MAX_DELEG, 200)
        self.assertEqual(prefs.N3_HASHLIMIT, 512)

    def test_instance_is_mutable(self):
        original = prefs.DNSSEC
        try:
            prefs.DNSSEC = True
            self.assertTrue(prefs.DNSSEC)
        finally:
            prefs.DNSSEC = original


if __name__ == "__main__":
    unittest.main()
