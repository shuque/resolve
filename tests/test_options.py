"""
Tests for command-line option parsing (reslib.options).
Offline, deterministic, no network.

process_args returns (prefs, qname, qtype, qclass); it does NOT mutate any
module global. Each test inspects the returned Prefs instance.
"""

import unittest

from reslib.prefs import Prefs
from reslib.options import process_args


class TestOptions(unittest.TestCase):

    def test_boolean_flags(self):
        prefs, _, _, _ = process_args(
            ["-m", "-t", "-s", "-n", "-x", "-c", "example.com"])
        self.assertTrue(prefs.MINIMIZE)
        self.assertTrue(prefs.TCPONLY)
        self.assertTrue(prefs.STATS)
        self.assertTrue(prefs.NSRESOLVE)
        self.assertTrue(prefs.VIOLATE)
        self.assertTrue(prefs.DUMPCACHE)

    def test_dnssec_flag(self):
        prefs, _, _, _ = process_args(["-z", "example.com"])
        self.assertTrue(prefs.DNSSEC)

    def test_verbose_counts(self):
        prefs, _, _, _ = process_args(["-v", "-v", "example.com"])
        self.assertEqual(prefs.VERBOSE, 2)

    def test_verbose_default_zero(self):
        prefs, _, _, _ = process_args(["example.com"])
        self.assertEqual(prefs.VERBOSE, 0)

    def test_payload_int(self):
        prefs, _, _, _ = process_args(["-e", "4096", "example.com"])
        self.assertEqual(prefs.PAYLOAD, 4096)

    def test_payload_non_integer_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-e", "abc", "example.com"])
        self.assertEqual(cm.exception.code, 2)

    def test_positional_name_only(self):
        prefs, qname, qtype, qclass = process_args(["example.com"])
        self.assertEqual((qname, qtype, qclass), ("example.com", "A", "IN"))
        self.assertIsInstance(prefs, Prefs)

    def test_positional_name_type(self):
        _, qname, qtype, qclass = process_args(["example.com", "AAAA"])
        self.assertEqual((qname, qtype, qclass), ("example.com", "AAAA", "IN"))

    def test_positional_name_type_class(self):
        _, qname, qtype, qclass = process_args(["example.com", "AAAA", "CH"])
        self.assertEqual((qname, qtype, qclass), ("example.com", "AAAA", "CH"))

    def test_no_positional_and_no_batch_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args([])
        self.assertEqual(cm.exception.code, 2)

    def test_four_positionals_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["a", "b", "c", "d"])
        self.assertEqual(cm.exception.code, 2)

    def test_batch_no_positionals(self):
        prefs, qname, qtype, qclass = process_args(["-b", "queries.txt"])
        self.assertEqual((qname, qtype, qclass), (None, None, None))
        self.assertEqual(prefs.BATCHFILE, "queries.txt")

    def test_batch_with_positional_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-b", "queries.txt", "example.com"])
        self.assertEqual(cm.exception.code, 2)

    def test_dnssec_requires_edns(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-z", "-e", "0", "example.com"])
        self.assertEqual(cm.exception.code, 2)

    def test_v4_v6_mutually_exclusive(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-4", "-6", "example.com"])
        self.assertEqual(cm.exception.code, 2)

    def test_v4_only(self):
        prefs, _, _, _ = process_args(["-4", "example.com"])
        self.assertTrue(prefs.V4_ONLY)
        self.assertFalse(prefs.V6_ONLY)

    def test_json_forces_verbose_off(self):
        prefs, _, _, _ = process_args(["-j", "-v", "-v", "example.com"])
        self.assertTrue(prefs.JSON)
        self.assertEqual(prefs.VERBOSE, 0)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-h"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
