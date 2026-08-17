"""
Tests for command-line option parsing (reslib.options).
Offline, deterministic, no network.
"""

import dataclasses
import unittest

from reslib.prefs import Prefs, prefs
from reslib.options import process_args


def reset_prefs():
    """Reset the shared prefs singleton to declared dataclass defaults."""
    for field in dataclasses.fields(Prefs):
        setattr(prefs, field.name, field.default)


class TestOptions(unittest.TestCase):

    def setUp(self):
        reset_prefs()

    def test_boolean_flags(self):
        process_args(["-m", "-t", "-s", "-n", "-x", "-c", "example.com"])
        self.assertTrue(prefs.MINIMIZE)
        self.assertTrue(prefs.TCPONLY)
        self.assertTrue(prefs.STATS)
        self.assertTrue(prefs.NSRESOLVE)
        self.assertTrue(prefs.VIOLATE)
        self.assertTrue(prefs.DUMPCACHE)

    def test_dnssec_flag(self):
        process_args(["-z", "example.com"])
        self.assertTrue(prefs.DNSSEC)

    def test_verbose_counts(self):
        process_args(["-v", "-v", "example.com"])
        self.assertEqual(prefs.VERBOSE, 2)

    def test_verbose_default_zero(self):
        process_args(["example.com"])
        self.assertEqual(prefs.VERBOSE, 0)

    def test_payload_int(self):
        process_args(["-e", "4096", "example.com"])
        self.assertEqual(prefs.PAYLOAD, 4096)

    def test_payload_non_integer_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-e", "abc", "example.com"])
        self.assertEqual(cm.exception.code, 2)

    def test_positional_name_only(self):
        result = process_args(["example.com"])
        self.assertEqual(result, ("example.com", "A", "IN"))

    def test_positional_name_type(self):
        result = process_args(["example.com", "AAAA"])
        self.assertEqual(result, ("example.com", "AAAA", "IN"))

    def test_positional_name_type_class(self):
        result = process_args(["example.com", "AAAA", "CH"])
        self.assertEqual(result, ("example.com", "AAAA", "CH"))

    def test_no_positional_and_no_batch_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args([])
        self.assertEqual(cm.exception.code, 2)

    def test_four_positionals_exits(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["a", "b", "c", "d"])
        self.assertEqual(cm.exception.code, 2)

    def test_batch_no_positionals(self):
        result = process_args(["-b", "queries.txt"])
        self.assertEqual(result, (None, None, None))
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
        process_args(["-4", "example.com"])
        self.assertTrue(prefs.V4_ONLY)
        self.assertFalse(prefs.V6_ONLY)

    def test_json_forces_verbose_off(self):
        process_args(["-j", "-v", "-v", "example.com"])
        self.assertTrue(prefs.JSON)
        self.assertEqual(prefs.VERBOSE, 0)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            process_args(["-h"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
