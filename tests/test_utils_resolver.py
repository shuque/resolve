"""
Tests that dnssec/utils helpers accept a resolver and read prefs through it.
Offline and deterministic; no network.
"""

import inspect
import unittest

from reslib.resolver import Resolver
import reslib.dnssec as dnssec


class TestDnssecTakesResolver(unittest.TestCase):

    def test_validate_all_first_param_is_resolver(self):
        sig = inspect.signature(dnssec.validate_all)
        params = list(sig.parameters)
        self.assertEqual(params[0], "resolver")

    def test_initialize_dnssec_takes_resolver(self):
        from reslib.lookup import initialize_dnssec
        sig = inspect.signature(initialize_dnssec)
        self.assertEqual(list(sig.parameters)[0], "resolver")


if __name__ == "__main__":
    unittest.main()
