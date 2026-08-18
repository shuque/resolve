"""
Tests for the walk-scoped SecureSoFar flag relocated from KeyCache to Query.
Offline and deterministic; no network.
"""

import unittest

from reslib.prefs import Prefs
from reslib.resolver import Resolver
from reslib.query import Query


class TestSecureFlagIsQueryScoped(unittest.TestCase):

    def _mkquery(self, resolver):
        return Query("example.com.", "A", "IN", resolver=resolver)

    def test_query_starts_secure(self):
        r = Resolver()
        q = self._mkquery(r)
        self.assertTrue(q.secure_so_far)

    def test_flag_is_not_shared_between_queries(self):
        r = Resolver()
        q1 = self._mkquery(r)
        q2 = self._mkquery(r)
        q1.secure_so_far = False
        self.assertTrue(q2.secure_so_far)

    def test_keycache_no_longer_carries_secure_flag(self):
        r = Resolver()
        self.assertFalse(hasattr(r.key_cache, "SecureSoFar"))


if __name__ == "__main__":
    unittest.main()
