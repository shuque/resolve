"""
Unit tests for the Resolver state-encapsulation object (Phase 2).
Offline and deterministic; no network.
"""

import unittest

import dns.name

from reslib.prefs import Prefs
from reslib.resolver import Resolver


class TestResolverConstruction(unittest.TestCase):

    def test_init_does_no_io_and_has_empty_state(self):
        r = Resolver()
        self.assertIsInstance(r.prefs, Prefs)
        self.assertIsNone(r.root_zone)
        self.assertEqual(r.cache.ZoneDict, {})
        self.assertEqual(r.cache.NSDict, {})
        # Back-references are wired.
        self.assertIs(r.cache.resolver, r)
        self.assertIs(r.key_cache.resolver, r)

    def test_accepts_injected_prefs(self):
        p = Prefs()
        p.DNSSEC = False
        r = Resolver(prefs=p)
        self.assertIs(r.prefs, p)

    def test_two_resolvers_are_independent(self):
        a = Resolver()
        b = Resolver()
        self.assertIsNot(a.cache, b.cache)
        self.assertIsNot(a.key_cache, b.key_cache)
        self.assertIsNot(a.stats, b.stats)

    def test_resolve_name_first_param_is_resolver(self):
        import inspect
        from reslib.lookup import resolve_name
        self.assertEqual(list(inspect.signature(resolve_name).parameters)[0],
                         "resolver")

    def test_print_root_zone_takes_resolver(self):
        import inspect
        from reslib.lookup import print_root_zone
        self.assertEqual(list(inspect.signature(print_root_zone).parameters)[0],
                         "resolver")

    def test_nsec3_helpers_take_resolver(self):
        import inspect
        import reslib.dnssec as d
        for fn in (d.nsec3hash, d.get_hashed_owner, d.nsec3_nxdomain_proof,
                   d.nsec3_wildcard_nodata_proof, d.nsec3hashname_from_record,
                   d.nsec3_closest_encloser_and_next, d.ds_rr_matches_dnskey):
            self.assertEqual(list(inspect.signature(fn).parameters)[0], "resolver",
                             "{} first param".format(fn.__name__))


class TestResolverBootstrap(unittest.TestCase):

    def test_bootstrap_builds_root_zone(self):
        r = Resolver()
        r.prefs.DNSSEC = False
        r.bootstrap()
        self.assertIsNotNone(r.root_zone)
        self.assertEqual(r.root_zone.name, dns.name.root)
        self.assertEqual(len(r.root_zone.nslist), 13)
        # KeyCache installs root trust anchors in its own reset(),
        # independent of the DNSSEC pref -- no network needed.
        self.assertIsNotNone(r.key_cache.get_keys(dns.name.root))

    def test_bootstrap_is_idempotent(self):
        r = Resolver()
        r.prefs.DNSSEC = False
        r.bootstrap()
        first = r.root_zone
        r.bootstrap()
        self.assertEqual(r.root_zone.name, first.name)

    def test_reset_rebuilds_state(self):
        r = Resolver()
        r.prefs.DNSSEC = False
        r.bootstrap()
        old_cache = r.cache
        old_key_cache = r.key_cache
        old_stats = r.stats
        # Inject state that a real reset must clear.
        r.stats.cnt_deleg = 5
        r.reset()
        # New component objects, not the old ones.
        self.assertIsNot(r.cache, old_cache)
        self.assertIsNot(r.key_cache, old_key_cache)
        self.assertIsNot(r.stats, old_stats)
        # Counters cleared and root zone rebuilt.
        self.assertEqual(r.stats.cnt_deleg, 0)
        self.assertIsNotNone(r.root_zone)
        self.assertEqual(r.root_zone.name, dns.name.root)

    def test_bootstrap_dnssec_init_runs_once(self):
        # With DNSSEC enabled, the (network) DNSKEY init must run at most
        # once across repeated bootstrap() calls. Stub _init_dnssec to
        # stay offline and count invocations.
        r = Resolver()
        r.prefs.DNSSEC = True
        calls = []
        r._init_dnssec = lambda: calls.append(1)
        r.bootstrap()
        r.bootstrap()
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
