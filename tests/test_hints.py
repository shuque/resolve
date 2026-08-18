"""
Unit tests for the root hints and root-zone bootstrap / cache reset.
Offline and deterministic; no network.

Guards the periodic root-hints refresh (e.g. the b.root-servers.net
renumbering) and the cache reset mechanics that batch mode relies on.
"""

import socket
import unittest

import dns.name

from reslib.hints import ROOTHINTS, ROOT_NS_TTL
from reslib.cache import get_root_zone
from reslib.resolver import Resolver


def is_valid_ip(addr):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, addr)
            return True
        except OSError:
            continue
    return False


class TestRootHints(unittest.TestCase):

    def test_thirteen_letters_a_through_m(self):
        names = {name for name, _ in ROOTHINTS}
        expected = {"{}.root-servers.net.".format(c)
                    for c in "abcdefghijklm"}
        self.assertEqual(names, expected)

    def test_every_address_parses(self):
        for name, addr in ROOTHINTS:
            self.assertTrue(is_valid_ip(addr),
                            "invalid address for {}: {}".format(name, addr))

    def test_each_letter_has_v4_and_v6(self):
        for c in "abcdefghijklm":
            name = "{}.root-servers.net.".format(c)
            addrs = [a for n, a in ROOTHINTS if n == name]
            v4 = [a for a in addrs if ":" not in a]
            v6 = [a for a in addrs if ":" in a]
            self.assertEqual(len(v4), 1, "one A record for {}".format(name))
            self.assertEqual(len(v6), 1, "one AAAA record for {}".format(name))

    def test_b_root_renumbered_2023(self):
        # Regression guard for the 2023 b-root renumbering.
        addrs = dict.fromkeys(
            a for n, a in ROOTHINTS if n == "b.root-servers.net.")
        self.assertIn("170.247.170.2", addrs)
        self.assertIn("2801:1b8:10::b", addrs)
        self.assertNotIn("199.9.14.201", addrs)


class TestRootZoneBootstrap(unittest.TestCase):

    def test_get_root_zone_builds_secure_zone(self):
        cache = Resolver().cache
        root = get_root_zone(cache)
        self.assertEqual(root.name, dns.name.root)
        self.assertTrue(root.secure)
        self.assertEqual(len(root.nslist), 13)
        self.assertEqual(root.ttl_ns, ROOT_NS_TTL)
        self.assertEqual(len(root.iplist()), 26)

    def test_root_zone_installed_and_reachable_via_closest_zone(self):
        cache = Resolver().cache
        get_root_zone(cache)
        z = cache.closest_zone(dns.name.from_text("example.com."))
        self.assertIsNotNone(z)
        self.assertEqual(z.name, dns.name.root)

    def test_cache_reset_rebuilds_cleanly(self):
        # reset empties the cache, and get_root_zone repopulates it in place.
        cache = Resolver().cache
        get_root_zone(cache)
        cache.reset()
        self.assertEqual(cache.ZoneDict, {})
        self.assertEqual(cache.NSDict, {})
        root = get_root_zone(cache)
        self.assertEqual(len(root.iplist()), 26)


if __name__ == "__main__":
    unittest.main()
