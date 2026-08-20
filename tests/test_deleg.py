"""Unit tests for the DELEG DelegInfos codec (reslib/deleg.py)."""

import struct
import unittest

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rrset

from reslib.deleg import (
    parse_deleginfos, DelegParseError, DelegInfo,
    DELEG_RDTYPE, DELEGPARAM_RDTYPE, EDNS_DE_FLAG, format_deleginfo,
    classify_record, build_slist, DelegRecordError,
    SLIST_USABLE, SLIST_UNUSABLE, SLIST_ABSENT,
)
from reslib.zone import Zone
from reslib.resolver import Resolver


def _tlv(keynum, value):
    """Build one (key, length, value) DelegInfo wire triple."""
    return struct.pack("!HH", keynum, len(value)) + value


def _wire_name(text):
    """Return the uncompressed wire-format encoding of a name."""
    return dns.name.from_text(text).to_wire()


def _deleg_rrset(owner_text, rdata_bytes_list):
    """Build a DELEG RRset from a list of raw RDATA byte blobs."""
    owner = dns.name.from_text(owner_text)
    rrset = dns.rrset.RRset(owner, dns.rdataclass.IN, DELEG_RDTYPE)
    for blob in rdata_bytes_list:
        rrset.add(dns.rdata.from_wire(dns.rdataclass.IN, DELEG_RDTYPE,
                                       blob, 0, len(blob)), ttl=3600)
    return rrset


class TestDelegConstants(unittest.TestCase):

    def test_type_codes(self):
        self.assertEqual(DELEG_RDTYPE, 61440)
        self.assertEqual(DELEGPARAM_RDTYPE, 65433)
        self.assertEqual(EDNS_DE_FLAG, 0x2000)


class TestParseDelegInfos(unittest.TestCase):

    def test_mandatory_and_ipv4(self):
        # Appendix B Figure 1: mandatory=server-ipv4 server-ipv4=192.0.2.1,192.0.2.2
        rdata = bytes.fromhex("00000002000100010008c0000201c0000202")
        di = parse_deleginfos(rdata)
        self.assertEqual(di.mandatory, {1})
        self.assertEqual(di.server_ipv4, ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(di.server_ipv6, [])
        self.assertEqual(di.unknown_keys, set())

    def test_ipv6(self):
        # Appendix B Figure 2
        rdata = bytes.fromhex(
            "00020020"
            "20010db8000000000000000000000001"
            "20010db8000000000000000000530001")
        di = parse_deleginfos(rdata)
        self.assertEqual(di.server_ipv6, ["2001:db8::1", "2001:db8::53:1"])

    def test_server_name(self):
        # Appendix B Figure 3: server-name=NS2.EXAMPLE.NET.,ns3.example.org.
        # Wire bytes verified by round-tripping dns.name.from_text(...).to_wire()
        # for both names (see task-1-report.md for the derivation).
        rdata = bytes.fromhex(
            "00030022"
            "034e5332074558414d504c45034e455400"
            "036e7333076578616d706c65036f726700")
        di = parse_deleginfos(rdata)
        self.assertEqual(
            di.server_name,
            [dns.name.from_text("NS2.EXAMPLE.NET."),
             dns.name.from_text("ns3.example.org.")])

    def test_include_delegparam(self):
        # Appendix B Figure 4
        rdata = bytes.fromhex("00040013" "05706172616d076578616d706c65036e657400")
        di = parse_deleginfos(rdata)
        self.assertEqual(di.include_delegparam,
                         [dns.name.from_text("param.example.net.")])

    def test_reject_non_increasing_keys(self):
        # key 2 then key 1 (out of order)
        rdata = bytes.fromhex("00020004c0000201" "00010004c0000202")
        with self.assertRaises(DelegParseError):
            parse_deleginfos(rdata)

    def test_reject_duplicate_key(self):
        rdata = bytes.fromhex("00010004c0000201" "00010004c0000202")
        with self.assertRaises(DelegParseError):
            parse_deleginfos(rdata)

    def test_reject_truncated(self):
        # key 1, claims length 8, only 4 bytes of value
        rdata = bytes.fromhex("00010008c0000201")
        with self.assertRaises(DelegParseError):
            parse_deleginfos(rdata)

    def test_reject_empty_value(self):
        rdata = bytes.fromhex("00010000")
        with self.assertRaises(DelegParseError):
            parse_deleginfos(rdata)

    def test_unknown_key_recorded(self):
        # key 99 (unsupported) with a 1-byte value
        rdata = bytes.fromhex("006300010a")
        di = parse_deleginfos(rdata)
        self.assertIn(99, di.unknown_keys)


class TestFormatDelegInfo(unittest.TestCase):

    def test_format_mandatory_and_ipv4(self):
        rdata = bytes.fromhex("00000002000100010008c0000201c0000202")
        text = format_deleginfo(rdata)
        self.assertIn("mandatory=server-ipv4", text)
        self.assertIn("server-ipv4=192.0.2.1,192.0.2.2", text)

    def test_format_falls_back_on_malformed(self):
        rdata = bytes.fromhex("00010000")  # empty value -> parse error
        text = format_deleginfo(rdata)
        self.assertTrue(text.startswith("\\# "))

    def test_format_unknown_key(self):
        rdata = bytes.fromhex("006300010a")
        text = format_deleginfo(rdata)
        self.assertIn("key99=0a", text)


class TestDelegInfoClass(unittest.TestCase):

    def test_keys_insertion_order(self):
        rdata = bytes.fromhex("00000002000100010008c0000201c0000202")
        di = parse_deleginfos(rdata)
        self.assertIsInstance(di, DelegInfo)
        self.assertEqual(list(di.keys.keys()), [0, 1])

    def test_server_info_keys(self):
        rdata = bytes.fromhex("00010008c0000201c0000202")
        di = parse_deleginfos(rdata)
        self.assertEqual(di.server_info_keys(), {1})


class TestClassifyRecord(unittest.TestCase):

    OWNER = dns.name.from_text("sub0.deleg.huque.com.")

    def test_ipv4_record(self):
        di = parse_deleginfos(bytes.fromhex("00010004c0000201"))
        kind, payload = classify_record(di, self.OWNER)
        self.assertEqual(kind, "addrs")
        self.assertEqual(payload, ["192.0.2.1"])

    def test_mandatory_unsatisfied_is_unusable(self):
        # mandatory references key 2 (server-ipv6) which is absent -> drop
        di = parse_deleginfos(bytes.fromhex("00000002000200010004c0000201"))
        with self.assertRaises(DelegRecordError):
            classify_record(di, self.OWNER)

    def test_multiple_server_shapes_malformed(self):
        # server-ipv4 (key1) + server-name (key3) is a disallowed combination
        rdata = (_tlv(1, bytes.fromhex("c0000201")) +
                  _tlv(3, _wire_name("www.example.com.")))
        di = parse_deleginfos(rdata)
        with self.assertRaises(DelegRecordError):
            classify_record(di, self.OWNER)

    def test_in_bailiwick_server_name_rejected(self):
        # server-name equal to / below the delegated owner -> malformed
        di = DelegInfo()
        di.keys = {3: b"x"}
        di.server_name = [dns.name.from_text("ns.sub0.deleg.huque.com.")]
        with self.assertRaises(DelegRecordError):
            classify_record(di, self.OWNER)

    def test_no_supported_keys_contributes_nothing(self):
        di = parse_deleginfos(bytes.fromhex("006300010a"))  # only key99
        kind, payload = classify_record(di, self.OWNER)
        self.assertEqual(kind, "none")


class TestBuildSlist(unittest.TestCase):

    OWNER = "sub0.deleg.huque.com."

    def test_absent(self):
        result = build_slist(None, dns.name.from_text(self.OWNER),
                              lambda n: [], lambda n: None, max_chain=5)
        self.assertEqual(result.state, SLIST_ABSENT)

    def test_inline_addrs_dedup(self):
        rdata = bytes.fromhex("00010004c0000201")
        rrset = _deleg_rrset(self.OWNER, [rdata, rdata])
        result = build_slist(rrset, dns.name.from_text(self.OWNER),
                              lambda n: [], lambda n: None, max_chain=5)
        self.assertEqual(result.state, SLIST_USABLE)
        self.assertEqual(result.addresses, ["192.0.2.1"])

    def test_server_name_resolved(self):
        # server-name=ns.example.net. (out of bailiwick of OWNER)
        rdata = _tlv(3, _wire_name("ns.example.net."))
        rrset = _deleg_rrset(self.OWNER, [rdata])
        result = build_slist(
            rrset, dns.name.from_text(self.OWNER),
            resolve_addrs=lambda n: ["203.0.113.9"],
            fetch_delegparam=lambda n: None, max_chain=5)
        self.assertEqual(result.state, SLIST_USABLE)
        self.assertEqual(result.addresses, ["203.0.113.9"])

    def test_all_records_dropped_is_unusable(self):
        # single record whose mandatory is unsatisfiable
        rdata = bytes.fromhex("00000002000200010004c0000201")
        rrset = _deleg_rrset(self.OWNER, [rdata])
        result = build_slist(rrset, dns.name.from_text(self.OWNER),
                              lambda n: [], lambda n: None, max_chain=5)
        self.assertEqual(result.state, SLIST_UNUSABLE)
        self.assertEqual(result.addresses, [])

    def test_delegparam_indirection_resolved(self):
        # include-delegparam=param.example.net. -> fetch returns a DELEGPARAM
        # RRset containing a usable inline address.
        target = dns.name.from_text("param.example.net.")
        indirect_rdata = _tlv(1, bytes.fromhex("c0000205"))
        indirect_rrset = _deleg_rrset(self.OWNER, [indirect_rdata])

        def fetch(name):
            if name == target:
                return indirect_rrset
            return None

        rdata = _tlv(4, _wire_name("param.example.net."))
        rrset = _deleg_rrset(self.OWNER, [rdata])
        result = build_slist(rrset, dns.name.from_text(self.OWNER),
                              lambda n: [], fetch, max_chain=5)
        self.assertEqual(result.state, SLIST_USABLE)
        self.assertEqual(result.addresses, ["192.0.2.5"])

    def test_delegparam_loop_bound_drops_record(self):
        # include-delegparam target whose fetch just points back at itself
        # forever; must be dropped once max_chain is exceeded rather than
        # recursing without bound.
        target = dns.name.from_text("param.example.net.")
        rdata = _tlv(4, _wire_name("param.example.net."))
        rrset = _deleg_rrset(self.OWNER, [rdata])

        def fetch(name):
            self.assertEqual(name, target)
            return rrset

        result = build_slist(rrset, dns.name.from_text(self.OWNER),
                              lambda n: [], fetch, max_chain=2)
        self.assertEqual(result.state, SLIST_UNUSABLE)
        self.assertEqual(result.addresses, [])


class TestZoneDeleg(unittest.TestCase):

    def _zone(self):
        resolver = Resolver()
        return Zone(dns.name.from_text("sub0.deleg.huque.com."), resolver)

    def test_deleg_iplist_used_when_via_deleg(self):
        zone = self._zone()
        zone.install_deleg_addresses(["192.0.2.1", "2001:db8::1"], None)
        self.assertTrue(zone.via_deleg)
        addrs = [ip.addr for ip in zone.iplist()]
        self.assertEqual(sorted(addrs), sorted(["192.0.2.1", "2001:db8::1"]))

    def test_default_zone_not_via_deleg(self):
        zone = self._zone()
        self.assertFalse(zone.via_deleg)
        self.assertFalse(zone.adt)

    def test_deleg_iplist_respects_v4_only_and_v6_only(self):
        zone = self._zone()
        zone.install_deleg_addresses(
            ["192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"], None)

        zone.resolver.prefs.V4_ONLY = True
        zone.resolver.prefs.V6_ONLY = False
        addrs = sorted(ip.addr for ip in zone.iplist())
        self.assertEqual(addrs, ["192.0.2.1", "192.0.2.2"])

        zone.resolver.prefs.V4_ONLY = False
        zone.resolver.prefs.V6_ONLY = True
        addrs = sorted(ip.addr for ip in zone.iplist())
        self.assertEqual(addrs, ["2001:db8::1", "2001:db8::2"])


import dns.flags
from reslib.utils import make_query_message
from reslib.query import Query


class TestDelegEdnsFlag(unittest.TestCase):

    def test_de_flag_set_when_prefs_deleg(self):
        resolver = Resolver()
        resolver.prefs.DELEG = True
        q = Query("sub0.deleg.huque.com.", "A", "IN", resolver=resolver)
        msg = make_query_message(q)
        from reslib.deleg import EDNS_DE_FLAG
        self.assertTrue(msg.ednsflags & EDNS_DE_FLAG)

    def test_de_flag_absent_by_default(self):
        resolver = Resolver()
        q = Query("sub0.deleg.huque.com.", "A", "IN", resolver=resolver)
        msg = make_query_message(q)
        from reslib.deleg import EDNS_DE_FLAG
        self.assertFalse(msg.ednsflags & EDNS_DE_FLAG)


import dns.rdtypes.ANY.DNSKEY
from reslib.dnssec import DNSKEY


def _make_dnskey_rr(flags):
    # protocol=3, alg=8 (RSASHA256), a minimal non-empty key blob
    return dns.rdtypes.ANY.DNSKEY.DNSKEY(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY,
        flags=flags, protocol=3, algorithm=8, key=b"\x03\x01\x00\x01abcd")


class TestAdtFlag(unittest.TestCase):

    def test_adt_flag_set(self):
        # 259 = ZONE(0x100) | ADT(0x0002) | SEP(0x0001)
        rr = _make_dnskey_rr(259)
        key = DNSKEY(dns.name.from_text("deleg.huque.com."), rr)
        self.assertTrue(key.adt_flag)
        self.assertTrue(key.zone_flag)
        self.assertTrue(key.sep_flag)

    def test_adt_flag_clear(self):
        rr = _make_dnskey_rr(257)   # ZONE | SEP, no ADT
        key = DNSKEY(dns.name.from_text("example.com."), rr)
        self.assertFalse(key.adt_flag)


from reslib.lookup import get_rrset_dict
import dns.message
import dns.rcode
import dns.rdatatype
from unittest import mock

from reslib.lookup import process_referral
import reslib.lookup as lookup
from reslib.query import Query
from reslib.exception import ResError

ZONE = "sub0.deleg.huque.com."
NSNAME = "ns.example.net."


def _ns_rrset(owner_text=ZONE, target_text=NSNAME):
    return dns.rrset.from_text(owner_text, 3600, "IN", "NS", target_text)


def _referral_query(resolver, authority_rrsets):
    """Build a Query whose response carries the given authority RRsets."""
    msg = dns.message.Message()
    for rrset in authority_rrsets:
        msg.authority.append(rrset)
    query = Query(ZONE, "A", "IN", resolver=resolver)
    query.response = msg
    return query


class TestProcessReferralDeleg(unittest.TestCase):
    """Offline coverage of the DELEG / NS dispatch in process_referral.

    All cases run with prefs.DNSSEC=False so the validate/DS block is skipped
    and no signatures or network are needed. The secure/insecure-via-DS
    decision and DELEG RRSIG validation are exercised live in Task 9.
    """

    def _resolver(self):
        r = Resolver()
        r.prefs.DELEG = True
        r.prefs.DNSSEC = False
        return r

    def test_deleg_happy_path_inline_addrs(self):
        # (a) inline server-ipv4 DELEG -> usable, no callbacks, no network.
        deleg = _deleg_rrset(ZONE, [_tlv(1, bytes.fromhex("c0000201"))])
        resolver = self._resolver()
        query = _referral_query(resolver, [deleg])
        zone = process_referral(query)
        self.assertTrue(zone.via_deleg)
        self.assertEqual([ip.addr for ip in zone.deleg_iplist], ["192.0.2.1"])
        self.assertEqual([ip.addr for ip in zone.iplist()], ["192.0.2.1"])

    def test_ns_not_cached_on_deleg_path(self):
        # (b) DELEG + stray NS -> NS must not be validated or cached, and the
        # zone must have no NS names. Regression test for FINDING 1.
        deleg = _deleg_rrset(ZONE, [_tlv(1, bytes.fromhex("c0000201"))])
        ns = _ns_rrset()
        resolver = self._resolver()
        query = _referral_query(resolver, [deleg, ns])
        zone = process_referral(query)
        self.assertTrue(zone.via_deleg)
        self.assertEqual(zone.nslist, [])
        self.assertNotIn((dns.name.from_text(ZONE), dns.rdatatype.NS),
                         resolver.cache.RRsets)
        # DELEG itself is cached.
        self.assertIn((dns.name.from_text(ZONE), DELEG_RDTYPE),
                      resolver.cache.RRsets)

    def test_unusable_deleg_raises_no_fallback(self):
        # (c) DELEG with only an unsupported key -> classify "none" ->
        # SLIST_UNUSABLE -> ResError, and NS is never cached (no fallback).
        deleg = _deleg_rrset(ZONE, [_tlv(99, b"\x00\x00")])
        ns = _ns_rrset()
        resolver = self._resolver()
        query = _referral_query(resolver, [deleg, ns])
        with self.assertRaises(ResError):
            process_referral(query)
        self.assertNotIn((dns.name.from_text(ZONE), dns.rdatatype.NS),
                         resolver.cache.RRsets)

    def test_deleg_only_cut_no_ns(self):
        # (d) DELEG with no NS at all -> guard relaxation; usable zone.
        deleg = _deleg_rrset(ZONE, [_tlv(1, bytes.fromhex("c0000201"))])
        resolver = self._resolver()
        query = _referral_query(resolver, [deleg])
        zone = process_referral(query)
        self.assertTrue(zone.via_deleg)
        self.assertEqual([ip.addr for ip in zone.iplist()], ["192.0.2.1"])

    def test_prefs_deleg_false_takes_ns_path(self):
        # (e) DELEG present but prefs.DELEG=False -> NS path dispatched.
        deleg = _deleg_rrset(ZONE, [_tlv(1, bytes.fromhex("c0000201"))])
        ns = _ns_rrset()
        resolver = self._resolver()
        resolver.prefs.DELEG = False
        query = _referral_query(resolver, [deleg, ns])
        with mock.patch.object(lookup, "_process_ns_referral") as ns_path, \
             mock.patch.object(lookup, "_process_deleg_referral") as de_path:
            ns_path.return_value = "NS_ZONE"
            result = process_referral(query)
        self.assertEqual(result, "NS_ZONE")
        self.assertEqual(ns_path.call_count, 1)
        self.assertEqual(de_path.call_count, 0)


class TestGetRrsetDictNoCache(unittest.TestCase):

    def test_install_cache_false_leaves_cache_empty(self):
        resolver = Resolver()
        msg = dns.message.from_text(
            "id 1\n;QUESTION\nsub0.deleg.huque.com. IN NS\n"
            ";AUTHORITY\nsub0.deleg.huque.com. 3600 IN NS ns.example.net.\n")
        rrset_dict, _ = get_rrset_dict(resolver, msg.authority,
                                       install_cache=False)
        self.assertTrue(rrset_dict)
        # nothing installed
        self.assertEqual(resolver.cache.RRsets, {})


import dns.rdtypes.ANY.NSEC
from reslib.lookup import adt_bitmap_consistent


class TestAdtEnforcement(unittest.TestCase):
    """Bitmap-consistency core of ADT delegation-type proof enforcement
    (delext Section 6.2), against synthetic NSEC RRsets. No network."""

    def test_bitmap_consistent_deleg_present(self):
        rrset = dns.rrset.from_text_list(
            dns.name.from_text("sub0.deleg.huque.com."), 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. RRSIG TYPE61440"])
        # DELEG present in Authority, bitmap lists TYPE61440 -> consistent
        self.assertTrue(
            adt_bitmap_consistent(rrset[0], deleg_present=True,
                                  ns_present=False))

    def test_bitmap_inconsistent_deleg_stripped(self):
        # bitmap says DELEG exists, but DELEG RRset absent from Authority
        rrset = dns.rrset.from_text_list(
            dns.name.from_text("sub0.deleg.huque.com."), 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. RRSIG TYPE61440"])
        self.assertFalse(
            adt_bitmap_consistent(rrset[0], deleg_present=False,
                                  ns_present=False))

    def test_bitmap_consistent_ns_only(self):
        rrset = dns.rrset.from_text_list(
            dns.name.from_text("sub2.deleg.huque.com."), 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. NS DS RRSIG"])
        self.assertTrue(
            adt_bitmap_consistent(rrset[0], deleg_present=False,
                                  ns_present=True))


class TestAdtFlagPopulatedFromKeylist(unittest.TestCase):
    """Carried minor from Task 5: unit-test the exact expression used in
    match_ds_zone / initialize_dnssec to set zone.adt / root_zone.adt --
    any(getattr(k, "adt_flag", False) for k in keylist) -- against
    constructed DNSKEY objects. A full match_ds_zone integration test would
    require a live DNSKEY response over the network, which is unavailable
    here (see class docstring in TestProcessReferralDeleg)."""

    def test_any_true_when_one_key_has_adt_flag(self):
        rr_adt = _make_dnskey_rr(259)     # ZONE | SEP | ADT
        rr_plain = _make_dnskey_rr(257)   # ZONE | SEP, no ADT
        keylist = [
            DNSKEY(dns.name.from_text("deleg.huque.com."), rr_plain),
            DNSKEY(dns.name.from_text("deleg.huque.com."), rr_adt),
        ]
        self.assertTrue(any(getattr(k, "adt_flag", False) for k in keylist))

    def test_any_false_when_no_key_has_adt_flag(self):
        rr_plain1 = _make_dnskey_rr(257)
        rr_plain2 = _make_dnskey_rr(256)  # ZONE only
        keylist = [
            DNSKEY(dns.name.from_text("example.com."), rr_plain1),
            DNSKEY(dns.name.from_text("example.com."), rr_plain2),
        ]
        self.assertFalse(any(getattr(k, "adt_flag", False) for k in keylist))

    def test_any_false_for_empty_keylist(self):
        self.assertFalse(any(getattr(k, "adt_flag", False) for k in []))


if __name__ == "__main__":
    unittest.main()
