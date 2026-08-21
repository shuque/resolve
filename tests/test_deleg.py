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


from reslib.lookup import adt_bitmap_consistent, enforce_adt_proof
from reslib.rrset import RRset


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

    def test_bitmap_consistent_stacked_deleg_ns_omitted(self):
        # Stacked cut: the signed NSEC bitmap legitimately carries both NS
        # and DELEG (zone truth), but a DE=1 referral sends only the DELEG
        # RRset (the server drops NS in its favour). NS-in-bitmap vs
        # NS-absent-from-Authority is therefore NOT a tampering signal --
        # only the DELEG direction is checked.
        rrset = dns.rrset.from_text_list(
            dns.name.from_text("sub0.deleg.huque.com."), 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. NS DS RRSIG TYPE61440"])
        self.assertTrue(
            adt_bitmap_consistent(rrset[0], deleg_present=True,
                                  ns_present=False))


class TestAdtFlagPopulatedFromKeylist(unittest.TestCase):
    """Carried minor from Task 5: unit-test the exact expression used in
    match_ds_zone / initialize_dnssec to set zone.adt / root_zone.adt --
    any(getattr(k, "adt_flag", False) for k in keylist) -- against
    constructed DNSKEY objects. See TestMatchDsZoneAdtAssignment below for
    coverage of the real `zone.adt = ...` assignment inside match_ds_zone
    itself (Fix round 1 strengthens this minor beyond re-testing any() +
    DNSKEY.adt_flag, which TestAdtFlag already covers)."""

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


class TestMatchDsZoneAdtAssignment(unittest.TestCase):
    """Fix round 1: exercise the REAL `zone.adt = ...` assignment inside
    match_ds_zone (reslib/lookup.py, near the "DS did not match DNSKEY"
    raise), not just the boolean expression in isolation.

    match_ds_zone's network-facing collaborators (get_zone_addresses,
    send_query, check_self_signature, match_ds_ksklist,
    supported_algorithm_present) are mocked so the function's own control
    flow runs for real, offline, all the way through to the zone.adt
    assignment line. This is the "reasonable effort" version of a live
    match_ds_zone integration test, which would otherwise require a real
    signed DNSKEY response over the network.
    """

    def _zone(self, resolver):
        zone = Zone(dns.name.from_text("deleg.huque.com."), resolver)
        zone.dslist = [mock.Mock()]  # non-empty; supported_algorithm_present is patched
        return zone

    def _run_match_ds_zone(self, keylist):
        resolver = Resolver()
        zone = self._zone(resolver)

        fake_response = mock.Mock()
        fake_response.rcode.return_value = dns.rcode.NOERROR
        fake_response.get_rrset.return_value = mock.Mock()  # non-None sentinel

        with mock.patch.object(lookup, "supported_algorithm_present",
                               return_value=True), \
             mock.patch.object(lookup, "get_zone_addresses",
                               return_value=[mock.Mock()]), \
             mock.patch.object(lookup, "send_query",
                               return_value=fake_response), \
             mock.patch.object(lookup, "check_self_signature",
                               return_value=(keylist, keylist)), \
             mock.patch.object(lookup, "match_ds_ksklist", return_value=True):
            lookup.match_ds_zone(zone, None)
        return zone

    def test_zone_adt_set_true_when_adt_flagged_key_signs(self):
        key_adt = DNSKEY(dns.name.from_text("deleg.huque.com."),
                         _make_dnskey_rr(259))  # ZONE | SEP | ADT
        zone = self._run_match_ds_zone([key_adt])
        self.assertTrue(zone.adt)

    def test_zone_adt_set_false_when_no_adt_flagged_key_signs(self):
        key_plain = DNSKEY(dns.name.from_text("deleg.huque.com."),
                           _make_dnskey_rr(257))  # ZONE | SEP, no ADT
        zone = self._run_match_ds_zone([key_plain])
        self.assertFalse(zone.adt)


class TestMatchDsZoneTerminalError(unittest.TestCase):
    """match_ds_zone's terminal failure message must name the actual cause.
    "DS did not match DNSKEY" is only truthful when a validated DNSKEY RRset
    was obtained and compared against the DS. When every nameserver is
    unreachable (or none returns a usable, self-signed DNSKEY) no comparison
    ever happens -- keylist stays None -- and the message must say so instead
    of blaming a DS mismatch (the sub0.deleg.huque.com case: DELEG points at
    unroutable placeholder addresses)."""

    def _zone(self, resolver):
        zone = Zone(dns.name.from_text("sub0.deleg.huque.com."), resolver)
        zone.dslist = [mock.Mock()]
        return zone

    def _run(self, response, ds_match):
        resolver = Resolver()
        zone = self._zone(resolver)
        with mock.patch.object(lookup, "supported_algorithm_present",
                               return_value=True), \
             mock.patch.object(lookup, "get_zone_addresses",
                               return_value=[mock.Mock()]), \
             mock.patch.object(lookup, "send_query", return_value=response), \
             mock.patch.object(lookup, "check_self_signature",
                               return_value=(["KEY"], ["KEY"])), \
             mock.patch.object(lookup, "match_ds_ksklist",
                               return_value=ds_match):
            lookup.match_ds_zone(zone, None)

    def test_all_servers_unreachable_reports_no_dnskey(self):
        # send_query returns None for every address -> keylist never set.
        with self.assertRaises(ResError) as cm:
            self._run(response=None, ds_match=False)
        self.assertIn("Could not obtain a validated DNSKEY", str(cm.exception))

    def test_dnskey_obtained_but_ds_mismatch_reports_ds(self):
        # A usable DNSKEY came back but no KSK matched the DS -> genuine
        # DS-mismatch, keep the original message.
        fake_response = mock.Mock()
        fake_response.rcode.return_value = dns.rcode.NOERROR
        fake_response.get_rrset.return_value = mock.Mock()
        with self.assertRaises(ResError) as cm:
            self._run(response=fake_response, ds_match=False)
        self.assertIn("DS did not match DNSKEY", str(cm.exception))


class TestEnforceAdtProof(unittest.TestCase):
    """Fix round 1: directly exercise enforce_adt_proof's raise paths and
    consistent-match return, against a synthetic rrset_dict keyed exactly
    as process_referral builds it: (rrname, rrtype) -> reslib.rrset.RRset.
    validate_rrset is patched to a no-op (it always re-validates and does
    not short-circuit on srrset.validated, so real signatures would
    otherwise be required)."""

    ZONENAME = dns.name.from_text("sub0.deleg.huque.com.")

    def _query(self):
        return Query(self.ZONENAME, "A", "IN", resolver=Resolver())

    def test_inconsistent_bitmap_deleg_stripped_raises(self):
        # Bitmap lists TYPE61440 (DELEG), but DELEG RRset absent from
        # Authority -> stripped -> ResError.
        nsec_rrset = dns.rrset.from_text_list(
            self.ZONENAME, 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. RRSIG TYPE61440"])
        srrset = RRset(self.ZONENAME, dns.rdatatype.NSEC, rrset=nsec_rrset)
        rrset_dict = {(self.ZONENAME, dns.rdatatype.NSEC): srrset}
        with mock.patch.object(lookup, "validate_rrset"):
            with self.assertRaises(ResError):
                enforce_adt_proof(self._query(), self.ZONENAME,
                                  deleg_present=False, ns_present=False,
                                  rrset_dict=rrset_dict)

    def test_missing_proof_owner_mismatch_raises(self):
        # NSEC present, but its owner is not the delegated name -> no proof
        # matches zonename -> ResError.
        other = dns.name.from_text("other.deleg.huque.com.")
        nsec_rrset = dns.rrset.from_text_list(
            other, 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. RRSIG TYPE61440"])
        srrset = RRset(other, dns.rdatatype.NSEC, rrset=nsec_rrset)
        rrset_dict = {(other, dns.rdatatype.NSEC): srrset}
        with mock.patch.object(lookup, "validate_rrset"):
            with self.assertRaises(ResError):
                enforce_adt_proof(self._query(), self.ZONENAME,
                                  deleg_present=True, ns_present=False,
                                  rrset_dict=rrset_dict)

    def test_missing_proof_no_nsec_at_all_raises(self):
        with mock.patch.object(lookup, "validate_rrset"):
            with self.assertRaises(ResError):
                enforce_adt_proof(self._query(), self.ZONENAME,
                                  deleg_present=True, ns_present=False,
                                  rrset_dict={})

    def test_consistent_match_returns_without_raising(self):
        nsec_rrset = dns.rrset.from_text_list(
            self.ZONENAME, 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. RRSIG TYPE61440"])
        srrset = RRset(self.ZONENAME, dns.rdatatype.NSEC, rrset=nsec_rrset)
        rrset_dict = {(self.ZONENAME, dns.rdatatype.NSEC): srrset}
        with mock.patch.object(lookup, "validate_rrset"):
            enforce_adt_proof(self._query(), self.ZONENAME,
                              deleg_present=True, ns_present=False,
                              rrset_dict=rrset_dict)  # must not raise

    def test_nsec3_consistent_match_returns_without_raising(self):
        hashed_owner = dns.name.from_text(
            "1avvqn74sg75ukfcmhfb4ulocmkn3mo2.deleg.huque.com.")
        nsec3_rrset = dns.rrset.from_text_list(
            hashed_owner, 3600, "IN", "NSEC3",
            ["1 0 0 - 1AVVQN74SG75UKFCMHFB4ULOCMKN3MO2 RRSIG TYPE61440"])
        srrset = RRset(hashed_owner, dns.rdatatype.NSEC3, rrset=nsec3_rrset,
                       rrsig=[mock.Mock(signer=dns.name.root)])
        rrset_dict = {(hashed_owner, dns.rdatatype.NSEC3): srrset}
        with mock.patch.object(lookup, "validate_rrset"), \
             mock.patch.object(lookup, "get_hashed_owner",
                               return_value=hashed_owner):
            enforce_adt_proof(self._query(), self.ZONENAME,
                              deleg_present=True, ns_present=False,
                              rrset_dict=rrset_dict)  # must not raise


class TestValidateRrsetNoRrsig(unittest.TestCase):
    """Final review M1: validate_rrset must fail closed with ResError -- not a
    TypeError -- when the RRset has no RRSIG. On the ADT delegation-type-proof
    path an attacker can strip the RRSIG from the NSEC; a ResError is caught by
    the per-server loop (try next / terminal reject), whereas a TypeError would
    escape it and abort resolution with a traceback."""

    def test_missing_rrsig_raises_reserror(self):
        name = dns.name.from_text("sub0.deleg.huque.com.")
        nsec_rrset = dns.rrset.from_text_list(
            name, 3600, "IN", "NSEC",
            ["nsec-next.deleg.huque.com. RRSIG TYPE61440"])
        srrset = RRset(name, dns.rdatatype.NSEC, rrset=nsec_rrset)  # rrsig=None
        query = Query(name, "A", "IN", resolver=Resolver())
        with self.assertRaises(ResError):
            lookup.validate_rrset(srrset, query)


class TestProcessReferralAdtGate(unittest.TestCase):
    """Fix round 1: gate-wiring test proving the adt_active conjuncts in
    process_referral are actually applied -- i.e. enforce_adt_proof is only
    called when the resolver itself sent DE=1 (prefs.DELEG), referring_zone
    is non-None, and referring_zone.adt is True (with DNSSEC/secure_so_far/
    not-nsquery already held by defaults). Anti-downgrade enforcement is
    gated on prefs.DELEG because a resolver that did not send DE=1 expects a
    traditional referral and has no delegation-type proof to demand; only
    when it knows it sent DE=1 must it detect a stripped/tampered referral
    (delext Section 8.2.2). _process_ns_referral / _process_deleg_referral
    are stubbed so this isolates the gate, not the dispatch or body."""

    def _resolver(self):
        r = Resolver()
        r.prefs.DELEG = True
        r.prefs.DNSSEC = True
        return r

    def _query(self, resolver):
        return _referral_query(resolver, [_ns_rrset()])

    def _patched(self, adt_mock):
        return (mock.patch.object(lookup, "enforce_adt_proof", adt_mock),
                mock.patch.object(lookup, "_process_ns_referral",
                                  return_value="STUB_ZONE"),
                mock.patch.object(lookup, "_process_deleg_referral",
                                  return_value="STUB_ZONE"))

    def test_called_when_referring_zone_adt_true(self):
        resolver = self._resolver()
        query = self._query(resolver)
        referring_zone = Zone(dns.name.from_text("deleg.huque.com."), resolver)
        referring_zone.adt = True
        adt_mock = mock.Mock()
        p1, p2, p3 = self._patched(adt_mock)
        with p1, p2, p3:
            result = process_referral(query, referring_zone=referring_zone)
        self.assertEqual(result, "STUB_ZONE")
        adt_mock.assert_called_once()

    def test_not_called_when_referring_zone_adt_false(self):
        resolver = self._resolver()
        query = self._query(resolver)
        referring_zone = Zone(dns.name.from_text("deleg.huque.com."), resolver)
        referring_zone.adt = False
        adt_mock = mock.Mock()
        p1, p2, p3 = self._patched(adt_mock)
        with p1, p2, p3:
            process_referral(query, referring_zone=referring_zone)
        adt_mock.assert_not_called()

    def test_not_called_when_referring_zone_is_none(self):
        resolver = self._resolver()
        query = self._query(resolver)
        adt_mock = mock.Mock()
        p1, p2, p3 = self._patched(adt_mock)
        with p1, p2, p3:
            process_referral(query, referring_zone=None)
        adt_mock.assert_not_called()

    def test_not_called_when_prefs_deleg_false(self):
        # The resolver did not send DE=1: even against an ADT zone it expects
        # a traditional referral and must NOT demand a delegation-type proof
        # (delext Section 8.2.2 -- anti-downgrade applies only when DE=1 was
        # sent). An on-path attacker can flip the wire DE bit but cannot
        # change the resolver's local prefs.DELEG.
        resolver = self._resolver()
        resolver.prefs.DELEG = False
        query = self._query(resolver)
        referring_zone = Zone(dns.name.from_text("deleg.huque.com."), resolver)
        referring_zone.adt = True
        adt_mock = mock.Mock()
        p1, p2, p3 = self._patched(adt_mock)
        with p1, p2, p3:
            process_referral(query, referring_zone=referring_zone)
        adt_mock.assert_not_called()


class TestDelegPresentation(unittest.TestCase):

    def test_format_deleg_rrset(self):
        rrset = dns.rrset.RRset(
            dns.name.from_text("sub0.deleg.huque.com."),
            dns.rdataclass.IN, DELEG_RDTYPE)
        blob = bytes.fromhex("00010004c0000201")
        rrset.add(dns.rdata.from_wire(dns.rdataclass.IN, DELEG_RDTYPE,
                                      blob, 0, len(blob)), ttl=3600)
        from reslib.query import format_deleg_rrset
        text = format_deleg_rrset(rrset)
        self.assertIn("server-ipv4=192.0.2.1", text)
        self.assertIn("sub0.deleg.huque.com.", text)


if __name__ == "__main__":
    unittest.main()
