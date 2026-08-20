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


if __name__ == "__main__":
    unittest.main()
