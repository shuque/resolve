"""Unit tests for the DELEG DelegInfos codec (reslib/deleg.py)."""

import unittest

import dns.name

from reslib.deleg import (
    parse_deleginfos, DelegParseError, DelegInfo,
    DELEG_RDTYPE, DELEGPARAM_RDTYPE, EDNS_DE_FLAG, format_deleginfo,
)


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


if __name__ == "__main__":
    unittest.main()
