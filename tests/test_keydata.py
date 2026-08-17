"""
Unit tests for RSA DNSKEY key-material parsing in reslib.dnssec.
Offline and deterministic; no network.

The 3-octet exponent-length case guards against regression of the bug
where the branch test compared a bytes element (an int) to the str
'\\x00', which is always False and left the 3-octet form unparsed.
"""

import struct
import unittest
from unittest import mock

import dns.rrset

from reslib.dnssec import keydata_to_rsa, load_keys
from reslib.rootkey import KSK_2017


class TestKeydataToRsaExponentDecode(unittest.TestCase):
    """
    Exercise both RFC 3110 exponent-length encodings by capturing the
    (exponent, modulus) passed to RSAPublicNumbers, so no real key
    construction / validation is needed.
    """

    def parse(self, keydata):
        with mock.patch("reslib.dnssec.rsa.RSAPublicNumbers") as rpn:
            rpn.return_value.public_key.return_value = "PUBKEY"
            result = keydata_to_rsa(keydata)
        self.assertEqual(result, "PUBKEY")
        args, _ = rpn.call_args
        return args  # (exponent, modulus_int)

    def test_one_octet_exponent_length(self):
        # elen in a single leading octet: 0x03, then e=65537, then modulus.
        modulus = b"\xAB" * 16
        keydata = bytes([3]) + (65537).to_bytes(3, "big") + modulus
        exponent, modulus_int = self.parse(keydata)
        self.assertEqual(exponent, 65537)
        self.assertEqual(modulus_int, int.from_bytes(modulus, "big"))

    def test_three_octet_exponent_length(self):
        # Leading octet 0x00 signals a 2-octet length field follows.
        # Use a >255-byte exponent so this encoding is the correct one.
        elen = 300
        exp_bytes = (2 ** 2399 + 1).to_bytes(elen, "big")
        modulus = b"\xCD" * 20
        keydata = b"\x00" + struct.pack("!H", elen) + exp_bytes + modulus
        exponent, modulus_int = self.parse(keydata)
        self.assertEqual(exponent, int.from_bytes(exp_bytes, "big"))
        self.assertEqual(modulus_int, int.from_bytes(modulus, "big"))


class TestRealRootKskParse(unittest.TestCase):
    """Known-answer test: parse the live root KSK-2017 (RSA/alg 8)."""

    def test_ksk_2017_parses_to_rsa_2048_e65537(self):
        rrset = dns.rrset.from_text(".", 3600, "IN", "DNSKEY", KSK_2017)
        keys, errors = load_keys(rrset)
        self.assertEqual(errors, [])
        self.assertEqual(len(keys), 1)
        key = keys[0]
        self.assertEqual(key.algorithm, 8)
        self.assertEqual(key.keytag, 20326)
        pubnum = key.key.public_numbers()
        self.assertEqual(pubnum.e, 65537)
        self.assertEqual(pubnum.n.bit_length(), 2048)


if __name__ == "__main__":
    unittest.main()
