"""
Unit tests for reslib.mldsa (ML-DSA-44 / DNSSEC algorithm 18 support).
Offline and deterministic; the signing round-trip is skipped when the
host's cryptography build lacks ML-DSA.
"""

import unittest

from reslib import mldsa


class TestMldsaModule(unittest.TestCase):

    def test_available_returns_bool(self):
        self.assertIsInstance(mldsa.available(), bool)

    def test_available_is_cached(self):
        self.assertEqual(mldsa.available(), mldsa.available())

    @unittest.skipUnless(mldsa.available(), "cryptography ML-DSA not available")
    def test_public_key_raw_is_1312_octets(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa as _m
        priv = _m.MLDSA44PrivateKey.generate()
        self.assertEqual(len(priv.public_key().public_bytes_raw()), 1312)

    @unittest.skipUnless(mldsa.available(), "cryptography ML-DSA not available")
    def test_verify_roundtrip_ok(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa as _m
        priv = _m.MLDSA44PrivateKey.generate()
        raw = priv.public_key().public_bytes_raw()
        data = b"the data to be signed"
        sig = priv.sign(data)
        pub = mldsa.load_public_key(raw)
        # Must not raise:
        self.assertIsNone(mldsa.verify(pub, sig, data))

    @unittest.skipUnless(mldsa.available(), "cryptography ML-DSA not available")
    def test_verify_rejects_tampered_data(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import mldsa as _m
        priv = _m.MLDSA44PrivateKey.generate()
        pub = mldsa.load_public_key(priv.public_key().public_bytes_raw())
        sig = priv.sign(b"original data")
        with self.assertRaises(InvalidSignature):
            mldsa.verify(pub, sig, b"tampered data")

    @unittest.skipUnless(mldsa.available(), "cryptography ML-DSA not available")
    def test_load_public_key_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            mldsa.load_public_key(b"\x01" * 100)


if __name__ == "__main__":
    unittest.main()
