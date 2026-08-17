"""
ML-DSA-44 (DNSSEC algorithm 18) support.

Quarantines the optional `cryptography` ML-DSA dependency. The import is
lazy so that hosts whose `cryptography` build lacks ML-DSA can still
validate every other DNSSEC algorithm. DNSSEC uses "pure" ML-DSA with an
empty signing context (context=None).
"""

_available = None


def available():
    """
    Return True if this host's cryptography build can verify ML-DSA-44.
    Result is probed once and cached.
    """
    global _available
    if _available is None:
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            _available = hasattr(mldsa, "MLDSA44PublicKey")
        except (ImportError, AttributeError):
            _available = False
    return _available


def load_public_key(raw):
    """
    Build an MLDSA44 public key object from the raw 1312-octet DNSKEY key
    field. Raises ValueError if the length is wrong.
    """
    from cryptography.hazmat.primitives.asymmetric import mldsa
    return mldsa.MLDSA44PublicKey.from_public_bytes(raw)


def verify(pubkey, signature, data):
    """
    Verify an ML-DSA-44 signature over data with the given public key
    object. Raises cryptography.exceptions.InvalidSignature on failure.
    context=None is the DNSSEC-mandated empty context.
    """
    pubkey.verify(signature, data, context=None)
