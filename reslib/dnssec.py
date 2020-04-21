"""
DNSSEC functions.
"""

import time
import struct
from io import BytesIO
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.dnssec
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
import nacl.encoding
import nacl.signing

from reslib.rootkey import RootKeyData
from reslib.exception import ResError


# Tolerable clock skew for signatures in seconds
CLOCK_SKEW = 300

# DNSSEC algorithm number -> name
ALG = {
    1: "RSAMD5",
    2: "DSA",
    5: "RSASHA1",
    6: "NSEC3-DSA",
    7: "NSEC3-RSASHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSA-P256",
    14: "ECDSA-P384",
    15: "ED25519",
    16: "ED448",
}

# DNSSEC algorithm -> hash function
HASHFUNC = {
    5: SHA1,
    7: SHA1,
    8: SHA256,
    10: SHA512,
    13: SHA256,
    14: SHA384,
    15: None,
}

# DS (Delegation Signer) Digest Algorithms
DS_ALG = {
    1: SHA1,
    2: SHA256,
    4: SHA384,
}


class KeyCache:
    """
    Zone to DNSSEC Keys mapping class.
    Ideally, we'd store keys in the common global Cache, but separating
    makes it easier to run this library without DNSSEC on platforms do
    not have the required crypto libraries installed.
    """

    def __init__(self):
        # dict of dns.name.Name: list(DNSKEY)
        self.data = {}
        self.SecureSoFar = False
        self.install(dns.name.root, [get_root_key()])

    def install(self, zone, keylist):
        """install (zone -> keylist) into dictionary"""
        self.data[zone] = keylist

    def has_key(self, zone):
        """do we have keys for given zone"""
        return zone in self.data

    def get_keys(self, zone):
        """obtain key list for given zone"""
        if zone in self.data:
            return self.data[zone]
        return None

    def print(self):
        """Print high level contents of keycache"""
        print("### Key Cache:")
        for item in self.data:
            print("{}: {}".format(item, self.data[item]))

    def dump(self):
        """Dump entire cache in summary form"""
        print("#### Key Cache dump")
        for zone in self.data:
            print("ZONE: {}".format(zone))
            for key in self.data[zone]:
                print("      {}".format(key))
        print("#### END: Key Cache dump")


class DNSKEY:
    """Class to hold a DNSKEY and associated information"""

    def __init__(self, rrname, rr):
        self.name = rrname
        self.flags = rr.flags
        self.protocol = rr.protocol
        self.algorithm = rr.algorithm
        self.rawkey = rr.key
        self.keytag = dns.dnssec.key_id(rr)
        self.sep_flag = (self.flags & 0x01) == 0x01
        if self.algorithm in [5, 7, 8, 10]:
            self.key = keydata_to_rsa(rr.key)
        elif self.algorithm in [13, 14]:
            self.key = keydata_to_ecc(self.algorithm, rr.key)
        elif self.algorithm in [15]:
            self.key = keydata_to_eddsa(self.algorithm, rr.key)
        else:
            raise ResError("DNSKEY algorithm {} not supported".format(
                self.algorithm))

    def size(self):
        """Return key size in bits"""
        if isinstance(self.key, RSA.RsaKey):
            return self.key.n.bit_length()
        else:
            return len(self.rawkey) * 8

    def __repr__(self):
        return "DNSKEY: {} {} {} {} ({}) {}-bits".format(
            self.name, self.flags, self.keytag,
            ALG.get(self.algorithm, "Unknown"), self.algorithm, self.size())


class Signature:
    """Signature class"""

    def __init__(self, rrset, sig_rdata, indata):
        self.rrset = rrset
        self.rdata = sig_rdata
        self.indata = indata

    def verify(self, key):
        """
        Verify signature with specified key. Raises a crypto key
        specific exception on failure.
        """
        if isinstance(key, RSA.RsaKey):
            verifier = pkcs1_15.new(key)
            verifier.verify(self.indata, self.rdata.signature)
        elif isinstance(key, ECC.EccKey):
            verifier = DSS.new(key, 'fips-186-3')
            verifier.verify(self.indata, self.rdata.signature)
        elif isinstance(key, nacl.signing.VerifyKey):
            _ = key.verify(self.indata, self.rdata.signature)
        else:
            raise ResError("Unknown key type: {}".format(type(key)))

    def check_time(self, skew=CLOCK_SKEW):
        """
        Check that current time is within signature validity period,
        modulo an allowable clock skew interval.
        """
        current_time = int(time.time() + 0.5)
        if current_time < (self.rdata.inception - skew):
            raise ResError("Signature inception too far in the future")
        if current_time > (self.rdata.expiration + skew):
            raise ResError("Signature has expired")

    def __repr__(self):
        return "<Signature: {}/{}/{} {} {}>".format(
            self.rrset.name, self.rrset.rdtype, self.rrset.rdclass,
            self.rdata.key_tag, self.rdata.algorithm)


def get_root_key():
    """Get root key/trust anchor"""
    rdata = dns.rdata.from_text(dns.rdataclass.from_text('IN'),
                                dns.rdatatype.from_text('DNSKEY'),
                                RootKeyData)
    return DNSKEY(dns.name.root, rdata)


def _to_wire(record):
    s = BytesIO()
    record.to_wire(s)
    return s.getvalue()


def keydata_to_rsa(keydata):
    """Convert raw keydata into an RSA key object"""
    if keydata[0] == '\x00':   # exponent field is 3 octets
        elen, = struct.unpack('!H', keydata[1:3])
    else:                     # exponent field is 1 octet
        elen, = struct.unpack('B', keydata[0:1])
    exponent = int.from_bytes(keydata[1:1+elen], byteorder='big')
    modulus = keydata[1+elen:]
    modulus_len = len(modulus) * 8
    modulus_int = int.from_bytes(modulus, byteorder='big')
    return RSA.construct((modulus_int, exponent))


def keydata_to_ecc(algnum, keydata):
    """Convert raw keydata into an ECC key object"""
    if algnum == 13:
        point_length = 32
        curve = 'p256'
    elif algnum == 14:
        point_length = 48
        curve = 'p384'
    else:
        raise ResError("Invalid algorithm number {} for ECDSA".format(algnum))
    x = int.from_bytes(keydata[0:point_length], byteorder='big')
    y = int.from_bytes(keydata[point_length:], byteorder='big')
    return ECC.construct(curve=curve, point_x=x, point_y=y)


def keydata_to_eddsa(algnum, keydata):
    """Convert raw keydata into an EdDSA key object"""
    if algnum == 15:
        return nacl.signing.VerifyKey(keydata)
    else:
        raise ResError("Unknown EdDSA algorithm number {}".format(algnum))


def load_keys(rrset):
    """
    return list of DNSKEY class objects from the given DNSKEY RRset
    parameters (name, keytag, algorithm, key object)
    """
    result = []
    for rr in rrset:
        result.append(DNSKEY(rrset.name, rr))
    return result


def get_sig_info(rrset, rrsigs):

    """
    For given rrset and rrsig set, for each rrsig, return a Signature
    object, yielding them one at a time. The Signature object, contains
    the rrset, rrsig rdata, and the calculated input for the signature
    algorithm in question.

    From RFC4034, Section 3.1.8.1, the signature input data is:
    (RRSIG_RDATA | RR(1) | RR(2)... ), where RRSIG_RDATA is the rdata
    minus the actual signature field. This input is then hashed for
    most signature algorithms with the hash algorithm defined for that
    algorithm, except for EdDSA (as used in DNSSEC) which just uses the
    raw data as input.
    """

    for sig_rdata in rrsigs.to_rdataset():
        indata = b''
        indata += _to_wire(sig_rdata)[0:18]
        indata += sig_rdata.signer.to_digestable()
        rrname = rrset.name
        if sig_rdata.labels < len(rrname) - 1:
            labels = (b'*',) + rrname.labels[-(sig_rdata.labels+1):]
            rrname = dns.name.Name(labels)
        rrname_wire = rrname.to_digestable()
        rrtype_wire = struct.pack('!H', rrset.rdtype)
        rrclass_wire = struct.pack('!H', rrset.rdclass)
        origttl_wire = struct.pack('!I', sig_rdata.original_ttl)
        for rr in sorted(rrset.to_rdataset()):
            indata += (rrname_wire + rrtype_wire + rrclass_wire + origttl_wire)
            rrdata = rr.to_digestable()
            rrlen = struct.pack('!H', len(rrdata))
            indata += (rrlen + rrdata)
        if HASHFUNC[sig_rdata.algorithm] is not None:
            hashed = HASHFUNC[sig_rdata.algorithm].new()
            hashed.update(indata)
            yield Signature(rrset, sig_rdata, hashed)
        else:
            yield Signature(rrset, sig_rdata, indata)


def sigset_covers_rrset(sigset, rrset):
    """does RRSIG set cover the RR set?"""
    return (sigset.name == rrset.name) and (sigset.covers == rrset.rdtype)


def verify_sig_with_keys(sig, keys):
    """
    Verify signature object against given list of DNSKEYs.
    Return 2 lists of keys that verified, and that failed.
    """

    Verified = []
    Failed = []

    for key in keys:
        if key.keytag != sig.rdata.key_tag:
            continue
        try:
            sig.verify(key.key)
            sig.check_time()
        except Exception as e:
            Failed.append((key, e))
        else:
            Verified.append(key)

    return Verified, Failed


def check_self_signature(rrset, rrsigs):
    """
    Check self signature of DNSKEY rrset. Raises exception on failure.
    Returns list of DNSKEY keys in the rrset, and the list of the subset
    of those keys that verifiably sign the DNSKEY rrset.
    """

    Verified = []
    keys = load_keys(rrset)

    for sig in get_sig_info(rrset, rrsigs):
        v, _ = verify_sig_with_keys(sig, keys)
        Verified += v

    if not Verified:
        raise ResError("DNSKEY self signature failed to validate: {}".format(
            rrset.name))

    return keys, Verified


def validate_all(rrset, rrsigs):
    """
    Validate rrsigs for rrset with the already authenticated global cache
    of keys in key_cache. Returns 2 lists of keys: Verified and Failed.
    Failed also includes verification errors.
    """

    Verified = []
    Failed = []

    for sig in get_sig_info(rrset, rrsigs):
        keylist = key_cache.get_keys(sig.rdata.signer)
        if keylist is None:
            raise ResError("No DNSSEC keys found for {}".format(
                sig.rdata.signer))
        v, f = verify_sig_with_keys(sig, keylist)
        Verified += v
        Failed += f

    return Verified, Failed


def ds_rrset_matches_dnskey(ds_list, dnskey):
    """
    Check that DS RRset includes at least one DS record whose digest
    field corresponds to the DNSKEY.
    ds_ digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    """

    preimage = (dnskey.name.to_digestable() +
                struct.pack('!H', dnskey.flags) +
                struct.pack('B', dnskey.protocol) +
                struct.pack('B', dnskey.algorithm) +
                dnskey.rawkey)
    for ds in ds_list:
        if ds.key_tag != dnskey.keytag:
            continue
        if ds.algorithm != dnskey.algorithm:
            continue
        if ds.digest_type not in DS_ALG:
            continue
        hashout = DS_ALG[ds.digest_type].new(data=preimage)
        if hashout.digest() == ds.digest:
            return True
    return False


# Instantiate key cache at module level
key_cache = KeyCache()
