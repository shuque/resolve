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

from reslib.root import ROOTHINTS, RootKeyData
from reslib.common import Prefs, RootZone
from reslib.query import Query
from reslib.lookup import send_query_zone


# Tolerable clock skew for signatures in seconds
CLOCK_SKEW = 300

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


class KeyCache:
    """
    Zone to DNSSEC Keys mapping class.
    Ideally, we'd store keys in the common global Cache, but separating
    makes it easier to run this library without DNSSEC on platforms do
    not have the required crypto libraries installed.
    """

    def __init__(self):
        # dict of dns.name.Name: list(DNSKEYinfo)
        self.data = {}
        self.install(dns.name.root, [get_root_key()])

    def install(self, zone, keylist):
        """install (zone -> keylist) into dictionary"""
        self.data[zone] = keylist

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


class DNSKEYinfo:
    """Class to hold a DNSKEY and associated information"""

    def __init__(self, rrname, rr):
        self.name = rrname
        self.flags = rr.flags
        self.algorithm = rr.algorithm
        self.keytag = dns.dnssec.key_id(rr)
        if self.algorithm in [5, 7, 8, 10]:
            self.key = keydata_to_rsa(rr.key)
        elif self.algorithm in [13, 14]:
            self.key = keydata_to_ecc(self.algorithm, rr.key)
        elif self.algorithm in [15]:
            self.key = keydata_to_eddsa(self.algorithm, rr.key)
        else:
            raise ValueError("DNSKEY algorithm {} not supported".format(
                self.algorithm))

    def __repr__(self):
        return "<DNSKEYinfo: {} {} {} {}>".format(
            self.name, self.flags, self.keytag, self.algorithm)


def get_root_key():
    """Get root key/trust anchor"""
    rdata = dns.rdata.from_text(dns.rdataclass.from_text('IN'),
                                dns.rdatatype.from_text('DNSKEY'),
                                RootKeyData)
    return DNSKEYinfo(dns.name.root, rdata)


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
        raise ValueError("Invalid algorithm number {} for ECDSA".format(algnum))
    x = int.from_bytes(keydata[0:point_length], byteorder='big')
    y = int.from_bytes(keydata[point_length:], byteorder='big')
    return ECC.construct(curve=curve, point_x=x, point_y=y)


def keydata_to_eddsa(algnum, keydata):
    """Convert raw keydata into an EdDSA key object"""
    if algnum == 15:
        return nacl.signing.VerifyKey(keydata)
    else:
        raise ValueError("Unknown EdDSA algorithm number {}".format(algnum))


def load_keys(rrset):
    """
    return list of DNSKEYinfo class objects from the given DNSKEY RRset
    parameters (name, keytag, algorithm, key object)
    """

    result = []
    for rr in rrset:
        result.append(DNSKEYinfo(rrset.name, rr))
    return result


def get_sig_inputs(rrset, rrsigs):

    """
    For given rrset and rrsig set, calculate the signature input for
    for each signature in the rrsig set. Yield one at a time.
    From RFC4034, this is: hash(RRSIG_RDATA | RR(1) | RR(2)... ), where
    RRSIG_RDATA is the rdata minus the actual signature field. However,
    note that EdDSA (as used in DNSSEC) does not use a hash function, so
    just the raw wire format data is the signature input.
    """

    rrname = rrset.name

    for sig_rdata in rrsigs.to_rdataset():
        indata = b''
        signature = sig_rdata.signature
        wire_sig_rdata = _to_wire(sig_rdata)
        indata += wire_sig_rdata[0:18]
        indata += sig_rdata.signer.to_digestable()
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
            yield hashed, signature, sig_rdata
        else:
            yield indata, signature, sig_rdata


def check_time(sig_rdata, skew=CLOCK_SKEW):
    """
    Check that current time is within signature validity period,
    modulo an allowable clock skew interval.
    """
    current_time = int(time.time() + 0.5)
    if current_time < (sig_rdata.inception - skew):
        raise ValueError("Signature inception too far in the future")
    if current_time > (sig_rdata.expiration + skew):
        raise ValueError("Signature has expired")


def sig_covers_rrset(sigset, rrset):
    """does RRSIG set cover the RR set?"""
    return (sigset.name == rrset.name) and (sigset.covers == rrset.rdtype)


def verify_sig(key, sig_input, signature):
    """verify signature on data with given algorithm"""

    if isinstance(key, RSA.RsaKey):
        verifier = pkcs1_15.new(key)
        verifier.verify(sig_input, signature)
    elif isinstance(key, ECC.EccKey):
        verifier = DSS.new(key, 'fips-186-3')
        verifier.verify(sig_input, signature)
    elif isinstance(key, nacl.signing.VerifyKey):
        _ = key.verify(sig_input, signature)
    else:
        raise ValueError("Unknown key type: {}".format(type(key)))
    return


def validate_all(rrset, rrsigs, dnskey_list):
    """
    Validate rrsigs for rrset with list of dnskeys.
    Returns 2 lists of keys: Verified and Failed. Failed also
    includes verification errors.
    """

    if not sig_covers_rrset(rrsigs, rrset):
        raise ValueError("Signature doesn't correspond to RRset")

    Verified = []                     # list of (key)
    Failed = []                       # list of (key, error)

    for sig_input, signature, sig_rdata in get_sig_inputs(rrset, rrsigs):
        for keyinfo in dnskey_list:
            if keyinfo.keytag != sig_rdata.key_tag:
                continue
            try:
                verify_sig(keyinfo.key, sig_input, signature)
                check_time(sig_rdata)
            except Exception as e:
                Failed.append((keyinfo, e))
            else:
                Verified.append(keyinfo)

    return Verified, Failed


# Instantiate key cache at module level
key_cache = KeyCache()


def get_root_keyset():
    """
    Query root DNSKEY RRset, authenticate it with current trust
    anchor and install the authenticated set in the KeyCache.
    """

    if not Prefs.DNSSEC:
        raise ValueError("DNSSEC Preference is not set")

    qname = dns.name.root
    qtype = dns.rdatatype.from_text('DNSKEY')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass)
    query.set_quiet(True)

    msg = send_query_zone(query, RootZone)
    dnskey_rrset = msg.get_rrset(msg.answer, qname, 1, qtype)
    dnskey_rrsigs = msg.get_rrset(msg.answer, qname, 1,
                                  dns.rdatatype.RRSIG, covers=qtype)

    if dnskey_rrsigs is None:
        raise ValueError("No signatures found for root DNSKEY set!")

    verified, failed = validate_all(dnskey_rrset, dnskey_rrsigs,
                                    key_cache.get_keys(dns.name.root))
    if not verified:
        raise ValueError("Couldn't validate root DNSKEY RRset: {}".format(
            failed))

    key_cache.install(dns.name.root, load_keys(dnskey_rrset))
    return
