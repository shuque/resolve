#!/usr/bin/env python3
#

"""
Testing DNSSEC signature validation.
for details: RFC 4034, Section 3.1.8.1.  Signature Calculation

Given a zone name, query its SOA RRset, and verify the SOA signature
against the apex DNSKEY RRset.

TODO:
     - raise error if we don't have proper crypto library version
     - test suite to excercise misc error conditions.
     - generalized DNSSEC key dict for many names.
"""

import sys
import time
import struct
from io import BytesIO
import dns.resolver
import dns.rcode
import dns.rdatatype
import dns.flags
import dns.dnssec
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA1, SHA256, SHA384, SHA512


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
}


class DNSKEYinfo:

    def __init__(self, rrname, rr):
        self.name = rrname
        self.flags = rr.flags
        self.algorithm = rr.algorithm
        self.keytag = dns.dnssec.key_id(rr)
        if self.algorithm in [5, 7, 8, 10]:
            self.key = keydata_to_rsa(rr.key)
        elif self.algorithm in [13, 14]:
            self.key = keydata_to_ecc(self.algorithm, rr.key)
        else:
            raise ValueError("DNSKEY algorithm {} not supported".format(
                self.algorithm))


def get_resolver(dnssec_ok=False, timeout=5):
    """return an appropriately configured Resolver object"""
    r = dns.resolver.Resolver()
    # Set query flags to RD=1, AD=1, CD=1
    #r.set_flags(0x0130)                      # binary 0000 0001 0011 0000
    r.lifetime = timeout
    if dnssec_ok:
        r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
    return r


def _to_wire(record):
    s = BytesIO()
    record.to_wire(s)
    return s.getvalue()


def keydata_to_rsa(keydata):
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


def get_rrset(resolver, qname, qtype):
    """
    Query name and type; return answer RRset and signature RRset.
    """
    msg = resolver.query(qname, qtype).response
    rrset = msg.get_rrset(msg.answer, qname, 1, qtype)
    rrsigs = msg.get_rrset(msg.answer, qname, 1,
                           dns.rdatatype.RRSIG, covers=qtype)
    return rrset, rrsigs


def load_keys(rrset):
    """
    return list of DNSKEYinfo class objects from the given DNSKEY RRset
    parameters (name, keytag, algorithm, key object)
    """

    result = []
    for rr in rrset:
        result.append(DNSKEYinfo(rrset.name, rr))
    return result

    
def get_sig_hashes(rrset, rrsigs):

    """
    For given rrset and rrsig set, calculate the signature hash to be
    verified for each signature in the rrsig set. Yield one at a time.
    From RFC4034, this is: hash(RRSIG_RDATA | RR(1) | RR(2)... ), where
    RRSIG_RDATA is the rdata minus the actual signature field.
    """

    rrname = rrset.name

    for sig_rdata in rrsigs.to_rdataset():
        alg = sig_rdata.algorithm
        signature = sig_rdata.signature
        wire_sig_rdata = _to_wire(sig_rdata)
        h = HASHFUNC[alg].new()
        h.update(wire_sig_rdata[0:18])                # RRSIG rdata upto signer
        h.update(sig_rdata.signer.to_digestable())    # RRSIG rdata signer
        if sig_rdata.labels < len(rrname) - 1:
            # construct wildcard name
            labels = (b'*',) + rrname.labels[-(sig_rdata.labels+1):]
            rrname = dns.name.Name(labels)
        rrname_wire = rrname.to_digestable()
        rrtype_wire = struct.pack('!H', rrset.rdtype)
        rrclass_wire = struct.pack('!H', rrset.rdclass)
        origttl_wire = struct.pack('!I', sig_rdata.original_ttl)
        for rr in sorted(soa_rrset.to_rdataset()):
            h.update(rrname_wire + rrtype_wire + rrclass_wire + origttl_wire)
            rrdata = rr.to_digestable()
            rrlen = struct.pack('!H', len(rrdata))
            h.update(rrlen + rrdata)
        yield h, signature, sig_rdata


def check_time(sig_rdata, skew=CLOCK_SKEW):
    """
    Check that current time is within signature validity period, plus
    minus an acceptable clock skew.
    """

    current_time = int(time.time() + 0.5)
    ok1 = (current_time >= sig_rdata.inception) or \
        (abs(sig_rdata.inception - current_time) <= skew)
    ok2 = (current_time <= sig_rdata.expiration) or \
        (abs(current_time - sig_rdata.expiration) <= skew)
    if ok1 and ok2:
        return
    raise ValueError("Error: Signature validity time is invalid")


def sig_covers_rrset(sigset, rrset):
    """does RRSIG set cover the RR set?"""
    return (sigset.name == rrset.name) and (sigset.covers == rrset.rdtype)


def validate(rrset, rrsigs, dnskey_list):
    """
    validate given rrset signatures in 'rrsigs' against the list
    of dnskey parameters.
    Returns Verify result + list of verification data.
    """

    if not sig_covers_rrset(rrsigs, rrset):
        raise ValueError("Signature doesn't correspond to RRset")

    Verified = False
    verified_list = []                # list of (keytag, algo)

    for h, signature, sig_rdata in get_sig_hashes(rrset, rrsigs):

        for keyinfo in DNSSEC_KEYS:
            if isinstance(keyinfo.key, RSA.RsaKey):
                verifier = pkcs1_15.new(keyinfo.key)
            elif isinstance(keyinfo.key, ECC.EccKey):
                verifier = DSS.new(keyinfo.key, 'fips-186-3')
            else:
                raise ValueError("Unknown key type")
            try:
                verifier.verify(h, signature)
                check_time(sig_rdata)
            except ValueError:
                pass
            else:
                Verified = True
                verified_list.append(keyinfo)

    return Verified, verified_list


if __name__ == '__main__':


    qname = dns.name.from_text(sys.argv[1])
    qtype = dns.rdatatype.from_text('SOA')

    r = get_resolver(dnssec_ok=True)
    soa_rrset, soa_rrsigs = get_rrset(r, qname, qtype)
    print(soa_rrset)
    if soa_rrsigs is None:
        print("No signatures found.")
        sys.exit(1)

    print("Found {} signature{}.".format(
        len(soa_rrsigs), "" if len(soa_rrsigs) == 1 else "s"))
    print('')

    dnskey_rrset, _ = get_rrset(r, qname, dns.rdatatype.from_text('DNSKEY'))
    DNSSEC_KEYS = load_keys(dnskey_rrset)
    for keyinfo in DNSSEC_KEYS:
        print("DNSKEY: {} {} {} {}".format(
            keyinfo.name, keyinfo.flags, keyinfo.keytag, keyinfo.algorithm))
    print('')

    valid, valid_info = validate(soa_rrset, soa_rrsigs, DNSSEC_KEYS)
    if valid:
        print("OK: Signature Verified")
        for keyinfo in valid_info:
            print("    Good signature with keytag={} algo={}".format(
                keyinfo.keytag, keyinfo.algorithm))
        sys.exit(0)
    else:
        print("FAIL: No Signature Verified with any DNSKEY")
        sys.exit(1)

