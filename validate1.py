#!/usr/bin/env python3
#

"""
Testing DNSSEC signature validation.
for details: RFC 4034, Section 3.1.8.1.  Signature Calculation
TODO:
     - Check signature validity time
"""

import sys
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


# DNSSEC algorithm -> hash function
HASHFUNC = {
    5: SHA1,
    7: SHA1,
    8: SHA256,
    10: SHA512,
    13: SHA256,
    14: SHA384,
}


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
    rrset = msg.get_rrset(msg.answer,
                          qname,
                          1,
                          qtype)
    rrsigs = msg.get_rrset(msg.answer,
                           qname,
                           1,
                           dns.rdatatype.RRSIG,
                           covers=qtype)
    return rrset, rrsigs


def load_keys(rrset):
    """return list of DNSKEY parameters from the given DNSKEY RRset"""

    result = []
    for rr in rrset:
        print(rrset.name, rr.flags, rr.protocol, rr.algorithm)
        if rr.algorithm in [5, 7, 8, 10]:
            key = keydata_to_rsa(rr.key)
        elif rr.algorithm in [13, 14]:
            key = keydata_to_ecc(rr.algorithm, rr.key)
        else:
            print("Can't decode key of algorithm {} yet.".format(rr.algorithm))
            continue
        print(key)
        result.append((rrset.name, key))
    return result

    
def get_sig_hashes(rrset, rrsigs):

    """
    For given rrset and rrsig set, calculate the signature hash to be
    verified for each signature in the rrsig set. Yield one at a time.
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
            # wildcard
            suffix = rrname.split(sig_rdata.labels + 1)[1]
            rrname = dns.name.from_text('*', suffix)
        rrname_wire = rrname.to_digestable()
        rrtype_wire = struct.pack('!H', rrset.rdtype)
        rrclass_wire = struct.pack('!H', rrset.rdclass)
        origttl_wire = struct.pack('!I', sig_rdata.original_ttl)
        for rr in sorted(soa_rrset.to_rdataset()):
            h.update(rrname_wire + rrtype_wire + rrclass_wire + origttl_wire)
            rrdata = rr.to_digestable()
            rrlen = struct.pack('!H', len(rrdata))
            h.update(rrlen + rrdata)
        yield h, signature


qname = dns.name.from_text(sys.argv[1])
qtype = dns.rdatatype.from_text('SOA')

r = get_resolver(dnssec_ok=True)
soa_rrset, soa_rrsigs = get_rrset(r, qname, qtype)
dnskey_rrset, _ = get_rrset(r, qname, dns.rdatatype.from_text('DNSKEY'))
DNSSEC_KEYS = load_keys(dnskey_rrset)

Verified = False

for h, signature in get_sig_hashes(soa_rrset, soa_rrsigs):

    for keyname, key in DNSSEC_KEYS:
        print(keyname, type(key))
        if isinstance(key, RSA.RsaKey):
            verifier = pkcs1_15.new(key)
            try:
                verifier.verify(h, signature)
            except ValueError:
                pass
            else:
                Verified = True
                break
        elif isinstance(key, ECC.EccKey):
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(h, signature)
            except ValueError:
                pass
            else:
                Verified = True
                break
    else:
        print("ERROR: Signature did note verify (which one?)")

if Verified:
    print("OK: Signature Verified")

