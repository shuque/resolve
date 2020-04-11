
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
import nacl.encoding
import nacl.signing


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
        elif self.algorithm in [15]:
            self.key = keydata_to_eddsa(self.algorithm, rr.key)
        else:
            raise ValueError("DNSKEY algorithm {} not supported".format(
                self.algorithm))


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


def keydata_to_eddsa(algnum, keydata):
    if algnum == 15:
        return nacl.signing.VerifyKey(keydata)
    else:
        raise ValueError("Unknown EdDSA algorithm number {}".format(algnum))


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


