"""
DNSSEC functions.
"""

import time
import math
import base64
import struct
from io import BytesIO
import dns.name
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.dnssec

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import rsa

from reslib.prefs import Prefs
from reslib.rootkey import RootKeyData
from reslib.exception import ResError


# Tolerable clock skew for signatures in seconds
CLOCK_SKEW = 300

# Maximum number of keytag collisions we honor
MAX_KEYTAG_COLLISIONS = 4

# DNSSEC algorithm number -> name
ALG = {
    5: "RSASHA1",
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
    5: hashes.SHA1,
    7: hashes.SHA1,
    8: hashes.SHA256,
    10: hashes.SHA512,
    13: hashes.SHA256,
    14: hashes.SHA384,
    15: None,
    16: None,
}

# DS (Delegation Signer) Digest Algorithms
DS_ALG = {
    1: hashes.SHA1,
    2: hashes.SHA256,
    4: hashes.SHA384,
}


def supported_algorithm_present(dslist):
    """
    Does given DS list have at least one algorithm that we support?
    """

    alglist = ALG.keys()

    for ds in dslist:
        if ds.rdata.algorithm in alglist:
            return True
    return False


class KeyCache:
    """
    Zone to DNSSEC Keys mapping class.
    Ideally, we'd store keys in the common global Cache, but separating
    makes it easier to run this library without DNSSEC on platforms do
    not have the required crypto libraries installed.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """reset cache and security status"""
        self.data = {}                  # dict of dns.name.Name: list(DNSKEY)
        self.SecureSoFar = False
        self.RootTA = get_root_key()    # DNSKEY object
        self.install(dns.name.root, [self.RootTA])

    def install(self, zone, keylist):
        """install (zone -> keylist) into dictionary"""
        self.data[zone] = [k for k in keylist if not k.revoke_flag]

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
    """Class to hold a single DNSKEY and associated information"""

    def __init__(self, rrname, rr):
        self.name = rrname
        self.flags = rr.flags
        self.protocol = rr.protocol
        self.algorithm = rr.algorithm
        self.rawkey = rr.key
        self.keytag = dns.dnssec.key_id(rr)
        self.sep_flag = (self.flags & 0x01) == 0x01
        self.zone_flag = (self.flags & 0x0100) == 0x0100
        self.revoke_flag = (self.flags & 0x0080) == 0x0080
        if not self.rawkey:
            raise ResError("DNSKEY keytag={} alg={} has null length data".format(
                self.keytag, self.algorithm))
        if self.algorithm in [5, 7, 8, 10]:
            self.key = keydata_to_rsa(rr.key)
        elif self.algorithm in [13, 14]:
            self.key = keydata_to_ecc(self.algorithm, rr.key)
        elif self.algorithm in [15, 16]:
            self.key = keydata_to_eddsa(self.algorithm, rr.key)
        else:
            raise ResError("DNSKEY algorithm {} not supported".format(
                self.algorithm))

    def size(self):
        """Return key size in bits"""
        if self.algorithm in [5, 7, 8, 10]:
            return self.key.public_numbers().n.bit_length()
        return len(self.rawkey) * 8

    def __repr__(self):
        flags_text = ''
        if self.zone_flag:
            flags_text += " ZONE"
        if self.sep_flag:
            flags_text += " SEP"
        if self.revoke_flag:
            flags_text += " REV"
        return "DNSKEY: {} {} {} {} ({}) {}-bits{}".format(
            self.name, self.flags, self.keytag,
            ALG.get(self.algorithm, "Unknown"), self.algorithm,
            self.size(), flags_text)


class Signature:
    """Signature class"""

    def __init__(self, rrset, sig_rdata, indata):
        self.rrset = rrset
        self.rdata = sig_rdata
        self.indata = indata

    def verify(self, dnskey):
        """
        Verify signature with specified key. Raises a crypto key
        specific exception on failure.
        """
        pubkey = dnskey.key
        hashalg = HASHFUNC[dnskey.algorithm]
        if dnskey.algorithm in [5, 7, 8, 10]:
            _ = pubkey.verify(self.rdata.signature, self.indata,
                              padding.PKCS1v15(), hashalg())
        elif dnskey.algorithm in [13, 14]:
            if dnskey.algorithm == 13:
                sig_r = self.rdata.signature[0:32]
                sig_s = self.rdata.signature[32:]
            elif dnskey.algorithm == 14:
                sig_r = self.rdata.signature[0:48]
                sig_s = self.rdata.signature[48:]
            sig_r = int.from_bytes(sig_r, byteorder='big')
            sig_s = int.from_bytes(sig_s, byteorder='big')
            encoded_sig = utils.encode_dss_signature(sig_r, sig_s)
            _ = pubkey.verify(encoded_sig, self.indata, ec.ECDSA(hashalg()))
        elif dnskey.algorithm in [15, 16]:
            _ = pubkey.verify(self.rdata.signature, self.indata)
        else:
            raise ResError("Unknown key type: {}".format(type(pubkey)))

    def check_time(self, skew=CLOCK_SKEW):
        """
        Check that current time is within signature validity period,
        modulo an allowable clock skew interval.
        """
        current_time = int(time.time() + 0.5)
        if current_time < (self.rdata.inception - skew):
            raise ResError("Signature inception in future: {}".format(
                time.asctime(time.gmtime(self.rdata.inception))))
        if current_time > (self.rdata.expiration + skew):
            raise ResError("Signature has expired: {}".format(
                time.asctime(time.gmtime(self.rdata.expiration))))

    def __repr__(self):
        return "<Signature: {}/{}/{} {} {}>".format(
            self.rrset.name, self.rrset.rdtype, self.rrset.rdclass,
            self.rdata.key_tag, self.rdata.algorithm)


def duration2string(duration):
    """
    Return time duration in human readable string form.
    """
    days, remainder = divmod(duration, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, remainder = divmod(remainder, 60)
    return "{}d{}h{}m{}s".format(days, hours, minutes, remainder)


def sig_validity(sig_rr):
    """
    Return length of signature validity period for given RRSIG RR.
    """
    duration = sig_rr.expiration - sig_rr.inception
    return duration2string(duration)


def sig_expires_in(sig_rr):
    """
    Return time to expiry of given RRSIG RR.
    """
    duration = sig_rr.expiration - math.floor(time.time() + 0.5)
    return duration2string(duration)


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
    modulus_int = int.from_bytes(modulus, byteorder='big')
    return rsa.RSAPublicNumbers(exponent,
                                modulus_int).public_key(default_backend())


def keydata_to_ecc(algnum, keydata):
    """Convert raw keydata into an ECC key object"""
    if algnum == 13:
        point_length = 32
        curve = ec.SECP256R1()
    elif algnum == 14:
        point_length = 48
        curve = ec.SECP384R1()
    else:
        raise ResError("Invalid algorithm number {} for ECDSA".format(algnum))
    x = int.from_bytes(keydata[0:point_length], byteorder='big')
    y = int.from_bytes(keydata[point_length:], byteorder='big')
    return ec.EllipticCurvePublicNumbers(
        curve=curve, x=x, y=y).public_key(default_backend())


def keydata_to_eddsa(algnum, keydata):
    """Convert raw keydata into an EdDSA key object"""
    if algnum == 15:
        return ed25519.Ed25519PublicKey.from_public_bytes(keydata)
    if algnum == 16:
        return ed448.Ed448PublicKey.from_public_bytes(keydata)
    raise ResError("Unknown EdDSA algorithm number {}".format(algnum))


def load_keys(rrset):
    """
    Return list of DNSKEY class objects from the given DNSKEY RRset
    parameters (name, keytag, algorithm, key object).
    Also returns list of keys that experienced load/parse errors.
    """
    result = []
    errors = []
    for rr in rrset:
        try:
            d = DNSKEY(rrset.name, rr)
        except ResError as e:
            errors.append("{}: {}".format(rrset.name, e))
        else:
            result.append(d)
    return result, errors


def get_sig_info(rrset, rrsigs):

    """
    For given rrset and rrsig set, for each rrsig, return a Signature
    object, yielding them one at a time. The Signature object, contains
    the rrset, rrsig rdata, and the calculated input for the signature
    algorithm in question.

    From RFC4034, Section 3.1.8.1, the signature input data is:
    (RRSIG_RDATA | RR(1) | RR(2)... ), where RRSIG_RDATA is the rdata
    minus the actual signature field. For algorithms that specify
    hashing, the hashing occurs when the Signature.verify() method is
    called.
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

    candidate_keys = [key for key in keys if key.keytag == sig.rdata.key_tag]
    if len(candidate_keys) > MAX_KEYTAG_COLLISIONS:
        return Verified, [(x, "Keytag Collision Limit") for x in candidate_keys]

    for key in candidate_keys:
        try:
            sig.verify(key)
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
    Failed = []
    keys, errors = load_keys(rrset)

    for sig in get_sig_info(rrset, rrsigs):
        v, f = verify_sig_with_keys(sig, keys)
        Verified += v
        Failed += f

    if errors:
        print("ERROR: DNSKEY errors: {}".format(errors))
    if Failed:
        print("ERROR: DNSKEY self signature failed: {}".format(Failed))
    if not Verified:
        raise ResError("DNSKEY {} self signatures failed to validate: {}".format(
            rrset.name, Failed))

    return keys, Verified


def validate_all(rrset, rrsigs):
    """
    Validate rrsigs for rrset with the already authenticated global cache
    of keys in key_cache. Returns a tuple:
    Verified - list of keys that verified the signature.
    Failed - list of (key, error) tuples for failed keys.
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


def ds_rr_matches_dnskey(ds, dnskey):
    """
    Check that DS RR matches the DNSKEY.
    ds_ digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    """

    preimage = (dnskey.name.to_digestable() +
                struct.pack('!H', dnskey.flags) +
                struct.pack('B', dnskey.protocol) +
                struct.pack('B', dnskey.algorithm) +
                dnskey.rawkey)

    if ds.key_tag != dnskey.keytag:
        return False
    if ds.algorithm != dnskey.algorithm:
        return False
    if ds.digest_type not in DS_ALG:
        return False
    digest = hashes.Hash(DS_ALG[ds.digest_type](),
                         backend=default_backend())
    digest.update(preimage)
    computed_hash = digest.finalize()
    if computed_hash == ds.digest:
        return True
    if Prefs.VERBOSE:
        hex_snippet = computed_hash.hex()[0:8]
        print("# ERROR: DS digest {}... didn't match key with tag {}".format(
            hex_snippet, ds.key_tag))

    return False


b32_to_ext_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                 b'0123456789ABCDEFGHIJKLMNOPQRSTUV')


def nsec3_hashalg(algnum):
    """
    Return NSEC3 hash function; only SHA1 supported at this time in
    the DNSSEC specifications.
    """
    if algnum == 1:
        return hashes.SHA1
    raise ResError("unsupported NSEC3 hash algorithm {}".format(algnum))


def nsec3hash(name, algnum, salt, iterations, binary_out=False):
    """
    Compute NSEC3 hash for given domain name and parameters. name is
    of type dns.name.Name, salt is a binary bytestring, algnum and
    iterations are integers.
    """

    if iterations < 0:
        raise ResError("NSEC3 hash iterations must be >= 0")
    if iterations > Prefs.N3_HASHLIMIT:
        raise ResError("NSEC3 hash iterations too high: {} {}".format(
            name, iterations))

    hashfunc = nsec3_hashalg(algnum)
    digest = name.to_digestable()
    while iterations >= 0:
        d = hashes.Hash(hashfunc(), backend=default_backend())
        d.update(digest+salt)
        digest = d.finalize()
        iterations -= 1
    if binary_out:
        return digest

    output = base64.b32encode(digest)
    output = output.translate(b32_to_ext_hex).decode()
    return output


def nsec3hashname_from_record(name, nsec3, zonename, binary_out=False):
    """
    Compute NSEC3 hashed name for name and zone, from given NSEC3 record
    parameters.
    """
    algnum = nsec3[0].algorithm
    iterations = nsec3[0].iterations
    salt = nsec3[0].salt
    hashed_label = nsec3hash(name, algnum, salt, iterations,
                             binary_out=binary_out)
    hashed_name = dns.name.Name((hashed_label,) + zonename.labels)
    return hashed_name


def type_in_bitmap(rrtype, nsec_rr):
    """Is RR type present in NSEC/NSEC3 RR type bitmap?"""

    window_needed, bitmap_offset = divmod(rrtype, 256)
    for window, bitmap in nsec_rr.windows:
        if window == window_needed:
            bitmap_octet, bitpos = divmod(bitmap_offset, 8)
            if bitmap_octet >= len(bitmap):
                return False
            isset = (bitmap[bitmap_octet] >> (7-bitpos)) & 0x1
            if isset:
                return True
    return False


def get_hashed_owner(qname, signer, nsec3_rdata):
    """
    Obtain NSEC3 hashed owner name for given qname, signer, and
    NSEC3 rdata.
    """

    hash_output = nsec3hash(qname,
                            nsec3_rdata.algorithm,
                            nsec3_rdata.salt,
                            nsec3_rdata.iterations)
    return dns.name.Name((hash_output,) + signer.labels)


def nsec_covers_name(nsec_rrset, name):
    """
    Does NSEC RR cover the given name?
    """
    return nsec_rrset.name < name < nsec_rrset[0].next


def nsec_closest_encloser(qname, zonename, nsec_list):
    """
    Given qname, zone name, and the set of related NSEC records, return
    the closest encloser name.
    """

    if not qname.is_subdomain(zonename):
        raise ResError("qname is not subdomain of ancestor")
    resultlist = []
    q = qname
    while q != zonename:
        q = q.parent()
        resultlist.append(q)
    resultlist.reverse()

    candidate = None
    for candidate in resultlist:
        for nsec in nsec_list:
            if nsec_covers_name(nsec, candidate):
                return candidate.parent()
    return candidate


def nsec_wildcard_at_closest_encloser(qname, zonename, nsec_list):
    """
    Return wildcard name at closest encloser.
    """
    closest_encloser = nsec_closest_encloser(qname,
                                             zonename,
                                             nsec_list)
    return dns.name.Name(('*',) + closest_encloser.labels)


def nsec_nxdomain_proof(qname, signer, nsec_list):
    """
    Check NSEC NXDOMAIN proof for given qname, zone, and NSEC list.
    Raise exception if not proved.
    """

    qname_cover = False
    wildcard_cover = False

    for rrset in nsec_list:
        if nsec_covers_name(rrset, qname):
            qname_cover = True

    if not qname_cover:
        raise ResError("No NSEC covering qname {} found.".format(qname))

    wildcard = nsec_wildcard_at_closest_encloser(qname, signer, nsec_list)

    for rrset in nsec_list:
        if nsec_covers_name(rrset, wildcard):
            wildcard_cover = True
            break

    if not wildcard_cover:
        raise ResError("No NSEC covering wildcard {} found.".format(wildcard))


def nsec3_covers_name(nsec_rrset, name, zonename):
    """
    Does NSEC3 RR cover the given name?
    """
    name = name.canonicalize()
    n1 = nsec_rrset.name.canonicalize()
    n2_hash = base64.b32encode(nsec_rrset[0].next)
    n2_hash = n2_hash.translate(b32_to_ext_hex).decode()
    n2 = dns.name.Name((n2_hash,) + zonename.labels)
    n2 = n2.canonicalize()
    if (name.fullcompare(n1)[1] > 0) and (name.fullcompare(n2)[1] < 0):
        return True
    return False


def nsec3_closest_encloser_and_next(qname, zonename, nsec3_list):
    """
    Given qname and an zone name and the set of relavent NSEC3 records,
    return the closest encloser name and the next closer name.
    """

    if not qname.is_subdomain(zonename):
        raise ResError("qname is not subdomain of zone")
    resultlist = []
    q = qname
    while q != zonename:
        q = q.parent()
        resultlist.append(q)
    resultlist.reverse()

    candidate = None
    for candidate in resultlist:
        for nsec3 in nsec3_list:
            hashed_name = nsec3hashname_from_record(candidate, nsec3, zonename)
            if nsec3_covers_name(nsec3, hashed_name, zonename):
                return candidate.parent(), candidate
    return candidate, qname


def nsec3_nxdomain_proof(qname, signer, nsec3_list, optout=False, quiet=False):
    """
    Check NSEC3 NXDOMAIN proof for given qname, zone, and NSEC list.
    Raise exception if not proved.
    """

    closest_encloser_match = False
    next_closer_cover = False
    wildcard_cover = optout

    closest_encloser, next_closer = nsec3_closest_encloser_and_next(
        qname, signer, nsec3_list)
    wildcard = dns.name.Name(('*',) + closest_encloser.labels)
    for nsec3 in nsec3_list:
        hashed_ce = nsec3hashname_from_record(closest_encloser, nsec3, signer)
        hashed_nc = nsec3hashname_from_record(next_closer, nsec3, signer)
        hashed_wild = nsec3hashname_from_record(wildcard, nsec3, signer)
        if nsec3.name == hashed_ce:
            closest_encloser_match = True
            if Prefs.VERBOSE and not quiet:
                print("# INFO: closest{} encloser: {} {}".format(
                    " provable" if optout else "",
                    closest_encloser, hashed_ce.labels[0].decode()))
        if nsec3_covers_name(nsec3, hashed_nc, signer):
            if optout:
                if not nsec3[0].flags & 0x1:
                    continue
            next_closer_cover = True
            if Prefs.VERBOSE and not quiet:
                print("# INFO: next closer: {} {}".format(
                    next_closer, hashed_nc.labels[0].decode()))
        if not optout and nsec3_covers_name(nsec3, hashed_wild, signer):
            wildcard_cover = True
            if Prefs.VERBOSE and not quiet:
                print("# INFO: wildcard: {} {}".format(
                    wildcard, hashed_wild.labels[0].decode()))

    if not (closest_encloser_match and next_closer_cover and wildcard_cover):
        raise ResError("{} NSEC3 NXDOMAIN proof failed.".format(
            qname))


def nsec3_wildcard_nodata_proof(qname, qtype, signer, nsec3_list, quiet=False):
    """
    NSEC3 wildcard NODATA proof for given qname, zone, and NSEC3 list.

    From RFC 5155, Section 8.7:
    8.7.  Validating Wildcard No Data Responses

    The validator MUST verify a closest encloser proof for QNAME and MUST
    find an NSEC3 RR present in the response that matches the wildcard
    name generated by prepending the asterisk label to the closest
    encloser.  Furthermore, the bits corresponding to both QTYPE and
    CNAME MUST NOT be set in the wildcard matching NSEC3 RR.
    """

    closest_encloser_match = False
    wildcard_match = False

    closest_encloser, _ = nsec3_closest_encloser_and_next(
        qname, signer, nsec3_list)
    wildcard = dns.name.Name(('*',) + closest_encloser.labels)

    for nsec3 in nsec3_list:
        hashed_ce = nsec3hashname_from_record(closest_encloser, nsec3, signer)
        hashed_wild = nsec3hashname_from_record(wildcard, nsec3, signer)
        if nsec3.name == hashed_ce:
            closest_encloser_match = True
            if Prefs.VERBOSE and not quiet:
                print("# INFO: closest encloser: {} {}".format(
                    closest_encloser, hashed_ce.labels[0].decode()))
        if nsec3.name == hashed_wild:
            if (not type_in_bitmap(qtype, nsec3[0]) and
                not type_in_bitmap(dns.rdatatype.CNAME, nsec3[0])):
                wildcard_match = True
                if Prefs.VERBOSE and not quiet:
                    print("# INFO: wildcard: {} {}".format(
                        wildcard, hashed_wild.labels[0].decode()))

    if not (closest_encloser_match and wildcard_match):
        raise ResError("{} NSEC3 Wildcard NODATA proof failed.".format(
            qname))
    return wildcard


# Instantiate key cache at module level
key_cache = KeyCache()
