"""
DelegInfos (draft-ietf-deleg Section 3) wire codec for the resolver.

The DELEG / DELEGPARAM RDATA is the DelegInfos list of draft-ietf-deleg
Section 3, which reuses the SvcParams wire encoding of SVCB [RFC9460]
Section 2.2: a sequence of (key, 2-byte length, value) triples in strictly
increasing key order with no duplicate keys.

This module is I/O-free: it holds only the pure decode/classify logic (plus
the type-code/flag constants), so it can be imported and unit tested without
pulling in any resolver machinery. It is a leaf module -- it imports only
stdlib and dnspython (dns.name, dns.rdataclass), no reslib modules.

Decode primitives are ported from adns_server/adns/deleg.py.
"""

import socket
import struct

import dns.name
import dns.rdataclass


# Pre-standardization type codes (agreed with collaborators).
DELEG_RDTYPE = 61440
DELEGPARAM_RDTYPE = 65433

# EDNS(0) Delegation-Extensions flag (bit 2 of the EDNS flags field).
EDNS_DE_FLAG = 0x2000

# DelegInfo key registry (draft-ietf-deleg Section 8.2.2).
KEY_BY_NAME = {
    "mandatory": 0,
    "server-ipv4": 1,
    "server-ipv6": 2,
    "server-name": 3,
    "include-delegparam": 4,
}
NAME_BY_KEY = {num: name for name, num in KEY_BY_NAME.items()}

SERVER_INFO_KEYS = {1, 2, 3, 4}
SUPPORTED_KEYS = {0, 1, 2, 3, 4}


class DelegParseError(Exception):
    """Malformed DelegInfos RDATA."""


def _decode_addrs(value, family, size):
    """Decode concatenated fixed-size addresses into a list of text strings."""
    if len(value) == 0 or len(value) % size != 0:
        raise DelegParseError(
            "address value length {} not a multiple of {}".format(
                len(value), size))
    out = []
    for i in range(0, len(value), size):
        chunk = value[i:i + size]
        try:
            out.append(socket.inet_ntop(family, chunk))
        except (OSError, ValueError) as exc:
            raise DelegParseError("bad address octets: {}".format(exc))
    return out


def _decode_names(value):
    """Decode concatenated uncompressed wire-format names to dns.name.Name."""
    out = []
    i = 0
    n = len(value)
    while i < n:
        labels = []
        while True:
            if i >= n:
                raise DelegParseError("truncated wire name in DelegInfo")
            length = value[i]
            i += 1
            if length == 0:
                break
            if length > 63:
                raise DelegParseError("bad label length {}".format(length))
            if i + length > n:
                raise DelegParseError("truncated label in DelegInfo")
            labels.append(value[i:i + length])
            i += length
        out.append(dns.name.Name([bytes(l) for l in labels] + [b""]))
    if not out:
        raise DelegParseError("empty wire-name value")
    return out


def _decode_mandatory(value):
    """Decode a mandatory value into a set of key numbers."""
    if len(value) == 0 or len(value) % 2 != 0:
        raise DelegParseError("mandatory value length not a multiple of 2")
    out = set()
    for i in range(0, len(value), 2):
        (num,) = struct.unpack_from("!H", value, i)
        out.add(num)
    return out


class DelegInfo:
    """Decoded DelegInfos of a single DELEG/DELEGPARAM record."""

    def __init__(self):
        self.keys = {}                 # keynum -> raw value bytes (wire order)
        self.mandatory = set()
        self.server_ipv4 = []
        self.server_ipv6 = []
        self.server_name = []          # list of dns.name.Name
        self.include_delegparam = []   # list of dns.name.Name
        self.unknown_keys = set()

    def server_info_keys(self):
        """Return the set of present server-information key numbers."""
        return set(self.keys) & SERVER_INFO_KEYS


def parse_deleginfos(rdata_bytes):
    """Parse DelegInfos RDATA bytes into a DelegInfo, enforcing the wire rules.

    Raises DelegParseError on: non-increasing key order, duplicate keys,
    truncation, or empty values.
    """
    di = DelegInfo()
    i = 0
    n = len(rdata_bytes)
    last_key = -1
    while i < n:
        if i + 4 > n:
            raise DelegParseError("truncated DelegInfo header")
        keynum, vlen = struct.unpack_from("!HH", rdata_bytes, i)
        i += 4
        if keynum <= last_key:
            raise DelegParseError(
                "DelegInfo keys not strictly increasing at key {}".format(
                    keynum))
        last_key = keynum
        if i + vlen > n:
            raise DelegParseError("truncated DelegInfo value for key {}".format(
                keynum))
        value = rdata_bytes[i:i + vlen]
        i += vlen
        if vlen == 0:
            raise DelegParseError("empty value for key {}".format(keynum))
        di.keys[keynum] = value
        if keynum == 0:
            di.mandatory = _decode_mandatory(value)
        elif keynum == 1:
            di.server_ipv4 = _decode_addrs(value, socket.AF_INET, 4)
        elif keynum == 2:
            di.server_ipv6 = _decode_addrs(value, socket.AF_INET6, 16)
        elif keynum == 3:
            di.server_name = _decode_names(value)
        elif keynum == 4:
            di.include_delegparam = _decode_names(value)
        else:
            di.unknown_keys.add(keynum)
    return di


def format_deleginfo(rdata_bytes):
    """Return a single-line presentation string for a DelegInfos RDATA blob.

    Falls back to RFC 3597 generic hex form if the RDATA cannot be parsed.
    """
    try:
        di = parse_deleginfos(rdata_bytes)
    except DelegParseError:
        return "\\# {} {}".format(len(rdata_bytes), rdata_bytes.hex())
    parts = []
    if di.mandatory:
        parts.append("mandatory={}".format(
            ",".join(NAME_BY_KEY.get(k, "key{}".format(k))
                     for k in sorted(di.mandatory))))
    if di.server_ipv4:
        parts.append("server-ipv4={}".format(",".join(di.server_ipv4)))
    if di.server_ipv6:
        parts.append("server-ipv6={}".format(",".join(di.server_ipv6)))
    if di.server_name:
        parts.append("server-name={}".format(
            ",".join(n.to_text() for n in di.server_name)))
    if di.include_delegparam:
        parts.append("include-delegparam={}".format(
            ",".join(n.to_text() for n in di.include_delegparam)))
    for k in sorted(di.unknown_keys):
        parts.append("key{}={}".format(k, di.keys[k].hex()))
    return " ".join(parts)


def format_deleg_rrset(rrset):
    """Presentation-format block for a DELEG/DELEGPARAM RRset.

    One presentation line per rdata: "owner ttl class TYPE key=val ...".
    """
    type_name = "DELEG" if rrset.rdtype == DELEG_RDTYPE else "DELEGPARAM"
    lines = []
    for rdata in rrset:
        lines.append("{} {} {} {} {}".format(
            rrset.name, rrset.ttl,
            dns.rdataclass.to_text(rrset.rdclass),
            type_name, format_deleginfo(rdata.data)))
    return "\n".join(lines)


class DelegRecordError(Exception):
    """A single DELEG record is malformed or unusable (drop it)."""


SLIST_USABLE = "usable"
SLIST_UNUSABLE = "present-but-unusable"
SLIST_ABSENT = "absent"

# Allowed server-information "shapes" (draft-ietf-deleg §3.4/§5.1.2 step 3).
_ALLOWED_SHAPES = [{1}, {2}, {1, 2}, {3}, {4}]


class SlistResult:
    """Tri-state result of building a server list from a DELEG RRset."""

    def __init__(self, state, addresses=None):
        self.state = state
        self.addresses = addresses if addresses is not None else []


def classify_record(di, delegated_owner):
    """Classify one DelegInfo per draft-ietf-deleg §5.1.2.

    Returns (kind, payload):
      ("addrs", [ipstr, ...])       inline server-ipv4/ipv6
      ("names", [dns.name.Name])    server-name (resolve via recursion)
      ("delegparam", [dns.name.Name]) include-delegparam (indirect)
      ("none", [])                  record contributes nothing
    Raises DelegRecordError if the record is malformed (caller drops it).
    """
    # Step 1: discard unsupported keys; if only unsupported keys remain, the
    # record contributes nothing.
    supported_present = set(di.keys) & SUPPORTED_KEYS
    if not supported_present:
        return ("none", [])

    # Step 2: every mandatory-referenced key must still be present.
    if di.mandatory and not di.mandatory.issubset(supported_present):
        raise DelegRecordError("mandatory key not present")

    # Step 3: exactly one allowed server-information shape.
    server_keys = di.server_info_keys()
    if server_keys and server_keys not in _ALLOWED_SHAPES:
        raise DelegRecordError("disallowed server-information key combination")

    # Step 4: server-name / include-delegparam targets must not be at or below
    # the ORIGINAL delegated owner.
    for name in di.server_name + di.include_delegparam:
        if name == delegated_owner or name.is_subdomain(delegated_owner):
            raise DelegRecordError(
                "in-bailiwick target {}".format(name))

    # Steps 5-7: pick the shape.
    if 1 in server_keys or 2 in server_keys:
        return ("addrs", list(di.server_ipv4) + list(di.server_ipv6))
    if 3 in server_keys:
        return ("names", list(di.server_name))
    if 4 in server_keys:
        return ("delegparam", list(di.include_delegparam))

    # Step 8: nothing usable.
    return ("none", [])


def build_slist(deleg_rrset, delegated_owner, resolve_addrs,
                 fetch_delegparam, max_chain, _depth=0):
    """Build a deduplicated server address list from a DELEG RRset.

    resolve_addrs(name) -> [ipstr, ...]      resolve a server-name.
    fetch_delegparam(name) -> RRset or None  fetch DELEGPARAM at a target.
    Returns SlistResult (tri-state).
    """
    if deleg_rrset is None:
        return SlistResult(SLIST_ABSENT)

    addresses = []
    seen = set()

    def _add(ip):
        if ip not in seen:
            seen.add(ip)
            addresses.append(ip)

    for rdata in deleg_rrset:
        blob = rdata.data
        try:
            di = parse_deleginfos(blob)
            kind, payload = classify_record(di, delegated_owner)
        except (DelegParseError, DelegRecordError):
            continue                                  # drop this record
        if kind == "addrs":
            for ip in payload:
                _add(ip)
        elif kind == "names":
            for name in payload:
                for ip in resolve_addrs(name):
                    _add(ip)
        elif kind == "delegparam":
            if _depth + 1 > max_chain:
                continue                              # drop; loop bound hit
            for target in payload:
                sub_rrset = fetch_delegparam(target)
                if sub_rrset is None:
                    continue
                sub = build_slist(sub_rrset, delegated_owner, resolve_addrs,
                                  fetch_delegparam, max_chain,
                                  _depth=_depth + 1)
                for ip in sub.addresses:
                    _add(ip)
        # kind == "none": nothing

    if addresses:
        return SlistResult(SLIST_USABLE, addresses)
    return SlistResult(SLIST_UNUSABLE)
