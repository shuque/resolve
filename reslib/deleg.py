"""
DelegInfos (draft-ietf-deleg Section 3) wire codec for the resolver.

The DELEG / DELEGPARAM RDATA is the DelegInfos list of draft-ietf-deleg
Section 3, which reuses the SvcParams wire encoding of SVCB [RFC9460]
Section 2.2: a sequence of (key, 2-byte length, value) triples in strictly
increasing key order with no duplicate keys.

This module is I/O-free: it holds only the pure decode/classify logic (plus
the type-code/flag constants), so it can be imported and unit tested without
pulling in any resolver machinery. It is a leaf module -- it imports only
stdlib and dns.name.

Decode primitives are ported from adns_server/adns/deleg.py.
"""

import socket
import struct

import dns.name


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
