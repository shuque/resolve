#!/usr/bin/env python3
#

"""
Testing DNSSEC signature validation.
for details: RFC 4034, Section 3.1.8.1.  Signature Calculation

Given a zone name, query its SOA RRset, and verify the SOA signature
against the apex DNSKEY RRset.

"""

import sys
import dns.name
import dns.rdatatype

from reslib.dnssec import *
from reslib.utils import get_resolver, get_rrset


def print_results(verified, failed):
    """Print signature verification results"""

    if verified:
        print("OK: Signature Verified")
        for keyinfo in verified:
            print("    Good signature with keytag={} algo={}".format(
                keyinfo.keytag, keyinfo.algorithm))
        if failed:
            print("FAILURES:")
            for keyinfo, error in failed:
                print("    keytag={} algo={} error={}".format(
                    keyinfo.keytag, keyinfo.algorithm, error))
    else:
        print("FAIL: No Signature Verified with any DNSKEY")
        for keyinfo, error in failed:
            print("    keytag={} algo={} error={}".format(
                keyinfo.keytag, keyinfo.algorithm, error))
    return


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
        print(keyinfo)
    print('')

    verified, failed = validate_all(soa_rrset, soa_rrsigs, DNSSEC_KEYS)
    print_results(verified, failed)
    if verified:
        sys.exit(0)
    else:
        sys.exit(1)
