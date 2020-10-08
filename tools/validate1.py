#!/usr/bin/env python3
#

"""
Simple standalone DNSSEC signature validation test. Does not perform
full chain authentication like resolve.py.

Given a zone name, query its SOA RRset and DNSKEY RRset, verify
the self signature of the DNSKEY, and then verify the SOA signature
against the DNSKEY RRset.

"""

import sys
import dns.name
import dns.rdatatype
import dns.resolver

from reslib.prefs import Prefs
from reslib.dnssec import key_cache, load_keys, validate_all
from reslib.utils import get_rrset_from_section


def get_resolver(dnssec_ok=False, timeout=5):
    """return an appropriately configured Resolver object"""
    r = dns.resolver.Resolver()
    # Set query flags to RD=1, AD=1, CD=1: # binary 0000 0001 0011 0000
    r.set_flags(0x0130)
    r.lifetime = timeout
    if dnssec_ok:
        r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
    return r


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


    Prefs.DNSSEC = True
    qname = dns.name.from_text(sys.argv[1])
    qtype = dns.rdatatype.from_text('SOA')

    r = get_resolver(dnssec_ok=True)
    msg = r.query(qname, qtype).response
    soa_rrset, soa_rrsigs = get_rrset_from_section(msg,
                                                   msg.answer,
                                                   qname, qtype)
    print(soa_rrset)
    if soa_rrsigs is None:
        print("No signatures found.")
        sys.exit(1)

    print("Found {} signature{}.".format(
        len(soa_rrsigs), "" if len(soa_rrsigs) == 1 else "s"))
    print('')

    msg = r.query(qname, dns.rdatatype.from_text('DNSKEY')).response
    dnskey_rrset, _ = get_rrset_from_section(msg,
                                             msg.answer,
                                             qname,
                                             dns.rdatatype.from_text('DNSKEY'))

    key_cache.install(qname, load_keys(dnskey_rrset)[0])
    key_cache.print()

    verified, failed = validate_all(soa_rrset, soa_rrsigs)
    print_results(verified, failed)
    if verified:
        sys.exit(0)
    else:
        sys.exit(1)
