import dns.resolver
from reslib.common import *


def dprint(msg):
    """Print debugging message if DEBUG flag is set"""
    if Prefs.DEBUG:
        print(">> DEBUG: %s" % msg)
    return


def get_resolver(dnssec_ok=False, timeout=5):
    """return an appropriately configured Resolver object"""
    r = dns.resolver.Resolver()
    # Set query flags to RD=1, AD=1, CD=1
    #r.set_flags(0x0130)                      # binary 0000 0001 0011 0000
    r.lifetime = timeout
    if dnssec_ok:
        r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
    return r


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return msg.flags & dns.flags.AA == dns.flags.AA


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return msg.flags & dns.flags.TC == dns.flags.TC


def is_referral(msg):
    """Is the DNS response message a referral?"""
    return (msg.rcode() == 0) and (not is_authoritative(msg)) and msg.authority

