"""
Miscellaneous helper functions.
"""

import time
import random
import dns.resolver
from reslib.common import Prefs, stats, TIMEOUT, RETRIES


def dprint(msg):
    """Print debugging message if DEBUG flag is set"""
    if Prefs.DEBUG:
        print(">> DEBUG: %s" % msg)
    return


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return msg.flags & dns.flags.AA == dns.flags.AA


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return msg.flags & dns.flags.TC == dns.flags.TC


def is_referral(msg):
    """Is the DNS response message a referral?"""
    return (msg.rcode() == 0) and (not is_authoritative(msg)) and msg.authority


def get_resolver(dnssec_ok=False, timeout=5):
    """return an appropriately configured Resolver object"""
    r = dns.resolver.Resolver()
    # Set query flags to RD=1, AD=1, CD=1
    #r.set_flags(0x0130)                      # binary 0000 0001 0011 0000
    r.lifetime = timeout
    if dnssec_ok:
        r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
    return r


def get_rrset(resolver, qname, qtype):
    """
    Query name and type; return answer RRset and signature RRset.
    """
    msg = resolver.query(qname, qtype).response
    rrset = msg.get_rrset(msg.answer, qname, 1, qtype)
    rrsigs = msg.get_rrset(msg.answer, qname, 1,
                           dns.rdatatype.RRSIG, covers=qtype)
    return rrset, rrsigs


def send_query_tcp(msg, nsaddr, query, timeout=TIMEOUT):
    """Send query over TCP"""
    res = None
    stats.update_query(query, tcp=True)
    try:
        res = dns.query.tcp(msg, nsaddr.addr, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(nsaddr.addr))
    return res


def send_query_udp(msg, nsaddr, query, timeout=TIMEOUT, retries=RETRIES):
    """Send query over UDP"""
    gotresponse = False
    res = None
    stats.update_query(query)
    while (not gotresponse) and (retries > 0):
        retries -= 1
        try:
            t0 = time.time()
            res = dns.query.udp(msg, nsaddr.addr, timeout=timeout)
            nsaddr.rtt = time.time() - t0
            gotresponse = True
        except dns.exception.Timeout:
            print("WARN: UDP query timeout for {}".format(nsaddr.addr))
    return res


def send_query(msg, nsaddr, query, timeout=TIMEOUT, retries=RETRIES,
               newid=False):
    """send DNS query to specified address"""
    res = None
    if newid:
        msg.id = random.randint(1, 65535)

    if Prefs.TCPONLY:
        return send_query_tcp(msg, nsaddr, query, timeout=timeout)

    res = send_query_udp(msg, nsaddr, query,
                         timeout=timeout, retries=retries)
    if res and is_truncated(res):
        print("WARN: response was truncated; retrying with TCP ..")
        stats.cnt_tcp_fallback += 1
        res = send_query_tcp(msg, nsaddr, query)
    return res


def make_query(qname, qtype, qclass):
    """Make DNS query message from qname/type/class"""
    msg = dns.message.make_query(qname,
                                 qtype,
                                 rdclass=qclass,
                                 want_dnssec=Prefs.DNSSEC_OK,
                                 payload=Prefs.PAYLOAD)
    msg.flags &= ~dns.flags.RD
    return msg
