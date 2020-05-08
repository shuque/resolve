"""
Miscellaneous helper functions.
"""

import time
import random
import dns.resolver
from reslib.common import Prefs, stats


def vprint_quiet(query):
    """Is verbose flag > 1 or is it set and query does not have quiet flag?"""
    if Prefs.VERBOSE > 1:
        return True
    return Prefs.VERBOSE and not query.quiet


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return msg.flags & dns.flags.AA == dns.flags.AA


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return msg.flags & dns.flags.TC == dns.flags.TC


def is_referral(msg):
    """Is the DNS response message a referral?"""
    return (msg.rcode() == 0) and (not is_authoritative(msg)) and msg.authority


def send_query_tcp(msg, nsaddr, query, timeout=Prefs.TIMEOUT):
    """Send query over TCP"""
    res = None
    stats.update_query(query, tcp=True)
    try:
        res = dns.query.tcp(msg, nsaddr.addr, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(nsaddr.addr))
    return res


def send_query_udp(msg, nsaddr, query,
                   timeout=Prefs.TIMEOUT, retries=Prefs.RETRIES):
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


def send_query(msg, nsaddr, query,
               timeout=Prefs.TIMEOUT, retries=Prefs.RETRIES, newid=False):
    """send DNS query to specified address"""
    res = None
    if newid:
        msg.id = random.randint(1, 65535)

    if Prefs.TCPONLY:
        return send_query_tcp(msg, nsaddr, query, timeout=timeout)

    res = send_query_udp(msg, nsaddr, query,
                         timeout=timeout, retries=retries)
    if res and is_truncated(res):
        print("WARN: response from {} was truncated; retrying with TCP".format(
            nsaddr.addr))
        stats.cnt_tcp_fallback += 1
        res = send_query_tcp(msg, nsaddr, query)
    return res


def make_query_message(query):
    """Make DNS query message from a query object"""
    use_edns = False if Prefs.PAYLOAD == 0 else True
    msg = dns.message.make_query(query.qname,
                                 query.qtype,
                                 rdclass=query.qclass,
                                 use_edns=use_edns,
                                 want_dnssec=Prefs.DNSSEC,
                                 payload=Prefs.PAYLOAD)
    msg.flags &= ~dns.flags.RD
    return msg


def get_rrset_from_section(message, section, qname, qtype):
    """
    From given DNS message/section return answer RRset and
    signature RRset for specified qname and qtype.
    """
    rrset = message.get_rrset(section, qname, 1, qtype)
    rrsigs = message.get_rrset(section, qname, 1,
                               dns.rdatatype.RRSIG, covers=qtype)
    return rrset, rrsigs
