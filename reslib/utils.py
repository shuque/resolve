"""
Miscellaneous helper functions.
"""

import time
import random
import dns.resolver


def vprint_quiet(query):
    """Is verbose flag > 1 or is it set and query does not have quiet flag?"""
    if query.resolver.prefs.VERBOSE > 1:
        return True
    return query.resolver.prefs.VERBOSE and not query.quiet


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return msg.flags & dns.flags.AA == dns.flags.AA


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return msg.flags & dns.flags.TC == dns.flags.TC


def is_referral(msg):
    """Is the DNS response message a referral?"""
    return (msg.rcode() == 0) and (not is_authoritative(msg)) and msg.authority


def send_query_tcp(msg, nsaddr, query, timeout=None):
    """Send query over TCP"""
    if timeout is None:
        timeout = query.resolver.prefs.TIMEOUT
    res = None
    query.resolver.stats.update_query(query, tcp=True)
    try:
        res = dns.query.tcp(msg, nsaddr.addr, timeout=timeout)
    except dns.exception.Timeout:
        if vprint_quiet(query):
            print("WARN: TCP query timeout for {}".format(nsaddr.addr))
    return res


def send_query_udp(msg, nsaddr, query,
                   timeout=None, retries=None):
    """Send query over UDP"""
    if timeout is None:
        timeout = query.resolver.prefs.TIMEOUT
    if retries is None:
        retries = query.resolver.prefs.RETRIES
    gotresponse = False
    res = None
    query.resolver.stats.update_query(query)
    while (not gotresponse) and (retries > 0):
        retries -= 1
        try:
            t0 = time.time()
            res = dns.query.udp(msg, nsaddr.addr, timeout=timeout)
            nsaddr.rtt = time.time() - t0
            gotresponse = True
        except dns.exception.Timeout:
            if vprint_quiet(query):
                print("WARN: UDP query timeout for {}".format(nsaddr.addr))
    return res


def send_query(msg, nsaddr, query,
               timeout=None, retries=None, newid=False):
    """send DNS query to specified address"""
    if timeout is None:
        timeout = query.resolver.prefs.TIMEOUT
    if retries is None:
        retries = query.resolver.prefs.RETRIES
    res = None
    if newid:
        msg.id = random.randint(1, 65535)

    if query.resolver.prefs.TCPONLY:
        return send_query_tcp(msg, nsaddr, query, timeout=timeout)

    res = send_query_udp(msg, nsaddr, query,
                         timeout=timeout, retries=retries)
    if res and is_truncated(res):
        if vprint_quiet(query):
            print("WARN: response from {} truncated; retrying with TCP".format(
                nsaddr.addr))
        query.resolver.stats.cnt_tcp_fallback += 1
        res = send_query_tcp(msg, nsaddr, query)
    return res


def make_query_message(query):
    """Make DNS query message from a query object"""
    use_edns = query.resolver.prefs.PAYLOAD != 0
    msg = dns.message.make_query(query.qname,
                                 query.qtype,
                                 rdclass=query.qclass,
                                 use_edns=use_edns,
                                 want_dnssec=query.resolver.prefs.DNSSEC,
                                 payload=query.resolver.prefs.PAYLOAD)
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
