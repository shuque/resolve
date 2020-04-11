#!/usr/bin/env python3

"""
resolve.py
Perform iterative resolution of a DNS name, type, class.

Author: Shumon Huque <shuque - @ - gmail.com>
"""


import os
import sys
import getopt
import time
import random

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.dnssec

from reslib.common import *
from reslib.usage import usage
from reslib.cache import Cache, get_root_zone
from reslib.zone import Zone
from reslib.nameserver import NameServer
from reslib.query import Query
from reslib.stats import Stats
from reslib.utils import dprint


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return msg.flags & dns.flags.AA == dns.flags.AA


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return msg.flags & dns.flags.TC == dns.flags.TC


def is_referral(msg):
    """Is the DNS response message a referral?"""
    return (msg.rcode() == 0) and (not is_authoritative(msg)) and msg.authority


def get_ns_addrs(zone, message):
    """
    Populate nameserver addresses for zone from a given referral message.

    Note: by default, we only save and use NS record addresses we can find
    in the additional section of the referral. To be complete, we should
    really explicitly resolve all non-glue NS addresses, but that would cause
    a potentially large number of additional queries and corresponding latency
    which are mostly unnecessary. This complete mode can be turned on with -n
    (NSRESOLVE). If no NS addresses can be found in the additional section, we
    of course resort to this complete mode.
    """

    needsGlue = []
    for nsname in zone.nslist:
        if nsname.is_subdomain(zone.name):
            needsGlue.append(nsname)
    needToResolve = list(set(zone.nslist) - set(needsGlue))

    for rrset in message.additional:
        if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            name = rrset.name
            for rr in rrset:
                if not zone.has_ns(name):
                    continue
                if (not Prefs.NSRESOLVE) or (name in needsGlue):
                    nsobj = cache.get_ns(name)
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or Prefs.NSRESOLVE:
        if Prefs.DEBUG:
            print(">> DEBUG: Need to resolve Nameserver names from referral:")
            for x in needToResolve:
                print(">> DEBUG: {}".format(x))
        for name in needToResolve:
            nsobj = cache.get_ns(name)
            if nsobj.iplist:
                continue
            for addrtype in ['A', 'AAAA']:
                nsquery = Query(name, addrtype, 'IN', Prefs.MINIMIZE,
                                is_nsquery=True)
                nsquery.quiet = True
                resolve_name(nsquery, cache.closest_zone(nsquery.qname),
                             inPath=False)
                for ip in nsquery.get_answer_ip_list():
                    nsobj.install_ip(ip)

    return


def process_referral(message, query):

    """Process referral. Returns a zone object for the referred zone"""

    for rrset in message.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            break
    else:
        print("ERROR: unable to find NS RRset in referral response")
        return None

    zonename = rrset.name
    if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
        print(">>        [Got Referral to zone: %s in %.3f s]" % \
              (zonename, query.elapsed_last))

    zone = cache.get_zone(zonename)
    if zone is None:
        zone = Zone(zonename, cache)
        for rr in rrset:
            _ = zone.install_ns(rr.target)

    get_ns_addrs(zone, message)

    if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
        zone.print_details()

    return zone


def process_answer(response, query, addResults=None):

    """Process answer section, chasing aliases when needed"""

    cname_dict = {}              # dict of alias -> target

    # If minimizing, ignore answers for intermediate query names.
    if query.qname != query.orig_qname:
        return

    if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
        print(">>        [Got answer in  %.3f s]" % query.elapsed_last)

    if not response.answer:
        if not query.quiet:
            print("ERROR: NODATA: %s of type %s not found" % \
                  (query.qname, query.qtype))
        return

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.from_text(query.qtype) and \
           rrset.name == query.qname:
            query.answer_rrset.append(rrset)
            if addResults:
                addResults.full_answer_rrset.append(rrset)
            query.got_answer = True
        elif rrset.rdtype == dns.rdatatype.DNAME:
            # Add DNAME record to results. Technically a good resolver should
            # do DNAME->CNAME synthesis itself here, but we rely on the fact
            # that almost all authorities provide the CNAMEs themselves.
            query.answer_rrset.append(rrset)
            if addResults:
                addResults.full_answer_rrset.append(rrset)
            if Prefs.VERBOSE:
                print(rrset.to_text())
        elif rrset.rdtype == dns.rdatatype.CNAME:
            query.answer_rrset.append(rrset)
            if addResults:
                addResults.full_answer_rrset.append(rrset)
            if Prefs.VERBOSE:
                print(rrset.to_text())
            cname = rrset[0].target
            cname_dict[rrset.name] = rrset[0].target
            stats.cnt_cname += 1
            if stats.cnt_cname >= MAX_CNAME:
                print("ERROR: Too many (%d) CNAME indirections." % MAX_CNAME)
                return

    if cname_dict:
        final_alias = response.question[0].name
        while True:
            if final_alias in cname_dict:
                final_alias = cname_dict[final_alias]
            else:
                break
        dprint("CNAME found, resolving canonical name %s" % final_alias)
        cname_query = Query(final_alias, query.qtype, query.qclass,
                            Prefs.MINIMIZE)
        if addResults:
            addResults.cname_chain.append(cname_query)
        resolve_name(cname_query, cache.closest_zone(cname),
                     inPath=False, addResults=addResults)

    return


def process_response(response, query, addResults=None):

    """process a DNS response. Returns rcode, answer message, zone referral"""

    rc = None
    ans = None
    referral = None

    if not response:
        return (rc, ans, referral)
    rc = response.rcode()
    query.rcode = rc
    if rc == dns.rcode.NOERROR:
        if is_referral(response):
            referral = process_referral(response, query)
            if not referral:
                print("ERROR: processing referral")
        else:                                            # Answer
            process_answer(response, query, addResults=addResults)
    elif rc == dns.rcode.NXDOMAIN:                       # NXDOMAIN
        if not query.quiet:
            print("ERROR: NXDOMAIN: %s not found" % query.qname)

    return (rc, referral)


def send_query_tcp(msg, nsaddr, query, timeout=TIMEOUT):
    res = None
    stats.update_query(query, tcp=True)
    try:
        res = dns.query.tcp(msg, nsaddr.addr, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(nsaddr.addr))
    return res


def send_query_udp(msg, nsaddr, query, timeout=TIMEOUT, retries=RETRIES):
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
            pass
    return res


def send_query(msg, nsaddr, query, timeout=TIMEOUT, retries=RETRIES,
               newid=False):
    res = None
    if newid:
        msg.id = random.randint(1, 65535)

    if Prefs.TCPONLY:
        return send_query_tcp(msg, nsaddr, query, timeout=timeout)

    res = send_query_udp(msg, nsaddr, query, timeout=timeout, retries=retries)
    if res and is_truncated(res):
        print("WARN: response was truncated; retrying with TCP ..")
        stats.cnt_tcp_fallback += 1
        res = send_query_tcp(msg, nsaddr, query)
    return res


def make_query(qname, qtype, qclass):
    msg = dns.message.make_query(qname, qtype, rdclass=qclass,
                                 want_dnssec=Prefs.DNSSEC_OK,
                                 payload=Prefs.PAYLOAD)
    msg.flags &= ~dns.flags.RD  # set RD=0
    return msg


def send_query_zone(query, zone):
    """send DNS query to nameservers of given zone"""

    response = None

    if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
        print("\n>> Query: %s %s %s at zone %s" % \
               (query.qname, query.qtype, query.qclass, zone.name))

    msg = make_query(query.qname, query.qtype, query.qclass)

    nsaddr_list = zone.iplist_sorted_by_rtt()
    if not nsaddr_list:
        print("ERROR: No nameserver addresses found for zone: %s." % zone.name)
        return None

    time_start = time.time()
    for nsaddr in nsaddr_list:
        if stats.cnt_query1 + stats.cnt_query2 >= MAX_QUERY:
            print("ERROR: Max number of queries (%d) exceeded." % MAX_QUERY)
            return None
        if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
            print(">>   Send to zone %s at address %s" % (zone.name, nsaddr.addr))
        response = send_query(msg, nsaddr, query, newid=True)
        if response:
            rc = response.rcode()
            if rc not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
                stats.cnt_fail += 1
                print("WARNING: response %s from %s" % (dns.rcode.to_text(rc), nsaddr.addr))
            else:
                break
    else:
        print("ERROR: Queries to all servers for zone %s failed." % zone.name)

    query.elapsed_last = time.time() - time_start
    return response


def resolve_name(query, zone, inPath=True, addResults=None):
    """resolve a DNS query. addResults is an optional Query object to
    which the answer results are to be added."""

    curr_zone = zone
    repeatZone = False

    while stats.cnt_deleg < MAX_DELEG:

        if query.minimize:
            if repeatZone:
                query.prepend_label()
                repeatZone = False
            else:
                query.set_minimized(curr_zone)

        response = send_query_zone(query, curr_zone)
        if not response:
            return

        rc, referral = process_response(response, query, addResults=addResults)

        if rc == dns.rcode.NXDOMAIN:
            # for broken servers that give NXDOMAIN for empty non-terminals
            if Prefs.VIOLATE and (query.minimize) and (query.qname != query.orig_qname):
                repeatZone = True
            else:
                break

        if not referral:
            if (not query.minimize) or (query.qname == query.orig_qname):
                break
            elif query.minimize:
                repeatZone = True
        else:
            stats.cnt_deleg += 1
            if inPath:
                stats.delegation_depth += 1
            if not referral.name.is_subdomain(curr_zone.name):
                print("ERROR: Upward referral: %s is not subdomain of %s" %
                      (referral.name, curr_zone.name))
                break
            curr_zone = referral

    if stats.cnt_deleg >= MAX_DELEG:
        print("ERROR: Max levels of delegation (%d) reached." % MAX_DELEG)

    return


def do_batchmode(infile, cmdline):
    """Execute batch mode on input file supplied to -b"""

    print("### resolve.py: Batch Mode file: %s" % Prefs.BATCHFILE)
    print("### command: %s" % ' '.join(cmdline))
    linenum = 0
    for line in open(infile):
        linenum += 1
        line = line.rstrip('\n')
        parts = line.split()
        if len(parts) == 1:
            qname, = parts
            qtype = 'A'
            qclass = 'IN'
        elif len(parts) == 2:
            qname, qtype = parts
            qclass = 'IN'
        elif len(parts) == 3:
            qname, qtype, qclass = parts
        else:
            print("\nERROR input line %d: %s" % (linenum, line))
            continue

        print("\n### INPUT: %s, %s, %s" % (qname, qtype, qclass))
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)
        starting_zone = cache.closest_zone(query.qname)
        print("### Query: %s" % query)
        print("### Starting at zone: %s" % starting_zone)
        resolve_name(query, starting_zone, addResults=query)
        if Prefs.VERBOSE:
            print('')
        query.print_full_answer()

    print("\n### End Batch Mode.")
    return


def exit_status(query):
    """Obtain final exit status code"""
    if query.cname_chain:
        last_cname = query.cname_chain.pop()
        rcode = last_cname.rcode
        got_answer = last_cname.got_answer
    else:
        rcode = query.rcode
        got_answer = query.got_answer

    if rcode == 0 and got_answer:
        return 0
    return 1


def process_args(arguments):
    """Process all command line arguments"""

    try:
        (options, args) = getopt.getopt(arguments, 'dmtvsnxezb:')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-d":
            Prefs.DEBUG = True
        elif opt == "-m":
            Prefs.MINIMIZE = True
        elif opt == "-t":
            Prefs.TCPONLY = True
        elif opt == "-v":
            Prefs.VERBOSE = True
        elif opt == "-s":
            Prefs.STATS = True
        elif opt == "-n":
            Prefs.NSRESOLVE = True
        elif opt == "-x":
            Prefs.VIOLATE = True
        elif opt == "-e":
            Prefs.PAYLOAD = None
        elif opt == "-z":
            Prefs.DNSSEC_OK = True
        elif opt == "-b":
            Prefs.BATCHFILE = optval

    if (Prefs.PAYLOAD is None) and Prefs.DNSSEC_OK:
        usage("Error: -e and -z are mutually incompatible.")

    if Prefs.BATCHFILE:
        if not args:
            return (None, None, None)
        else:
            usage()

    numargs = len(args)
    if numargs == 1:
        qname, = args
        qtype = 'A'
        qclass = 'IN'
    elif numargs == 2:
        qname, qtype = args
        qclass = 'IN'
    elif numargs == 3:
        qname, qtype, qclass = args
    else:
        usage()

    return (qname, qtype, qclass)


if __name__ == '__main__':

    random.seed(os.urandom(64))
    qname, qtype, qclass = process_args(sys.argv[1:])
    cache = Cache()
    RootZone = get_root_zone(cache)
    stats = Stats()

    if Prefs.BATCHFILE:
        time_start = time.time()
        do_batchmode(infile=Prefs.BATCHFILE, cmdline=sys.argv)
        stats.elapsed = time.time() - time_start
        if Prefs.STATS:
            stats.print_stats()
        sys.exit(0)
    else:
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)

        time_start = time.time()
        resolve_name(query, RootZone, addResults=query)
        stats.elapsed = time.time() - time_start

        if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
            print('')
        query.print_full_answer()

        if Prefs.STATS:
            stats.print_stats()

        sys.exit(exit_status(query))
