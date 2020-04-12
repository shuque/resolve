"""
Main suite of functions to perform iterative DNS resolution.

"""

import time

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.dnssec

from reslib.common import Prefs, cache, stats, RootZone
from reslib.zone import Zone
from reslib.query import Query
from reslib.utils import make_query, send_query, is_referral
from reslib.dnssec import key_cache, load_keys, validate_all, \
    ds_rrset_matches_dnskey


def get_ns_addrs(zone, additional):
    """
    Populate nameserver addresses for zone from the additional section
    of a given referral message.

    To additionally resolve all non-glue NS record addresses, we need to
    supply the -n (NSRESOLVE) switch to this program. If no NS address
    records can be found in the additional section of the referral, we
    switch to NSRESOLVE mode.
    """

    needsGlue = []
    for nsname in zone.nslist:
        if nsname.is_subdomain(zone.name):
            needsGlue.append(nsname)
    needToResolve = list(set(zone.nslist) - set(needsGlue))

    for rrset in additional:
        if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            name = rrset.name
            for rr in rrset:
                if not zone.has_ns(name):
                    continue
                if (not Prefs.NSRESOLVE) or (name in needsGlue):
                    nsobj = cache.get_ns(name)
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or Prefs.NSRESOLVE:
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


def install_zone_in_cache(zonename, ns_rrset, ds_rrset, additional):
    """
    Install zone entry and associated info in global cache. Return
    zone object.
    """
    zone = cache.get_zone(zonename)
    if zone is None:
        zone = Zone(zonename, cache)
        for rr in ns_rrset:
            _ = zone.install_ns(rr.target)
        if ds_rrset:
            zone.install_ds(ds_rrset.to_rdataset())
    get_ns_addrs(zone, additional)
    return zone


def process_referral(message, query):
    """
    Process referral. Returns a zone object for the referred zone.
    The zone object is populated with the nameserver names, addresses,
    and if present, authenticated DS RRset data.
    """

    ns_rrset = ds_rrset = ds_rrsigs = None

    for rrset in message.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            if ns_rrset is None:
                ns_rrset = rrset
            else:
                raise ValueError("Multiple NS RRset found in referral")
        elif rrset.rdtype == dns.rdatatype.DS:
            if ds_rrset is None:
                ds_rrset = rrset
            else:
                raise ValueError("Multiple DS RRset found in referral")
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            if rrset.covers == dns.rdatatype.DS:
                if ds_rrsigs is None:
                    ds_rrsigs = rrset
                else:
                    raise ValueError("Multiple DS RRSIG sets found in referral")

    if ns_rrset is None:
        print("ERROR: unable to find NS RRset in referral response")
        return None

    zonename = ns_rrset.name
    if ds_rrset:
        if zonename != ds_rrset.name:
            raise ValueError("DS didn't match NS in referral message")
        if ds_rrsigs is None:
            raise ValueError("DS RRset has no signatures")
        ds_verified, _ = validate_all(ds_rrset, ds_rrsigs)
        if not ds_verified:
            raise ValueError("DS RRset failed to authenticate")

    if Prefs.VERBOSE and not query.quiet:
        print(">>        [Got Referral to zone: %s in %.3f s]" % \
              (zonename, query.elapsed_last))

    zone = install_zone_in_cache(zonename, ns_rrset, ds_rrset,
                                 message.additional)
    if Prefs.VERBOSE and not query.quiet:
        zone.print_details()

    return zone


def process_answer(response, query, addResults=None):
    """
    Process answer section, chasing aliases when needed.
    """

    cname_dict = {}              # dict of alias -> target

    # If minimizing, ignore answers for intermediate query names.
    # TODO: for DNSSEC, authenticate thse intermediate answers too.
    if query.qname != query.orig_qname:
        return

    if Prefs.VERBOSE and not query.quiet:
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
            if stats.cnt_cname >= Prefs.MAX_CNAME:
                print("ERROR: Too many ({}) CNAME indirections.".format(
                    Prefs.MAX_CNAME))
                return

    if cname_dict:
        final_alias = response.question[0].name
        while True:
            if final_alias in cname_dict:
                final_alias = cname_dict[final_alias]
            else:
                break
        cname_query = Query(final_alias, query.qtype, query.qclass,
                            Prefs.MINIMIZE)
        if addResults:
            addResults.cname_chain.append(cname_query)
        resolve_name(cname_query, cache.closest_zone(cname),
                     inPath=False, addResults=addResults)

    return


def process_response(response, query, addResults=None):
    """
    Process a DNS response. Returns rcode, answer message, zone referral.
    """

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


def send_query_zone(query, zone):
    """
    Send DNS query to nameservers of given zone
    """

    response = None

    if Prefs.VERBOSE and not query.quiet:
        print("\n>> Query: %s %s %s at zone %s" % \
               (query.qname, query.qtype, query.qclass, zone.name))

    msg = make_query(query.qname, query.qtype, query.qclass)

    nsaddr_list = zone.iplist_sorted_by_rtt()
    if not nsaddr_list:
        print("ERROR: No nameserver addresses found for zone: %s." % zone.name)
        return None

    time_start = time.time()
    for nsaddr in nsaddr_list:
        if stats.cnt_query1 + stats.cnt_query2 >= Prefs.MAX_QUERY:
            print("ERROR: Max number of queries ({}) exceeded.".format(
                Prefs.MAX_QUERY))
            return None
        if Prefs.VERBOSE and not query.quiet:
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


def match_ds(zone):
    """
    DS (Delegation Signer) processing: Authenticate the secure delegation
    to the zone, by fetching its DNSKEY RRset, authenticating the self
    signature on it, and matching one of the DNSKEYs to the (previously
    authenticated) DS data in the zone object.
    """

    dnskey_rrset, dnskey_rrsigs = fetch_dnskey(zone)
    if dnskey_rrsigs is None:
        raise ValueError("No signatures found for root DNSKEY set!")

    keylist = load_keys(dnskey_rrset)
    key_cache.install(zone.name, keylist)

    verified, failed = validate_all(dnskey_rrset, dnskey_rrsigs)
    if not verified:
        raise ValueError("Couldn't validate root DNSKEY RRset: {}".format(
            failed))

    for key in keylist:
        if not key.sep_flag:
            continue
        if ds_rrset_matches_dnskey(zone.dslist, key):
            zone.set_ds_verified(True)
            return True
    raise ValueError("DS RRset did not match DNSKEY RRset")


def resolve_name(query, zone, inPath=True, addResults=None):
    """
    Resolve a DNS query. addResults is an optional Query object to
    which the answer results are to be added.
    """

    curr_zone = zone
    repeatZone = False

    while stats.cnt_deleg < Prefs.MAX_DELEG:

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
                print("ERROR: referral: %s is not subdomain of %s" %
                      (referral.name, curr_zone.name))
                break
            curr_zone = referral
            if curr_zone.dslist:
                match_ds(curr_zone)

    if stats.cnt_deleg >= Prefs.MAX_DELEG:
        print("ERROR: Max levels of delegation ({}) reached.".format(
            Prefs.MAX_DELEG))

    return


def fetch_dnskey(zone):
    """
    Fetch DNSKEY RRset and signatures from specified zone.
    """

    qname = zone.name
    qtype = dns.rdatatype.from_text('DNSKEY')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass)
    query.set_quiet(True)

    msg = send_query_zone(query, zone)
    dnskey_rrset = msg.get_rrset(msg.answer, qname, 1, qtype)
    dnskey_rrsigs = msg.get_rrset(msg.answer, qname, 1,
                                  dns.rdatatype.RRSIG, covers=qtype)
    if dnskey_rrsigs is None:
        raise ValueError("No signatures found for root DNSKEY set!")
    return dnskey_rrset, dnskey_rrsigs


def initialize_dnssec():
    """
    Query root DNSKEY RRset, authenticate it with current trust
    anchor and install the authenticated set in the KeyCache.
    """

    dnskey_rrset, dnskey_rrsigs = fetch_dnskey(RootZone)

    if dnskey_rrsigs is None:
        raise ValueError("No signatures found for root DNSKEY set!")

    verified, failed = validate_all(dnskey_rrset, dnskey_rrsigs)
    if not verified:
        raise ValueError("Couldn't validate root DNSKEY RRset: {}".format(
            failed))

    key_cache.install(dns.name.root, load_keys(dnskey_rrset))
    return
