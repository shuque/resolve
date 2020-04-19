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
from reslib.exception import ResError
from reslib.zone import Zone
from reslib.query import Query
from reslib.nameserver import NameServer
from reslib.rrset import RRset
from reslib.utils import (vprint_quiet, make_query_message, send_query,
                          is_referral)
from reslib.dnssec import (key_cache, load_keys, validate_all,
                           ds_rrset_matches_dnskey, check_dnskey_self_signature)


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
            if not zone.has_ns(rrset.name):
                continue
            for rr in rrset:
                if (not Prefs.NSRESOLVE) or (rrset.name in needsGlue):
                    nsobj = cache.get_ns(rrset.name)
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or Prefs.NSRESOLVE:
        for name in needToResolve:
            nsobj = cache.get_ns(name)
            if nsobj.iplist:
                continue
            for addrtype in ['A', 'AAAA']:
                nsquery = Query(name, addrtype, 'IN', is_nsquery=True)
                nsquery.quiet = True
                resolve_name(nsquery, cache.closest_zone(nsquery.qname))
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


def print_referral_trace(query, zonename, has_ds=False):
    """
    Print Referral trace: {secure/insecure, zone, response time}
    """
    if vprint_quiet(query):
        if Prefs.DNSSEC:
            ref_prefix = "SECURE " if has_ds else "INSECURE "
        else:
            ref_prefix = None
        print("#        [{}Referral to zone: {} in {:.3f} s]".format(
            ref_prefix if ref_prefix else "",
            zonename, query.elapsed_last))


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
                raise ResError("Multiple NS RRset found in referral")
        elif rrset.rdtype == dns.rdatatype.DS:
            if ds_rrset is None:
                ds_rrset = rrset
            else:
                raise ResError("Multiple DS RRset found in referral")
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            if rrset.covers == dns.rdatatype.DS:
                if ds_rrsigs is None:
                    ds_rrsigs = rrset
                else:
                    raise ResError("Multiple DS RRSIG sets found in referral")

    if ns_rrset is None:
        raise ResError("Unable to find NS RRset in referral response")

    zonename = ns_rrset.name
    if key_cache.SecureSoFar and ds_rrset:
        if zonename != ds_rrset.name:
            raise ResError("DS didn't match NS in referral message")
        if ds_rrsigs is None:
            raise ResError("DS RRset has no signatures")
        ds_verified, _ = validate_all(ds_rrset, ds_rrsigs)
        if not ds_verified:
            raise ResError("DS RRset failed to authenticate")
    else:
        # TODO: authenticate lack of DS, if possible
        if not query.is_nsquery:
            key_cache.SecureSoFar = False

    print_referral_trace(query, zonename, ds_rrset)

    zone = install_zone_in_cache(zonename, ns_rrset, ds_rrset,
                                 message.additional)
    if vprint_quiet(query):
        zone.print_details()

    return zone


def get_rrset_dict(section):
    """get dict of RRset objects from given message section"""

    rrset_dict = {}

    for rrset in section:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            if (rrset.name, rrset.covers) in rrset_dict:
                r = rrset_dict[(rrset.name, rrset.covers)]
                r.set_rrsig(rrset)
            else:
                r = RRset(rrset.name, rrset.covers, rrsig=rrset)
                rrset_dict[(rrset.name, rrset.covers)] = r
        else:
            if (rrset.name, rrset.rdtype) in rrset_dict:
                r = rrset_dict[(rrset.name, rrset.rdtype)]
                r.set_rrset(rrset)
            else:
                r = RRset(rrset.name, rrset.rdtype, rrset=rrset)
                rrset_dict[(rrset.name, rrset.rdtype)] = r

    return rrset_dict


def get_ns_ds_dnskey(zonename):
    """Get NS/DS/DNSKEY for zone"""

    zone = get_zone(zonename)
    ds_rrset, ds_rrsigs = fetch_ds(zonename)
    ds_verified, _ = validate_all(ds_rrset, ds_rrsigs)
    if not ds_verified:
        raise ResError("DS RRset failed to authenticate")
    zone.install_ds(ds_rrset.to_rdataset())
    match_ds(zone)
    return


def validate_rrset(srrset, query):
    """
    Validate signed RRset object

    If we don't have the signer's DNSKEY, we have to fetch the
    DNSKEY and corresponding DS, authenticate, and cache it.
    One situation in which this can happen is if parent, child
    zones are on the same nameserver. Another situation is when
    we need to lookup NS addresses from referrals whose name
    server names are in an offpath zone.
    """

    signer = srrset.rrsig[0].signer
    if not key_cache.has_key(signer):
        if Prefs.VERBOSE:
            print("# FETCH: NS/DS/DNSKEY for {}".format(signer))
        get_ns_ds_dnskey(signer)

    verified, failed = validate_all(srrset.rrset, srrset.rrsig)
    if verified:
        srrset.set_validated()
        if vprint_quiet(query):
            for line in srrset.rrset.to_text().split('\n'):
                print("SECURE: {}".format(line))
    else:
        raise ResError("Validation fail: {}".format(failed))


def process_answer(response, query, addResults=None):
    """Process answer section, chasing aliases when needed."""

    cname_dict = {}              # dict of alias -> target

    # qname minimization (ignore); TODO: validate also?
    if query.qname != query.orig_qname:
        if vprint_quiet(query):
            print("#        [Ignoring AA=1 answer for intermediate name]")
        return

    if vprint_quiet(query):
        print("#        [Got answer in {:.3f} s]".format(query.elapsed_last))

    rrset_dict = get_rrset_dict(response.answer)

    for key in rrset_dict:
        rrname, rrtype = key
        srrset = rrset_dict[key]
        if key_cache.SecureSoFar and srrset.rrsig and not query.is_nsquery:
            validate_rrset(srrset, query)

        if rrtype == query.qtype and rrname == query.qname:
            query.got_answer = True
            query.answer_rrset.append(srrset)
            if addResults:
                addResults.full_answer_rrset.append(srrset)
        elif rrtype == dns.rdatatype.DNAME:
            query.answer_rrset.append(srrset)
            if addResults:
                addResults.full_answer_rrset.append(srrset)
            if Prefs.VERBOSE:
                print(srrset.rrset.to_text())
        elif rrtype == dns.rdatatype.CNAME:
            query.answer_rrset.append(srrset)
            if addResults:
                addResults.full_answer_rrset.append(srrset)
            if Prefs.VERBOSE:
                print(srrset.rrset.to_text())
            cname = srrset.rrset[0].target
            cname_dict[srrset.rrset.name] = srrset.rrset[0].target
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
        cname_query = Query(final_alias, query.qtype, query.qclass)
        if addResults:
            addResults.cname_chain.append(cname_query)
        resolve_name(cname_query, cache.closest_zone(cname),
                     addResults=addResults)

    return


def process_response(response, query, addResults=None):
    """
    Process a DNS response. Returns rcode & zone referral.
    """

    query.rcode = response.rcode()

    if query.rcode == dns.rcode.NOERROR:

        if is_referral(response):                                  # Referral
            referral = process_referral(response, query)
            return query.rcode, referral

        if not response.answer:                                    # NODATA
            if vprint_quiet(query):
                print("#        [Got answer in {:.3f} s]".format(
                    query.elapsed_last))
            if not query.quiet and query.qname == query.orig_qname:
                print("ERROR: NODATA: {} of type {} not found".format(
                    query.qname,
                    dns.rdatatype.to_text(query.qtype)))
            return query.rcode, None

        process_answer(response, query, addResults=addResults)     # Answer
        return query.rcode, None

    if query.rcode == dns.rcode.NXDOMAIN:                          # NXDOMAIN
        if vprint_quiet(query):
            print("#        [Got answer in {:.3f} s]".format(
                query.elapsed_last))
        if not query.quiet:
            print("ERROR: NXDOMAIN: {} not found".format(query.qname))

    return query.rcode, None


def print_query_trace(query, zone, address):
    """Print query trace"""
    if vprint_quiet(query):
        print("\n# QUERY: {} {} {} at zone {} address {}".format(
            query.qname,
            dns.rdatatype.to_text(query.qtype),
            dns.rdataclass.to_text(query.qclass),
            zone.name,
            address))
    return


def check_query_count_limit():
    """Check query count limit"""
    if stats.cnt_query1 + stats.cnt_query2 >= Prefs.MAX_QUERY:
        raise ResError("Max number of queries ({}) exceeded.".format(
            Prefs.MAX_QUERY))


def get_zone_addresses(zone):
    """Return list of nameserver addresses for zone"""
    result = zone.iplist_sorted_by_rtt()
    if not result:
        raise ResError("No nameserver addresses found for zone: {}.".format(
            zone.name))
    return result


def send_query_zone(query, zone):
    """Send DNS query to nameservers of given zone"""

    msg = make_query_message(query)
    nsaddr_list = get_zone_addresses(zone)
    time_start = time.time()

    for nsaddr in nsaddr_list:
        check_query_count_limit()
        print_query_trace(query, zone, nsaddr.addr)
        response = None
        try:
            response = send_query(msg, nsaddr, query, newid=True)
        except OSError as e:
            print("OSError {}: {}: {}".format(e.errno, e.strerror, nsaddr.addr))
            continue
        if response:
            if response.rcode() not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
                stats.cnt_fail += 1
                print("WARNING: response {} from {}".format(
                    dns.rcode.to_text(response.rcode()), nsaddr.addr))
                continue
            break
    else:
        raise ResError("Queries to all servers for zone {} failed.".format(
            zone.name))

    query.elapsed_last = time.time() - time_start
    return response


def resolve_name(query, zone, addResults=None):
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
        query.responses.append(response)

        rc, referral = process_response(response, query, addResults=addResults)

        if rc == dns.rcode.NXDOMAIN:
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
            if not referral.name.is_subdomain(curr_zone.name):
                print("ERROR: referral: {} is not subdomain of {}".format(
                    referral.name, curr_zone.name))
                break
            curr_zone = referral
            if curr_zone.dslist:
                match_ds(curr_zone, referring_query=query)

    if stats.cnt_deleg >= Prefs.MAX_DELEG:
        print("ERROR: Max number of delegation ({}) reached.".format(
            Prefs.MAX_DELEG))

    return


def get_zone(zonename):
    """
    Get zone object for given zonename, from cache, if present.
    If not present, query nameservers and addresses for the zone,
    create a new zone object and return it.
    """

    zone = cache.get_zone(zonename)
    if zone:
        return zone

    qtype = dns.rdatatype.from_text('NS')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(zonename, qtype, qclass)
    query.set_quiet(True)
    msg = send_query_zone(query, cache.closest_zone(query.qname))

    zone = Zone(zonename, cache)
    ns_rrset = msg.get_rrset(msg.answer, zonename, qclass, qtype)

    for ns_rr in ns_rrset:
        _ = zone.install_ns(ns_rr.target)
        nsobj = cache.get_ns(ns_rr.target)
        if nsobj and nsobj.iplist:
            continue
        nsobj = NameServer(ns_rr.target)
        for addrtype in ['A', 'AAAA']:
            query = Query(ns_rr.target, addrtype, 'IN', is_nsquery=True)
            query.quiet = True
            resolve_name(query, cache.closest_zone(query.qname))
            for ip in query.get_answer_ip_list():
                nsobj.install_ip(ip)

    return zone


def fetch_ds(zonename):
    """
    Fetch DS RRset and signatures for specified zone. Note: DS has
    to be queried in parent zone.
    """

    qname = zonename
    qtype = dns.rdatatype.from_text('DS')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass)
    query.set_quiet(True)

    startZone = cache.closest_zone(zonename.parent())

    msg = send_query_zone(query, startZone)
    ds_rrset = msg.get_rrset(msg.answer, qname, qclass, qtype)
    ds_rrsigs = msg.get_rrset(msg.answer, qname, qclass,
                              dns.rdatatype.RRSIG, covers=qtype)

    if ds_rrset is None:
        raise ResError("No DS RRset for {} found.".format(zonename))

    if ds_rrsigs is None:
        raise ResError("No signatures found for {} DS set!".format(
            zonename))
    return ds_rrset, ds_rrsigs


def match_ds(zone, referring_query=None):
    """
    DS (Delegation Signer) processing: Authenticate the secure delegation
    to the zone, by fetching its DNSKEY RRset, authenticating the self
    signature on it, and matching one of the signing DNSKEYs to the
    (previously authenticated) DS data in the zone object.
    """

    dnskey_rrset, dnskey_rrsigs = fetch_dnskey(zone)
    if dnskey_rrsigs is None:
        raise ResError("No signatures found for root DNSKEY set!")

    keylist = load_keys(dnskey_rrset)
    sigkeys = check_dnskey_self_signature(dnskey_rrset, dnskey_rrsigs, keylist)

    if referring_query and Prefs.VERBOSE and not referring_query.quiet:
        for key in keylist:
            print("DNSKEY: {} {} {} {}".format(
                key.name, key.flags, key.keytag, key.algorithm))

    for key in sigkeys:
        if not key.sep_flag:
            continue
        if ds_rrset_matches_dnskey(zone.dslist, key):
            zone.set_ds_verified(True)
            key_cache.install(zone.name, keylist)
            return True

    raise ResError("DS did not match DNSKEY for {}".format(zone.name))


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
    dnskey_rrset = msg.get_rrset(msg.answer, qname, qclass, qtype)
    dnskey_rrsigs = msg.get_rrset(msg.answer, qname, qclass,
                                  dns.rdatatype.RRSIG, covers=qtype)
    if dnskey_rrsigs is None:
        raise ResError("No signatures found for root DNSKEY set!")
    return dnskey_rrset, dnskey_rrsigs


def initialize_dnssec():
    """
    Query root DNSKEY RRset, authenticate it with current trust
    anchor and install the authenticated set in the KeyCache.
    """

    dnskey_rrset, dnskey_rrsigs = fetch_dnskey(RootZone)

    if dnskey_rrsigs is None:
        raise ResError("No signatures found for root DNSKEY set!")

    verified, failed = validate_all(dnskey_rrset, dnskey_rrsigs)
    if not verified:
        raise ResError("Couldn't validate root DNSKEY RRset: {}".format(
            failed))

    key_cache.install(dns.name.root, load_keys(dnskey_rrset))
    key_cache.SecureSoFar = True
    return
