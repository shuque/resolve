"""
Main suite of functions to perform iterative DNS resolution.

"""

import time

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.dnssec

from reslib.prefs import Prefs
from reslib.cache import cache, RootZone
from reslib.stats import stats
from reslib.exception import ResError
from reslib.zone import Zone
from reslib.query import Query
from reslib.rrset import RRset
from reslib.utils import (vprint_quiet, make_query_message, send_query,
                          is_referral)
from reslib.dnssec import (key_cache, load_keys, validate_all,
                           ds_rrset_matches_dnskey, check_self_signature,
                           type_in_bitmap, get_hashed_owner,
                           nsec_covers_name, nsec3_covers_name,
                           nsec_nxdomain_proof, nsec3_nxdomain_proof,
                           nsec3_wildcard_nodata_proof,
                           supported_algorithm_present)


def get_ns_addrs(zone, query):
    """
    Populate nameserver addresses for zone from the additional section
    of a given referral message.

    To additionally resolve all non-glue NS record addresses, we need to
    supply the -n (NSRESOLVE) switch to this program. If no NS address
    records can be found in the additional section of the referral, we
    switch to NSRESOLVE mode.
    """

    additional = query.response.additional
    needsGlue = []
    for nsname in zone.nslist:
        if nsname.is_subdomain(zone.name):
            needsGlue.append(nsname)
    needToResolve = list(set(zone.nslist) - set(needsGlue))

    for rrset in additional:
        if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            if not zone.has_ns(rrset.name):
                if Prefs.VERBOSE > 1:
                    print(("WARN: referral to {} has unrelated additional" +
                           "data: {} {}").format(zone.name,
                                                 rrset.name, rrset.rdtype))
                continue
            if not rrset.name.is_subdomain(zone.name):
                if Prefs.VERBOSE > 1:
                    print("INFO: referral to {} has unneeded (sibling?) glue: {} {}".format(
                        zone.name, rrset.name,
                        dns.rdatatype.to_text(rrset.rdtype)))
            for rr in rrset:
                if (not Prefs.NSRESOLVE) or (rrset.name in needsGlue):
                    nsobj = cache.get_ns(rrset.name)
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or Prefs.NSRESOLVE:
        if Prefs.VERBOSE > 1:
            print("INFO: NS addresses need to be explicitly resolved:")
            zone.print_nsinfo()
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


def install_zone_in_cache(zonename, query, ns_srrset, ds_srrset):
    """
    Install zone entry and associated info in global cache. Return
    zone object.
    """
    zone = cache.get_zone(zonename)
    if zone is None:
        zone = Zone(zonename, cache)
        zone.install_ns_rrset_ttl(ns_srrset.rrset.ttl)
        for rr in ns_srrset.rrset:
            _ = zone.install_ns(rr.target)
        if ds_srrset:
            zone.install_ds_rrset(ds_srrset.rrset)
    get_ns_addrs(zone, query)
    return zone


def authenticate_insecure_referral(query, zonename):
    """
    Authenticate insecure referral. AUTHORITY section should have a
    signed NSEC/NSEC3 record that demonstrates that no DS record exists.
    However, the opt-out flag on the NSEC/NSEC3 records, if present may
    omit this requirement.
    """

    rrset_dict, _ = get_rrset_dict(query.response.authority)
    authenticated = False
    optout = False
    nsec3_set = []

    for (rrname, rrtype) in rrset_dict:
        if rrtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            continue
        srrset = rrset_dict[(rrname, rrtype)]
        validate_rrset(srrset, query, silent=False)
        if rrtype == dns.rdatatype.NSEC:
            if zonename != rrname:
                continue
            if not type_in_bitmap(dns.rdatatype.DS, srrset.rrset[0]):
                authenticated = True
        elif rrtype == dns.rdatatype.NSEC3:
            nsec3_set.append(srrset.rrset)
            nsec3_rdata = srrset.rrset[0]
            signer = srrset.rrsig[0].signer
            hashed_owner = get_hashed_owner(zonename, signer, nsec3_rdata)
            if (hashed_owner == rrname and
                not type_in_bitmap(dns.rdatatype.DS, nsec3_rdata) and
                not type_in_bitmap(dns.rdatatype.CNAME, nsec3_rdata)):
                authenticated = True
                if Prefs.VERBOSE and not query.quiet:
                    print("# H({}) = {}".format(zonename,
                                                hashed_owner.labels[0].decode()))
            optout = nsec3_rdata.flags & 0x1

    if not authenticated and optout:
        nsec3_nxdomain_proof(zonename, signer, nsec3_set, optout=True,
                             quiet=query.quiet)
        if vprint_quiet(query):
            print("# INFO: NSEC3 opt-out insecure referral")

    if not optout and not authenticated:
        raise ResError("Failed authenticating insecure referral: {}".format(
            zonename))


def print_referral_trace(query, zonename, ds_srrset):
    """
    Print Referral trace: {secure/insecure, zone, response time}
    """
    if vprint_quiet(query):
        if Prefs.DNSSEC:
            ref_prefix = "SECURE " if ds_srrset else "INSECURE "
        else:
            ref_prefix = None
        print("#        [{}Referral to zone: {} in {:.3f} s]".format(
            ref_prefix if ref_prefix else "",
            zonename, query.elapsed_last))


def process_referral(query):
    """
    Process referral. Returns a zone object for the referred zone. If
    referring zone is signed, then if DS records are present, they are
    authenticated, otherwise the lack of secure referral is authenticated.
    The returned zone object is populated with the nameserver names,
    addresses, and if present, DS RRset data.
    """

    ns_srrset = ds_srrset = None

    rrset_dict, _ = get_rrset_dict(query.response.authority)

    for (rrname, rrtype) in rrset_dict:
        srrset = rrset_dict[(rrname, rrtype)]
        if rrtype != dns.rdatatype.NS:
            validate_rrset(srrset, query, silent=True)
        if rrtype == dns.rdatatype.NS:
            if ns_srrset is None:
                ns_srrset = srrset
            else:
                raise ResError("Multiple NS RRset found in referral")
        elif rrtype == dns.rdatatype.DS:
            if ds_srrset is None:
                ds_srrset = srrset
            else:
                raise ResError("Multiple DS RRset found in referral")

    if ns_srrset is None:
        raise ResError("Unable to find NS RRset in referral response")

    zonename = ns_srrset.rrname
    if key_cache.SecureSoFar and not query.is_nsquery:
        if ds_srrset:
            if zonename != ds_srrset.rrname:
                raise ResError("DS didn't match NS in referral message")
        else:
            authenticate_insecure_referral(query, zonename)
            if not query.is_nsquery:
                key_cache.SecureSoFar = False
    else:
        if not query.is_nsquery:
            key_cache.SecureSoFar = False

    print_referral_trace(query, zonename, ds_srrset)

    zone = install_zone_in_cache(zonename, query, ns_srrset, ds_srrset)

    if vprint_quiet(query):
        zone.print_details()

    return zone


def synthesize_cname(dname_rrset, query):
    """
    Synthesize CNAME for queryname from DNAME RR.
    """
    dname_owner = dname_rrset.name
    dname_rr = dname_rrset[0]
    dname_target = dname_rr.target
    qname = query.qname
    if not qname.is_subdomain(dname_owner):
        raise ResError("DNAME not ancestor of qname: {} {}".format(
            dname_owner, qname))
    cname_target = qname.relativize(dname_owner).concatenate(dname_target)
    cname_rrset = dns.rrset.RRset(qname, query.qclass, dns.rdatatype.CNAME)
    rdataset = dns.rdataset.Rdataset(query.qclass, dns.rdatatype.CNAME)
    rdataset.update_ttl(dname_rrset.ttl)
    cname_rdata = dns.rdtypes.ANY.CNAME.CNAME(query.qclass,
                                              dns.rdatatype.CNAME,
                                              cname_target)
    rdataset.add(cname_rdata)
    cname_rrset.update(rdataset)
    return cname_rrset


def process_cname(query, rrset_dict, cname_dict, synthetic_cname,
                  addResults=None):
    """
    Process CNAMEs in the response.
    """

    seen = []
    final_alias = query.response.question[0].name
    while True:
        if final_alias in seen:
            raise ResError("CNAME loop detected: {}".format(final_alias))
        seen.append(final_alias)
        if final_alias not in cname_dict:
            break
        if Prefs.DNSSEC and synthetic_cname  and \
           (final_alias == synthetic_cname.name)  and \
           (cname_dict[final_alias] == synthetic_cname[0].target):
            srrset = rrset_dict[(final_alias, dns.rdatatype.CNAME)]
            srrset.set_validated()
        final_alias = cname_dict[final_alias]

    cname_query = Query(final_alias, query.qtype, query.qclass)
    resolve_name(cname_query, cache.closest_zone(cname_query.qname),
                 addResults=addResults)
    if addResults:
        addResults.latest_rcode = cname_query.response.rcode()
        addResults.cname_chain.append(cname_query)

    return


def get_rrset_dict(section):
    """
    Create and return dict of RRset objects from given message section.
    Also returns a boolean that indicates whether signed RRs were found.
    """

    rrset_dict = {}
    found_sigs = False

    for rrset in section:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            found_sigs = True
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

    return rrset_dict, found_sigs


def get_ns_ds_dnskey(zonename, referring_query=None):
    """
    Get NS/DS/DNSKEY for zone. This routine is usually invoked when
    the iterative resolution path encounters a signature with an unknown
    signer.
    """

    if Prefs.VERBOSE and not referring_query.is_nsquery:
        print("# FETCH: NS/DS/DNSKEY for {}".format(zonename))
    zone = get_zone(zonename)
    ds_rrset, ds_rrsigs = fetch_ds(zonename)
    ds_verified, ds_failed = validate_all(ds_rrset, ds_rrsigs)
    if not ds_verified:
        raise ResError("DS RRset {} failed to authenticate: {}".format(
            zonename, ds_failed))
    zone.install_ds_rrset(ds_rrset)
    if vprint_quiet(referring_query):
        zone.print_details()
    match_ds_zone(zone, referring_query=referring_query)
    return


def validate_wildcard(srrset, query):
    """
    If RRset was synthesized from a wildcard, authenticate that no
    closer match exists (except if the query is for the wildcard itself).
    """

    wildcard = srrset.wildcard()
    if wildcard is None or wildcard == srrset.rrname:
        return
    query.wildcard = wildcard

    wildcard_base = dns.name.Name(wildcard.labels[1:])
    next_label = srrset.rrname.relativize(wildcard_base).labels[-1]
    next_closer = dns.name.Name((next_label,) + wildcard_base.labels)
    query.wildcard = wildcard
    if vprint_quiet(query):
        print("# INFO: Wildcard match: {}".format(wildcard))

    rrset_dict, _ = get_rrset_dict(query.response.authority)
    authenticated = False

    for (rrname, rrtype) in rrset_dict:
        if rrtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            continue
        srrset = rrset_dict[(rrname, rrtype)]
        validate_rrset(srrset, query, silent=True)
        if rrtype == dns.rdatatype.NSEC:
            nsec = srrset.rrset
            if nsec_covers_name(nsec, next_closer):
                authenticated = True
                if vprint_quiet(query):
                    print("# INFO: NSEC no closer: {}".format(nsec))
        elif rrtype == dns.rdatatype.NSEC3:
            nsec3 = srrset.rrset
            signer = srrset.rrsig[0].signer
            hashed_next = get_hashed_owner(next_closer, signer, nsec3[0])
            if nsec3_covers_name(nsec3, hashed_next, signer):
                authenticated = True
                if vprint_quiet(query):
                    print("# INFO next closer: {} {}".format(
                        next_closer, hashed_next.labels[0].decode()))
                    print("# INFO: NSEC3: {}".format(nsec3))

    if not authenticated:
        raise ResError("Failed wildcard no closer match proof: {}".format(
            wildcard))


def validate_rrset(srrset, query, silent=False):
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
        get_ns_ds_dnskey(signer, referring_query=query)

    verified, failed = validate_all(srrset.rrset, srrset.rrsig)
    if not verified:
        rrstring = "{}/{}".format(srrset.rrname,
                                  dns.rdatatype.to_text(srrset.rrtype))
        raise ResError("Validation fail: {}, keys={}".format(rrstring,
                                                             failed))
    validate_wildcard(srrset, query)

    srrset.set_validated()
    if not silent and vprint_quiet(query):
        for line in srrset.rrset.to_text().split('\n'):
            print("# SECURE: {}".format(line))


def authenticate_nxdomain(query):
    """
    Attempt to authenticate NXDOMAIN response. All RRsets in authority
    section should be signed and validated, an SOA should be present,
    and NSEC or NSEC3 records that prove the non-existence of the name
    and the non-existence of a wildcard that could have synthesized the
    name must be present.
    """

    rrset_dict, _ = get_rrset_dict(query.response.authority)
    nsec_set = []
    nsec3_set = []
    seen_soa = False
    signers = []

    for (rrname, rrtype) in rrset_dict:
        srrset = rrset_dict[(rrname, rrtype)]
        validate_rrset(srrset, query)
        if rrtype == dns.rdatatype.SOA:
            seen_soa = True
        elif rrtype == dns.rdatatype.NSEC:
            signer = srrset.rrsig[0].signer
            if signer not in signers:
                signers.append(signer)
            nsec_set.append(srrset.rrset)
        elif rrtype == dns.rdatatype.NSEC3:
            signer = srrset.rrsig[0].signer
            if signer not in signers:
                signers.append(signer)
            nsec3_set.append(srrset.rrset)

    if len(signers) > 1:
        raise ResError("Response with multiple NSEC/3 signers.")

    if not seen_soa:
        raise ResError("NXDOMAIN response failed to include SOA RRset.")

    if not (nsec_set or nsec3_set):
        raise ResError("No NSEC/3 records found in NXDOMAIN response.")

    if nsec3_set:
        nsec3_nxdomain_proof(query.qname, signer, nsec3_set, quiet=query.quiet)
    elif nsec_set:
        nsec_nxdomain_proof(query.qname, signer, nsec_set)

    query.dnssec_secure = True


def authenticate_nodata(query):
    """
    Attempt to authenticate NODATA response. All RRsets in authority
    section should be signed and validated, an SOA should be present,
    and at least one NSEC or NSEC3 record should deny the existence
    of the rrtype at the query name.
    For NSEC3, if routine NODATA proof fails, attempt wildcard NODATA
    proof.
    """

    rrset_dict, _ = get_rrset_dict(query.response.authority)
    nsec3_set = []

    authenticated = False
    seen_soa = False

    for (rrname, rrtype) in rrset_dict:
        srrset = rrset_dict[(rrname, rrtype)]
        validate_rrset(srrset, query)
        if rrtype == dns.rdatatype.SOA:
            seen_soa = True
        elif rrtype == dns.rdatatype.NSEC:
            wildcard = srrset.wildcard()
            if wildcard is not None:
                if wildcard != rrname:
                    continue
                else:
                    query.wildcard = wildcard
                    if vprint_quiet(query):
                        print("# INFO: Wildcard match: {}".format(wildcard))
            elif query.qname != rrname:
                if (nsec_covers_name(srrset.rrset, query.qname) and
                    srrset.rrset[0].next.is_subdomain(query.qname)):
                    authenticated = True
                    query.ent = query.qname
                    if vprint_quiet(query):
                        print("# INFO: Empty Non-Terminal found")
                else:
                    continue
            if (not type_in_bitmap(query.qtype, srrset.rrset[0]) and
                not type_in_bitmap(dns.rdatatype.CNAME, srrset.rrset[0])):
                authenticated = True
        elif rrtype == dns.rdatatype.NSEC3:
            nsec3 = srrset.rrset
            nsec3_rdata = srrset.rrset[0]
            signer = srrset.rrsig[0].signer
            optout = nsec3_rdata.flags & 0x1
            nsec3_set.append(nsec3)
            hashed_owner = get_hashed_owner(query.qname, signer, nsec3[0])
            if optout and nsec3_covers_name(nsec3, hashed_owner, signer):
                authenticated = True
                if vprint_quiet(query):
                    print("# INFO: OptOut H({}) = {}".format(
                        query.qname, hashed_owner))
                continue
            if hashed_owner != rrname:
                continue
            if not nsec3_rdata.windows:
                query.ent = query.qname
                if vprint_quiet(query):
                    print("# INFO: Empty Non-Terminal found")
            if (not type_in_bitmap(query.qtype, nsec3_rdata) and
                not type_in_bitmap(dns.rdatatype.CNAME, nsec3_rdata)):
                authenticated = True
                if vprint_quiet(query):
                    print("# INFO: H({}) = {}".format(
                        query.qname, hashed_owner))

    if not authenticated and nsec3_set:
        wildcard = nsec3_wildcard_nodata_proof(query.qname,
                                               query.qtype,
                                               signer,
                                               nsec3_set,
                                               quiet=query.quiet)
        authenticated = True
        query.wildcard = wildcard
        if vprint_quiet(query):
            print("# INFO: wildcard NODATA for {}".format(wildcard))

    if not seen_soa:
        raise ResError("NODATA response failed to include SOA RRset.")

    if not authenticated:
        raise ResError("Failed to authenticate NODATA response.")

    if query.qname == query.orig_qname:
        query.dnssec_secure = True


def find_insecure_referral(query):
    """
    Response had no signatures, yet our last state in the DNSSEC
    chain was secure. This is usually because of servers that host
    layers of zones and subzones. So there should be some intermediary
    zone that we have not yet encountered that has an insecure referral.
    Search down from closest enclosing secure zone to query name, label
    by label, until we find and authenticate it, otherwise raise an
    exception.
    """

    closest_zone = cache.closest_zone(query.qname)
    labels = query.qname.relativize(closest_zone.name).labels
    zone_labels = closest_zone.name.labels
    for label in reversed(labels):
        zone_labels = (label,) + zone_labels
        zonename = dns.name.Name(zone_labels)
        zone = get_zone(zonename)
        if zone is None:
            continue
        ds_rrset, ds_rrsigs = fetch_ds(zonename)
        if ds_rrset is None:
            key_cache.SecureSoFar = False
            if vprint_quiet(query):
                print("# INFO: found INSECURE Referral to {}".format(zonename))
                zone.print_details()
            return
        ds_verified, ds_failed = validate_all(ds_rrset, ds_rrsigs)
        if not ds_verified:
            raise ResError("DS RRset {} failed to authenticate: {}".format(
                zonename, ds_failed))
        zone.install_ds_rrset(ds_rrset)
        match_ds_zone(zone)
    raise ValueError("Can't find insecure referral, yet response is unsigned.")


def check_signature(query, srrset, found_sigs=False):
    """
    Check signatures if needed. If SecureSoFar is true (i.e. we were
    expecting signatures) and no signatures are present, then call
    function to find an insecure referral above us. Otherwise validate
    the signature.
    """
    if not key_cache.SecureSoFar:
        return
    if query.is_nsquery or query.dnskey_novalidate:
        return
    if found_sigs is False:
        find_insecure_referral(query)
    else:
        if srrset.rrsig:
            validate_rrset(srrset, query)


def process_answer(query, addResults=None):
    """
    Process answer section, chasing aliases when needed.
    """

    cname_dict = {}              # dict of CNAME owner: target
    synthetic_cname = None       # only set if DNAME encountered

    if vprint_quiet(query):
        print("#        [Got answer in {:.3f} s]".format(query.elapsed_last))

    if query.qname != query.orig_qname:
        addResults = None

    rrset_dict, found_sigs = get_rrset_dict(query.response.answer)

    for (rrname, rrtype) in rrset_dict:
        srrset = rrset_dict[(rrname, rrtype)]
        check_signature(query, srrset, found_sigs=found_sigs)

        if rrtype == query.qtype and rrname == query.qname:
            query.got_answer = True
            query.answer_rrset.append(srrset)
            if addResults:
                addResults.add_to_full_answer(srrset)
        elif rrtype == dns.rdatatype.DNAME:
            query.answer_rrset.append(srrset)
            if addResults:
                addResults.add_to_full_answer(srrset)
            if vprint_quiet(query):
                print(srrset.rrset.to_text())
            synthetic_cname = synthesize_cname(srrset.rrset, query)
        elif rrtype == dns.rdatatype.CNAME:
            query.answer_rrset.append(srrset)
            if addResults:
                addResults.add_to_full_answer(srrset)
            if Prefs.VERBOSE:
                print(srrset.rrset.to_text())
            cname_target = srrset.rrset[0].target
            cname_dict[srrset.rrset.name] = cname_target
            stats.cnt_cname += 1
            if stats.cnt_cname >= Prefs.MAX_CNAME:
                raise ResError("Too many ({}) CNAME indirections.".format(
                    Prefs.MAX_CNAME))

    if query.qname != query.orig_qname:
        if vprint_quiet(query):
            print("# INFO: Ignoring AA=1 answer for intermediate name")
    elif cname_dict:
        process_cname(query, rrset_dict, cname_dict, synthetic_cname,
                      addResults=addResults)
    return


def process_response(query, addResults=None):
    """
    Process a DNS response. Returns rcode & zone referral.
    """

    if query.response.rcode() == dns.rcode.NOERROR:

        if is_referral(query.response):                            # Referral
            referral = process_referral(query)
            return query.response.rcode(), referral

        if not query.response.answer:                              # NODATA
            if vprint_quiet(query):
                print("#        [Got answer in {:.3f} s]".format(
                    query.elapsed_last))
            if not query.quiet and query.qname == query.orig_qname:
                query.nodata = True
                if addResults:
                    addResults.nodata = True
                if vprint_quiet(query):
                    print("ERROR: NODATA: {} of type {} not found".format(
                        query.qname,
                        dns.rdatatype.to_text(query.qtype)))
            if Prefs.DNSSEC and not query.is_nsquery and key_cache.SecureSoFar:
                authenticate_nodata(query)
            return query.response.rcode(), None

        process_answer(query, addResults=addResults)               # Answer
        return query.response.rcode(), None

    if query.response.rcode() == dns.rcode.NXDOMAIN:               # NXDOMAIN
        if vprint_quiet(query):
            print("#        [Got answer in {:.3f} s]".format(
                query.elapsed_last))
        if vprint_quiet(query):
            print("ERROR: NXDOMAIN: {} not found".format(query.qname))
        if query.response.answer:
            process_answer(query, addResults=addResults)
        elif Prefs.DNSSEC and not query.is_nsquery and key_cache.SecureSoFar:
            authenticate_nxdomain(query)

    return query.response.rcode(), None


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
    result = zone.iplist_shuffled()
    if not result:
        raise ResError("No nameserver addresses found for zone: {}.".format(
            zone.name))
    return result


def send_query_zone(query, zone, addResults=None):
    """Send DNS query to nameservers of given zone"""

    msg = make_query_message(query)
    time_start = time.time()

    for nsaddr in get_zone_addresses(zone):
        check_query_count_limit()
        print_query_trace(query, zone, nsaddr.addr)
        response = None
        try:
            response = send_query(msg, nsaddr, query, newid=True)
        except OSError as e:
            print("OSError {}: {}: {}".format(e.errno, e.strerror, nsaddr.addr))
            continue
        if not response:
            if vprint_quiet(query):
                print("WARNING: no response from {}".format(nsaddr))
            continue
        if response.rcode() not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
            stats.cnt_fail += 1
            if vprint_quiet(query):
                print("WARNING: response {} from {}".format(
                    dns.rcode.to_text(response.rcode()), nsaddr.addr))
            continue
        # process and return response; but goto next server on error
        query.elapsed_last = time.time() - time_start
        query.response = response
        try:
            return process_response(query, addResults=addResults)
        except ResError as e:
            if vprint_quiet(query):
                print("WARNING: {} error {}".format(nsaddr.addr, e))
            continue

    raise ResError("Queries to all servers for zone {} failed.".format(
        zone.name))


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

        rc, referral = send_query_zone(query, curr_zone, addResults=addResults)

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
            if Prefs.DNSSEC:
                if curr_zone.dslist:
                    match_ds_zone(curr_zone, referring_query=query)
                else:
                    if vprint_quiet(query):
                        check_isolated_dnskey(curr_zone)

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
    query = Query(zonename, qtype, qclass, is_nsquery=True)
    query.set_quiet(True)

    _ = send_query_zone(query, cache.closest_zone(query.qname))
    msg = query.response

    ns_rrset = msg.get_rrset(msg.answer, zonename, qclass, qtype)
    if ns_rrset is None:
        ns_rrset = msg.get_rrset(msg.authority, zonename, qclass, qtype)
    if ns_rrset is None:
        return None

    zone = Zone(zonename, cache)
    zone.install_ns_rrset_ttl(ns_rrset.ttl)
    for ns_rr in ns_rrset:
        _ = zone.install_ns(ns_rr.target)
        nsobj = cache.get_ns(ns_rr.target)
        if nsobj.iplist:
            continue
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

    _ = send_query_zone(query, startZone)
    msg = query.response

    ds_rrset = msg.get_rrset(msg.answer, qname, qclass, qtype)

    if ds_rrset is None:
        authenticate_insecure_referral(query, zonename)
        return None, None

    ds_rrsigs = msg.get_rrset(msg.answer, qname, qclass,
                              dns.rdatatype.RRSIG, covers=qtype)
    if ds_rrsigs is None:
        raise ResError("No signatures found for {} DS set!".format(
            zonename))
    return ds_rrset, ds_rrsigs


def check_isolated_dnskey(zone):
    """
    With verbose mode, for an insecure delegation, this routine attempts
    to obtain the DNSKEY RRset anyway, and it if exists, verify its self
    signature, and print information about the keys.
    """

    try:
        dnskey_rrset, dnskey_rrsigs = fetch_dnskey(zone)
    except ResError:
        return

    try:
        keylist, _ = check_self_signature(dnskey_rrset, dnskey_rrsigs)
    except ResError:
        print("WARNING: {} DNSKEY self signature did not validate".format(zone))

    for key in keylist:
        print(key)


def match_ds_ksklist(ds_rdatalist, ksk_list):
    """
    Match DS rdataset to given KSK list. Returns True if any of them match.
    """
    for key in ksk_list:
        if not key.zone_flag:
            continue
        if ds_rrset_matches_dnskey(ds_rdatalist, key):
            return True
    return False


def match_ds_zone(zone, referring_query=None):
    """
    DS (Delegation Signer) processing: Authenticate the secure delegation
    to the zone, by fetching its DNSKEY RRset, authenticating the self
    signature on it, and matching one of the signing DNSKEYs to the
    (previously authenticated) DS data in the zone object.
    """

    if not supported_algorithm_present(zone.dslist):
        raise ResError("No supported algorithms in DS set found")

    qname = zone.name
    qtype = dns.rdatatype.from_text('DNSKEY')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass)
    query.set_quiet(True)
    query.dnskey_novalidate = True
    msg = make_query_message(query)

    authenticated = False

    keylist = None

    for nsaddr in get_zone_addresses(zone):
        check_query_count_limit()
        response = None
        try:
            response = send_query(msg, nsaddr, query, newid=True)
        except OSError as e:
            print("OSError {}: {}: {}".format(e.errno,
                                              e.strerror,
                                              nsaddr.addr))
            continue
        if not response:
            print("WARNING: no {} DNSKEY response from {}".format(qname,
                                                                  nsaddr))
            continue
        if response.rcode() not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
            stats.cnt_fail += 1
            print("WARNING: response {} from {}".format(
                dns.rcode.to_text(response.rcode()), nsaddr.addr))
            continue
        dnskey_rrset = response.get_rrset(response.answer,
                                          qname, qclass, qtype)
        dnskey_rrsigs = response.get_rrset(response.answer,
                                           qname, qclass, dns.rdatatype.RRSIG,
                                           covers=qtype)
        if dnskey_rrsigs is None:
            print("ERROR: No signatures for {} DNSKEY RRset at {}".format(
                zone.name, nsaddr.addr))
            continue

        try:
            keylist, sigkeys = check_self_signature(dnskey_rrset,
                                                    dnskey_rrsigs)
        except ResError as e:
            print("ERROR: DNSKEY did not validate: {}".format(e))
            continue

        if match_ds_ksklist(zone.dslist, sigkeys):
            zone.set_secure(True)
            key_cache.install(zone.name, keylist)
            authenticated = True
            break

        if referring_query and vprint_quiet(referring_query):
            print("ERROR: DS did not match DNSKEY: {} at {}".format(
                zone.name, nsaddr.addr))

    if not authenticated:
        if referring_query and vprint_quiet(referring_query):
            if keylist:
                print('')
                for key in keylist:
                    print(key)
        raise ResError("DS did not match DNSKEY for {}".format(zone.name))

    if referring_query and vprint_quiet(referring_query):
        for key in keylist:
            print(key)


def fetch_dnskey(zone):
    """
    Fetch DNSKEY RRset and signatures from specified zone.
    """

    qname = zone.name
    qtype = dns.rdatatype.from_text('DNSKEY')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass)
    query.set_quiet(True)
    query.dnskey_novalidate = True

    _ = send_query_zone(query, zone)
    msg = query.response
    dnskey_rrset = msg.get_rrset(msg.answer, qname, qclass, qtype)
    dnskey_rrsigs = msg.get_rrset(msg.answer, qname, qclass,
                                  dns.rdatatype.RRSIG, covers=qtype)
    if dnskey_rrset is None:
        raise ResError("No {} DNSKEY RRset found in answer".format(
            zone.name))
    if dnskey_rrsigs is None:
        raise ResError("No signatures found for {} DNSKEY RRset".format(
            zone.name))
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


def print_root_zone():
    """Print root zone details"""
    RootZone.print_details()
    if Prefs.DNSSEC:
        for key in key_cache.get_keys(RootZone.name):
            print(key)
