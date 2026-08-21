"""
Main suite of functions to perform iterative DNS resolution.

"""

import time

import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.dnssec

from reslib.exception import ResError
from reslib.deleg import (DELEG_RDTYPE, DELEGPARAM_RDTYPE,
                          build_slist, SLIST_UNUSABLE)
from reslib.zone import Zone
from reslib.query import Query
from reslib.rrset import RRset
from reslib.utils import (vprint_quiet, make_query_message, send_query,
                          is_referral)
from reslib.dnssec import (load_keys, validate_all, signer_on_path,
                           ds_rr_matches_dnskey, check_self_signature,
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
                if query.resolver.prefs.VERBOSE > 1:
                    print(("WARN: referral to {} has unrelated additional" +
                           "data: {} {}").format(zone.name,
                                                 rrset.name, rrset.rdtype))
                continue
            if not rrset.name.is_subdomain(zone.name):
                if query.resolver.prefs.VERBOSE > 1:
                    print("INFO: referral to {} has unneeded (sibling?) glue: {} {}".format(
                        zone.name, rrset.name,
                        dns.rdatatype.to_text(rrset.rdtype)))
            for rr in rrset:
                if (not query.resolver.prefs.NSRESOLVE) or (rrset.name in needsGlue):
                    nsobj = query.resolver.cache.get_ns(rrset.name)
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or query.resolver.prefs.NSRESOLVE:
        if query.resolver.prefs.VERBOSE > 1:
            print("INFO: NS addresses need to be explicitly resolved:")
            zone.print_nsinfo()
        for name in needToResolve:
            nsobj = query.resolver.cache.get_ns(name)
            if nsobj.iplist:
                continue
            for addrtype in ['A', 'AAAA']:
                nsquery = Query(name, addrtype, 'IN', is_nsquery=True, resolver=query.resolver)
                nsquery.quiet = True
                resolve_name(query.resolver, nsquery, query.resolver.cache.closest_zone(nsquery.qname))
                for ip in nsquery.get_answer_ip_list():
                    nsobj.install_ip(ip)

    return


def install_zone_in_cache(zonename, query, ns_srrset, ds_srrset):
    """
    Install zone entry and associated info in global cache. Return
    zone object.
    """
    zone = query.resolver.cache.get_zone(zonename)
    if zone is None:
        zone = Zone(zonename, query.resolver)
        zone.install_ns_rrset_ttl(ns_srrset.rrset.ttl)
        for rr in ns_srrset.rrset:
            _ = zone.install_ns(rr.target)
        if ds_srrset:
            zone.install_ds_rrset(ds_srrset.rrset)
    get_ns_addrs(zone, query)
    return zone


def authenticate_insecure_referral(query, zonename, install_cache=True):
    """
    Authenticate insecure referral. AUTHORITY section should have a
    signed NSEC/NSEC3 record that demonstrates that no DS record exists.
    However, the opt-out flag on the NSEC/NSEC3 records, if present may
    omit this requirement.

    install_cache is forwarded to get_rrset_dict. The DELEG path passes
    install_cache=False so that a stray NS accompanying the DELEG is not
    re-cached here (delext Section 5.2); the DELEG path installs the DELEG,
    DS and NSEC/NSEC3 RRsets selectively afterwards.
    """

    rrset_dict, _ = get_rrset_dict(query.resolver, query.response.authority,
                                   install_cache=install_cache)
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
            hashed_owner = get_hashed_owner(query.resolver, zonename, signer, nsec3_rdata)
            if (hashed_owner == rrname and
                not type_in_bitmap(dns.rdatatype.DS, nsec3_rdata) and
                not type_in_bitmap(dns.rdatatype.CNAME, nsec3_rdata)):
                authenticated = True
                if query.resolver.prefs.VERBOSE and not query.quiet:
                    print("# H({}) = {}".format(zonename,
                                                hashed_owner.labels[0].decode()))
            optout = nsec3_rdata.flags & 0x1

    if not authenticated and optout:
        nsec3_nxdomain_proof(query.resolver, zonename, signer, nsec3_set, optout=True,
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
        if query.resolver.prefs.DNSSEC:
            ref_prefix = "SECURE " if ds_srrset else "INSECURE "
        else:
            ref_prefix = None
        print("#        [{}Referral to zone: {} in {:.3f} s]".format(
            ref_prefix if ref_prefix else "",
            zonename, query.elapsed_last))


def adt_bitmap_consistent(nsec_rdata, deleg_present, ns_present):
    """Return True if an NSEC/NSEC3 type bitmap is consistent with the
    delegation types present in the referral (delext Section 6.2).

    The DELEG(61440) bit MUST be set iff a DELEG RRset is present in the
    Authority section: that is the anti-downgrade check -- a bitmap that
    proves a DELEG exists while the referral carries none (or vice versa)
    signals a stripped/injected DELEG.

    The NS direction is deliberately NOT checked. A "stacked" cut carries
    both NS and DELEG as zone truth, so its signed NSEC bitmap legitimately
    lists NS; but a DE=1 referral omits the NS RRset (the server sends the
    DELEG in its place, per delext Section 5.2). NS-in-bitmap vs
    NS-absent-from-Authority is thus a normal, non-tampered state. ns_present
    is retained for symmetry with the caller but does not gate the result.
    """
    if type_in_bitmap(DELEG_RDTYPE, nsec_rdata) != deleg_present:
        return False
    return True


def enforce_adt_proof(query, zonename, deleg_present, ns_present, rrset_dict):
    """Enforce the ADT delegation-type proof for a referral from a zone whose
    validated DNSKEY carries the ADT flag (delext Sections 6.2 / 8.2.1).

    Requires a validated NSEC or NSEC3 record matching the delegated name whose
    type bitmap is consistent with the delegation types present. Missing or
    inconsistent -> ResError (bogus).
    """
    for (rrname, rrtype) in rrset_dict:
        if rrtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            continue
        srrset = rrset_dict[(rrname, rrtype)]
        validate_rrset(srrset, query, silent=True)
        if rrtype == dns.rdatatype.NSEC:
            if rrname != zonename:
                continue
            if adt_bitmap_consistent(srrset.rrset[0], deleg_present, ns_present):
                return
            raise ResError(
                "ADT proof inconsistent for {} (referral tampered)".format(
                    zonename))
        else:  # NSEC3
            nsec3_rdata = srrset.rrset[0]
            signer = srrset.rrsig[0].signer
            hashed_owner = get_hashed_owner(query.resolver, zonename, signer,
                                            nsec3_rdata)
            if hashed_owner != rrname:
                continue
            if adt_bitmap_consistent(nsec3_rdata, deleg_present, ns_present):
                return
            raise ResError(
                "ADT proof inconsistent for {} (referral tampered)".format(
                    zonename))

    raise ResError(
        "ADT flag set for delegating zone but referral lacks NSEC/NSEC3 "
        "delegation-type proof for {}".format(zonename))


def _referral_zonename(deleg_srrset, ns_srrset):
    """The delegated owner name, from whichever delegation RRset is present."""
    if deleg_srrset is not None:
        return deleg_srrset.rrname
    if ns_srrset is not None:
        return ns_srrset.rrname
    raise ResError("Referral has neither DELEG nor NS RRset")


def process_referral(query, referring_zone=None):
    """
    Process referral. Returns a zone object for the referred zone.

    When DELEG is enabled (prefs.DELEG) and a DELEG RRset is present in the
    referral, the child zone's servers are sourced from the DELEG record and
    any accompanying NS is ignored (not validated, not cached). Secure/
    insecure status is still decided by the DS RRset.

    For the legacy NS path (DELEG disabled or absent), behaviour is unchanged:
    if the referring zone is signed, then if DS records are present they are
    authenticated, otherwise the lack of a secure referral is authenticated,
    and the returned zone object is populated with the nameserver names,
    addresses, and if present, DS RRset data.
    """
    ns_srrset = ds_srrset = deleg_srrset = None

    # Build the authority dict WITHOUT auto-caching so a stray NS accompanying
    # a DELEG can never be cached (delext Section 5.2). The legacy NS path
    # re-installs the relevant RRsets explicitly below.
    rrset_dict, _ = get_rrset_dict(query.resolver, query.response.authority,
                                   install_cache=False)

    for (rrname, rrtype) in rrset_dict:
        srrset = rrset_dict[(rrname, rrtype)]
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
        elif rrtype == DELEG_RDTYPE:
            if deleg_srrset is None:
                deleg_srrset = srrset
            else:
                raise ResError("Multiple DELEG RRset found in referral")

    follow_deleg = query.resolver.prefs.DELEG and deleg_srrset is not None

    # Anti-downgrade enforcement applies only when this resolver actually
    # sent DE=1 (prefs.DELEG). A resolver that did not send DE=1 expects a
    # traditional referral and has no delegation-type proof to demand; only
    # a DE=1 sender must detect a stripped/tampered referral (delext Section
    # 8.2.2). prefs.DELEG is local intent, so an on-path attacker who flips
    # the wire DE bit cannot suppress this check.
    adt_active = (query.resolver.prefs.DELEG and query.resolver.prefs.DNSSEC
                  and query.secure_so_far and not query.is_nsquery
                  and referring_zone is not None and referring_zone.adt)
    if adt_active:
        deleg_present = deleg_srrset is not None
        ns_present = ns_srrset is not None
        enforce_adt_proof(query, _referral_zonename(deleg_srrset, ns_srrset),
                          deleg_present, ns_present, rrset_dict)

    if follow_deleg:
        return _process_deleg_referral(query, rrset_dict, deleg_srrset,
                                       ds_srrset, referring_zone)
    return _process_ns_referral(query, rrset_dict, ns_srrset, ds_srrset)


def _install_referral_rrsets(query, rrset_dict, keep_types):
    """Install only the referral RRsets whose type is in keep_types (plus the
    NSEC/NSEC3 records needed for proofs), so a stray NS is never cached."""
    proof_types = (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
    for (_, rrtype), srrset in rrset_dict.items():
        if rrtype in keep_types or rrtype in proof_types:
            query.resolver.cache.install_rrset(srrset)


def _process_ns_referral(query, rrset_dict, ns_srrset, ds_srrset):
    """Legacy NS-based referral (DELEG disabled or absent). Behaviour is
    preserved from the pre-DELEG process_referral: everything except NS is
    validated, and NS + DS (+ NSEC/NSEC3) are installed in the cache."""
    for (rrname, rrtype), srrset in rrset_dict.items():
        if rrtype != dns.rdatatype.NS:
            validate_rrset(srrset, query, silent=True)
    _install_referral_rrsets(
        query, rrset_dict,
        keep_types=(dns.rdatatype.NS, dns.rdatatype.DS))

    if ns_srrset is None:
        raise ResError("Unable to find NS RRset in referral response")

    zonename = ns_srrset.rrname
    if query.resolver.prefs.DNSSEC and query.secure_so_far and not query.is_nsquery:
        if ds_srrset:
            if zonename != ds_srrset.rrname:
                raise ResError("DS didn't match NS in referral message")
        else:
            authenticate_insecure_referral(query, zonename)
            if not query.is_nsquery:
                query.secure_so_far = False
    else:
        if not query.is_nsquery:
            query.secure_so_far = False

    print_referral_trace(query, zonename, ds_srrset)
    zone = install_zone_in_cache(zonename, query, ns_srrset, ds_srrset)
    if vprint_quiet(query):
        zone.print_details()
    return zone


def _process_deleg_referral(query, rrset_dict, deleg_srrset, ds_srrset,
                            referring_zone):
    """DELEG-based referral: source servers from the DELEG record; ignore NS.

    Accompanying NS is neither validated nor cached (delext Section 5.2).
    A DELEG-only cut (no NS) is legal here, unlike the legacy NS path. A
    present-but-unusable DELEG raises a terminal ResError with NO NS fallback
    (draft-ietf-deleg Section 4.4).
    """
    zonename = deleg_srrset.rrname

    # Validate the DELEG RRset like DS when in a secure chain, and decide
    # secure/insecure via the DS RRset exactly as the NS path does.
    if query.resolver.prefs.DNSSEC and query.secure_so_far and not query.is_nsquery:
        validate_rrset(deleg_srrset, query, silent=True)
        if ds_srrset:
            validate_rrset(ds_srrset, query, silent=True)
            if zonename != ds_srrset.rrname:
                raise ResError("DS didn't match DELEG in referral message")
        else:
            authenticate_insecure_referral(query, zonename,
                                           install_cache=False)
            if not query.is_nsquery:
                query.secure_so_far = False
    else:
        if not query.is_nsquery:
            query.secure_so_far = False

    # Install DELEG + DS + NSEC/NSEC3 proofs; NEVER install NS.
    _install_referral_rrsets(
        query, rrset_dict,
        keep_types=(DELEG_RDTYPE, dns.rdatatype.DS))

    print_referral_trace(query, zonename, ds_srrset)

    # Reuse/create the zone object.
    zone = query.resolver.cache.get_zone(zonename)
    if zone is None:
        zone = Zone(zonename, query.resolver)
    zone.install_ns_rrset_ttl(deleg_srrset.rrset.ttl)
    if ds_srrset:
        zone.install_ds_rrset(ds_srrset.rrset)

    # Build the server list from the DELEG record.
    result = _build_deleg_slist(query, deleg_srrset.rrset, zonename)
    if result.state == SLIST_UNUSABLE:
        raise ResError(
            "DELEG for {} present but unusable; no NS fallback".format(
                zonename))
    zone.install_deleg_addresses(result.addresses, deleg_srrset.rrset)

    if vprint_quiet(query):
        zone.print_details()
    return zone


def _build_deleg_slist(query, deleg_rrset, zonename):
    """Drive build_slist with resolver-backed callbacks for server-name and
    include-delegparam resolution.

    CONTROLLER RULING option (b): the build_slist / fetch_delegparam contract
    does not surface how many CNAME/DNAME hops a nested resolution consumed,
    so draft-ietf-deleg Section 4.2 step 7 ("a CNAME/DNAME step counts the
    same as a DELEGPARAM step against the loop limit") is not enforced through
    a single shared budget. This is safe against unbounded recursion because
    every path is independently bounded:
      * the include-delegparam chain depth is bounded by max_chain
        (prefs.MAX_DELEGPARAM) inside build_slist;
      * each nested resolve_name (both server-name address resolution and the
        DELEGPARAM fetch) follows CNAME/DNAME only up to the resolver-global
        MAX_CNAME counter, which raises ResError when exceeded.
    The divergence is thus a matter of using two finite budgets instead of one
    shared budget; there is no unbounded-loop hole.
    """

    def resolve_addrs(name):
        ips = []
        for addrtype in ['A', 'AAAA']:
            nsquery = Query(name, addrtype, 'IN', is_nsquery=True,
                            resolver=query.resolver)
            nsquery.quiet = True
            resolve_name(query.resolver, nsquery,
                         query.resolver.cache.closest_zone(nsquery.qname))
            ips.extend(nsquery.get_answer_ip_list())
        return ips

    def fetch_delegparam(name):
        dpquery = Query(name, DELEGPARAM_RDTYPE, 'IN', resolver=query.resolver)
        dpquery.quiet = True
        resolve_name(query.resolver, dpquery,
                     query.resolver.cache.closest_zone(name))
        msg = dpquery.response
        if msg is None:
            return None
        return msg.get_rrset(msg.answer, name, dns.rdataclass.IN,
                             DELEGPARAM_RDTYPE)

    return build_slist(deleg_rrset, zonename, resolve_addrs, fetch_delegparam,
                       max_chain=query.resolver.prefs.MAX_DELEGPARAM)


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
    # A DNAME whose target lies at or below its own owner is self-
    # referential: the rewrite stays within the owner's subtree, so the
    # same DNAME re-applies without bound (RFC 6672, Table 1). Fail fast
    # rather than grinding through the CNAME-indirection limit.
    if dname_target.is_subdomain(dname_owner):
        raise ResError("DNAME loop: target {} is at or below owner {}".format(
            dname_target, dname_owner))
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
        if query.resolver.prefs.DNSSEC and synthetic_cname  and \
           (final_alias == synthetic_cname.name)  and \
           (cname_dict[final_alias] == synthetic_cname[0].target):
            srrset = rrset_dict[(final_alias, dns.rdatatype.CNAME)]
            srrset.set_validated()
        final_alias = cname_dict[final_alias]

    cname_query = Query(final_alias, query.qtype, query.qclass, resolver=query.resolver)
    cname_query.secure_so_far = query.secure_so_far
    resolve_name(query.resolver, cname_query, query.resolver.cache.closest_zone(cname_query.qname),
                 addResults=addResults)
    if addResults:
        addResults.latest_rcode = cname_query.response.rcode()
        addResults.cname_chain.append(cname_query)

    return


def get_rrset_dict(resolver, section, install_cache=True):
    """
    Create and return dict of RRset objects from given message section.
    By default, installs the RRset object in the RRset cache also.
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

    if install_cache:
        for _, srrset in rrset_dict.items():
            resolver.cache.install_rrset(srrset)

    return rrset_dict, found_sigs


def get_ns_ds_dnskey(zonename, referring_query=None):
    """
    Get NS/DS/DNSKEY for zone. This routine is usually invoked when
    the iterative resolution path encounters a signature with an unknown
    signer, e.g. if there are layers of zones on the same nameservers.
    """

    if referring_query.resolver.prefs.VERBOSE and not referring_query.is_nsquery:
        print("# FETCH: NS/DS/DNSKEY for {}".format(zonename))
    zone = get_zone(referring_query.resolver, zonename)
    ds_rrset, ds_rrsigs = fetch_ds(referring_query.resolver, zonename)
    if ds_rrset is None:
        referring_query.secure_so_far = False
        if vprint_quiet(referring_query):
            print("# INFO: found INSECURE Referral to {}".format(zonename))
            zone.print_details()
    else:
        ds_verified, ds_failed = validate_all(referring_query.resolver, ds_rrset, ds_rrsigs)
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

    rrset_dict, _ = get_rrset_dict(query.resolver, query.response.authority)
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
            hashed_next = get_hashed_owner(query.resolver, next_closer, signer, nsec3[0])
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

    if not srrset.rrsig:
        raise ResError("No RRSIG for {}/{}".format(
            srrset.rrname, dns.rdatatype.to_text(srrset.rrtype)))

    for sig_rr in srrset.rrsig:
        signer = sig_rr.signer
        # Don't fetch keys for a signer that isn't on the path to the
        # RRset owner (RFC 4035 5.3.1); validate_all discards it anyway.
        if not signer_on_path(srrset.rrname, signer):
            continue
        if not query.resolver.key_cache.has_key(signer):
            get_ns_ds_dnskey(signer, referring_query=query)

    verified, failed = validate_all(query.resolver, srrset.rrset, srrset.rrsig)
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

    rrset_dict, _ = get_rrset_dict(query.resolver, query.response.authority)
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
        nsec3_nxdomain_proof(query.resolver, query.qname, signer, nsec3_set, quiet=query.quiet)
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

    rrset_dict, _ = get_rrset_dict(query.resolver, query.response.authority)
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
            hashed_owner = get_hashed_owner(query.resolver, query.qname, signer, nsec3[0])
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
        wildcard = nsec3_wildcard_nodata_proof(query.resolver,
                                               query.qname,
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

    closest_zone = query.resolver.cache.closest_zone(query.qname)
    labels = query.qname.relativize(closest_zone.name).labels
    zone_labels = closest_zone.name.labels
    for label in reversed(labels):
        zone_labels = (label,) + zone_labels
        zonename = dns.name.Name(zone_labels)
        zone = get_zone(query.resolver, zonename)
        if zone is None:
            continue
        ds_rrset, ds_rrsigs = fetch_ds(query.resolver, zonename)
        if ds_rrset is None:
            query.secure_so_far = False
            if vprint_quiet(query):
                print("# INFO: found INSECURE Referral to {}".format(zonename))
                zone.print_details()
            return
        ds_verified, ds_failed = validate_all(query.resolver, ds_rrset, ds_rrsigs)
        if not ds_verified:
            raise ResError("DS RRset {} failed to authenticate: {}".format(
                zonename, ds_failed))
        zone.install_ds_rrset(ds_rrset)
        match_ds_zone(zone, query)
    raise ValueError("Can't find insecure referral, yet response is unsigned.")


def check_signature(query, srrset, found_sigs=False):
    """
    Check signatures if needed. If secure_so_far is true (i.e. we were
    expecting signatures) and no signatures are present, then call
    function to find an insecure referral above us. Otherwise validate
    the signature.
    """
    if not (query.resolver.prefs.DNSSEC and query.secure_so_far):
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

    rrset_dict, found_sigs = get_rrset_dict(query.resolver, query.response.answer)

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
            if query.resolver.prefs.VERBOSE:
                print(srrset.rrset.to_text())
            cname_target = srrset.rrset[0].target
            cname_dict[srrset.rrset.name] = cname_target
            query.resolver.stats.cnt_cname += 1
            if query.resolver.stats.cnt_cname >= query.resolver.prefs.MAX_CNAME:
                raise ResError("Too many ({}) CNAME indirections.".format(
                    query.resolver.prefs.MAX_CNAME))

    if query.qname != query.orig_qname:
        if vprint_quiet(query):
            print("# INFO: Ignoring AA=1 answer for intermediate name")
    elif cname_dict:
        process_cname(query, rrset_dict, cname_dict, synthetic_cname,
                      addResults=addResults)
    return


def process_response(query, addResults=None, referring_zone=None):
    """
    Process a DNS response. Returns rcode & zone referral.
    """

    if query.response.rcode() == dns.rcode.NOERROR:

        if is_referral(query.response):                            # Referral
            referral = process_referral(query, referring_zone=referring_zone)
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
            if (query.resolver.prefs.DNSSEC and not query.is_nsquery
                    and not query.dnskey_novalidate and query.secure_so_far):
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
        elif (query.resolver.prefs.DNSSEC and not query.is_nsquery
              and not query.dnskey_novalidate and query.secure_so_far):
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


def check_query_count_limit(resolver):
    """Check query count limit"""
    if resolver.stats.cnt_query1 + resolver.stats.cnt_query2 >= resolver.prefs.MAX_QUERY:
        raise ResError("Max number of queries ({}) exceeded.".format(
            resolver.prefs.MAX_QUERY))


def get_zone_addresses(zone):
    """Return list of nameserver addresses for zone"""
    result = zone.iplist_shuffled()
    if not result:
        raise ResError("No nameserver addresses found for zone: {}.".format(
            zone.name))
    return result


def zone_failure_message(zone, errors):
    """Build terminal error for a zone whose servers were all exhausted.

    errors is a list of (address, reason) tuples. We surface the distinct
    set of reasons (first-seen order) so the real cause -- e.g. a DS/DNSKEY
    mismatch that every server reports identically -- is pulled up to the
    top-level error instead of a generic 'all servers failed'.
    """
    base = "Queries to all servers for zone {} failed.".format(zone.name)
    if not errors:
        return base
    reasons = []
    for _, reason in errors:
        if reason not in reasons:
            reasons.append(reason)
    label = "Cause" if len(reasons) == 1 else "Causes"
    return "{} {}: {}".format(base, label, "; ".join(reasons))


def send_query_zone(query, zone, addResults=None):
    """Send DNS query to nameservers of given zone"""

    msg = make_query_message(query)
    time_start = time.time()

    errors = []
    for nsaddr in get_zone_addresses(zone):
        check_query_count_limit(query.resolver)
        print_query_trace(query, zone, nsaddr.addr)
        response = None
        try:
            response = send_query(msg, nsaddr, query, newid=True)
        except OSError as e:
            print("OSError {}: {}: {}".format(e.errno, e.strerror, nsaddr.addr))
            errors.append((nsaddr.addr, "OSError {}: {}".format(e.errno, e.strerror)))
            continue
        if not response:
            if vprint_quiet(query):
                print("WARNING: no response from {}".format(nsaddr))
            errors.append((nsaddr.addr, "no response"))
            continue
        if response.rcode() not in [dns.rcode.NOERROR, dns.rcode.NXDOMAIN]:
            query.resolver.stats.cnt_fail += 1
            rcode_text = dns.rcode.to_text(response.rcode())
            if vprint_quiet(query):
                print("WARNING: response {} from {}".format(
                    rcode_text, nsaddr.addr))
            errors.append((nsaddr.addr, "response {}".format(rcode_text)))
            continue
        # process and return response; but goto next server on error
        query.elapsed_last = time.time() - time_start
        query.response = response
        try:
            return process_response(query, addResults=addResults, referring_zone=zone)
        except ResError as e:
            if vprint_quiet(query):
                print("WARNING: {} error {}".format(nsaddr.addr, e))
            errors.append((nsaddr.addr, str(e)))
            continue

    raise ResError(zone_failure_message(zone, errors))


def resolve_name(resolver, query, zone, addResults=None):
    """
    Resolve a DNS query. addResults is an optional Query object to
    which the answer results are to be added.
    """

    curr_zone = zone
    repeatZone = False

    while resolver.stats.cnt_deleg < resolver.prefs.MAX_DELEG:

        if query.minimize:
            if repeatZone:
                query.prepend_label()
                repeatZone = False
            else:
                query.set_minimized(curr_zone)

        rc, referral = send_query_zone(query, curr_zone, addResults=addResults)

        if rc == dns.rcode.NXDOMAIN:
            if resolver.prefs.VIOLATE and (query.minimize) and (query.qname != query.orig_qname):
                repeatZone = True
            else:
                break

        if not referral:
            if (not query.minimize) or (query.qname == query.orig_qname):
                break
            elif query.minimize:
                repeatZone = True
        else:
            resolver.stats.cnt_deleg += 1
            if not referral.name.is_subdomain(curr_zone.name):
                print("ERROR: referral: {} is not subdomain of {}".format(
                    referral.name, curr_zone.name))
                break
            curr_zone = referral
            if resolver.prefs.DNSSEC:
                if curr_zone.dslist:
                    match_ds_zone(curr_zone, referring_query=query)
                else:
                    if vprint_quiet(query) and not query.is_nsquery:
                        check_isolated_dnskey(curr_zone)

    if resolver.stats.cnt_deleg >= resolver.prefs.MAX_DELEG:
        print("ERROR: Max number of delegation ({}) reached.".format(
            resolver.prefs.MAX_DELEG))

    return


def get_zone(resolver, zonename):
    """
    Get zone object for given zonename, from cache, if present.
    If not present, query nameservers and addresses for the zone,
    create a new zone object and return it.
    """

    zone = resolver.cache.get_zone(zonename)
    if zone:
        return zone

    qtype = dns.rdatatype.from_text('NS')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(zonename, qtype, qclass, is_nsquery=True, resolver=resolver)
    query.set_quiet(True)

    _ = send_query_zone(query, resolver.cache.closest_zone(query.qname))
    msg = query.response

    ns_rrset = msg.get_rrset(msg.answer, zonename, qclass, qtype)
    if ns_rrset is None:
        ns_rrset = msg.get_rrset(msg.authority, zonename, qclass, qtype)
    if ns_rrset is None:
        return None

    zone = Zone(zonename, resolver)
    zone.install_ns_rrset_ttl(ns_rrset.ttl)
    for ns_rr in ns_rrset:
        _ = zone.install_ns(ns_rr.target)

    # Populate nameserver addresses from the glue in the additional
    # section of the NS response (as the referral path does). This is
    # essential when the zone's nameservers are in-bailiwick (e.g. a
    # parent and child stacked on the same servers, such as . and arpa.):
    # those names can only be resolved from glue, and attempting to
    # resolve them iteratively would deadlock on this very zone, which
    # has just been installed in the cache without any addresses.
    get_ns_addrs(zone, query)

    return zone


def fetch_ds(resolver, zonename):
    """
    Fetch DS RRset and signatures for specified zone. Note: DS has
    to be queried in parent zone.
    """

    qname = zonename
    qtype = dns.rdatatype.from_text('DS')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass, resolver=resolver)
    query.set_quiet(True)

    startZone = resolver.cache.closest_zone(zonename.parent())

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
        keylist, _ = check_self_signature(zone.resolver, dnskey_rrset,
                                          dnskey_rrsigs)
    except ResError:
        print("WARNING: {} DNSKEY self signature did not validate".format(zone))

    for key in keylist:
        print(key)


def match_ds_ksklist(zone, nsaddr, ksk_list, referring_query):
    """
    Match DS rdataset to given KSK list. The provided ksk_list is typically
    the subset of DNSKEYs that sign the DNSKEY RRset.
    Returns True if any of them match, and populates each DS RR object with
    the corresponding matched DNSKEYs.
    """
    Matched = False

    for ds in zone.dslist:
        for key in ksk_list:
            if not key.zone_flag:
                continue
            if ds_rr_matches_dnskey(zone.resolver, ds.rdata, key):
                Matched = True
                ds.add_matched(key)
                if zone.resolver.prefs.VERBOSE and not referring_query.is_nsquery:
                    #print("DEBUG: query", referring_query, zone.name, nsaddr.addr)
                    print("# DS match OK: {} {}: {} {}".format(zone.name, nsaddr.addr, ds, key))
            else:
                if zone.resolver.prefs.VERBOSE:
                    #print("DEBUG: query", referring_query, zone.name, nsaddr.addr)
                    print("# DS match FAIL: {} {}: {} {}".format(zone.name, nsaddr.addr, ds, key))
    return Matched


def match_ds_zone(zone, referring_query):
    """
    DS (Delegation Signer) processing: Authenticate the secure delegation
    to the zone, by fetching its DNSKEY RRset, authenticating the self
    signature on it, and matching one of the signing DNSKEYs to the
    (previously authenticated) DS data in the zone object.
    """

    if not supported_algorithm_present(zone.dslist):
        # The DS RRset is authenticated but references only DNSSEC
        # algorithms we don't support. Per RFC 4035 Section 5.2 (and
        # RFC 6840 Section 5.11), this is not a validation failure: the
        # child zone must be treated as insecure/unsigned rather than
        # bogus, and resolution must continue. (Degrade-to-insecure only
        # applies when NO supported algorithm is present; a DS set with
        # even one supported algorithm still validates via that path.)
        if referring_query and vprint_quiet(referring_query):
            algs = sorted({int(ds.rdata.algorithm) for ds in zone.dslist})
            print("# INFO: no supported DNSSEC algorithm (DS alg {}) for "
                  "zone {}; treating as insecure".format(
                      ",".join(str(a) for a in algs), zone.name))
        if referring_query is not None:
            referring_query.secure_so_far = False
        return

    qname = zone.name
    qtype = dns.rdatatype.from_text('DNSKEY')
    qclass = dns.rdataclass.from_text('IN')
    query = Query(qname, qtype, qclass, resolver=zone.resolver)
    query.set_quiet(True)
    query.dnskey_novalidate = True
    msg = make_query_message(query)

    authenticated = False

    keylist = None

    for nsaddr in get_zone_addresses(zone):
        check_query_count_limit(zone.resolver)
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
            zone.resolver.stats.cnt_fail += 1
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
            keylist, sigkeys = check_self_signature(zone.resolver,
                                                    dnskey_rrset,
                                                    dnskey_rrsigs)
        except ResError as e:
            print("ERROR: DNSKEY did not validate: {}".format(e))
            continue

        if match_ds_ksklist(zone, nsaddr, sigkeys, referring_query):
            zone.set_secure(True)
            zone.resolver.key_cache.install(zone.name, keylist)
            authenticated = True
            r = RRset(dnskey_rrset.name, dnskey_rrset.rdtype, rrset=dnskey_rrset,
                        rrsig=dnskey_rrsigs)
            zone.resolver.cache.install_rrset(r)
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

    zone.adt = any(getattr(k, "adt_flag", False) for k in keylist)

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
    query = Query(qname, qtype, qclass, resolver=zone.resolver)
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


def initialize_dnssec(resolver):
    """
    Query root DNSKEY RRset, authenticate it with current trust
    anchor and install the authenticated set in the KeyCache.
    """
    dnskey_rrset, dnskey_rrsigs = fetch_dnskey(resolver.root_zone)

    if dnskey_rrsigs is None:
        raise ResError("No signatures found for root DNSKEY set!")

    verified, failed = validate_all(resolver, dnskey_rrset, dnskey_rrsigs)
    if not verified:
        raise ResError("Couldn't validate root DNSKEY RRset: {}".format(
            failed))

    result, errors = load_keys(dnskey_rrset)
    if errors:
        print("ERROR: initialzing DNSSEC: {}".format(errors))
    resolver.key_cache.install(dns.name.root, result)
    resolver.root_zone.adt = any(getattr(k, "adt_flag", False) for k in result)

    return


def print_root_zone(resolver):
    """Print root zone details"""
    resolver.root_zone.print_details()
    if resolver.prefs.DNSSEC:
        for key in resolver.key_cache.get_keys(resolver.root_zone.name):
            print(key)
