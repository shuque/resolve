#!/usr/bin/env python

"""

resolve.py

Perform an iterative resolution of a DNS name, type, class,
starting from the root DNS servers.

Author: Shumon Huque <shuque - @ - gmail.com>

"""

import os, sys, getopt, time, random
import dns.message, dns.query, dns.rdatatype, dns.rcode, dns.dnssec


PROGNAME   = os.path.basename(sys.argv[0])
VERSION    = "0.14"

TIMEOUT    = 3                            # Query timeout in seconds
RETRIES    = 2                            # Number of retries per server
RETRY      = 1                            # of full list (not implemented yet)
MAX_CNAME  = 10                           # Max #CNAME indirections
MAX_QUERY  = 300                          # Max number of queries
MAX_DELEG  = 26                           # Max number of delegations
UDPSIZE    = 1460                         # UDP payload size advertisement
WANT_DNSSEC = False


# root server names and addresses
ROOTHINTS = [
    ("a.root-servers.net.", "198.41.0.4"),
    ("a.root-servers.net.", "2001:503:ba3e::2:30"),
    ("b.root-servers.net.", "192.228.79.201"),
    ("b.root-servers.net.", "2001:500:200::b"),
    ("c.root-servers.net.", "192.33.4.12"),
    ("c.root-servers.net.", "2001:500:2::c"),
    ("d.root-servers.net.", "199.7.91.13"),
    ("d.root-servers.net.", "2001:500:2d::d"),
    ("e.root-servers.net.", "192.203.230.10"),
    ("e.root-servers.net.", "2001:500:a8::e"),
    ("f.root-servers.net.", "192.5.5.241"),
    ("f.root-servers.net.", "2001:500:2f::f"),
    ("g.root-servers.net.", "192.112.36.4"),
    ("g.root-servers.net.", "2001:500:12::d0d"),
    ("h.root-servers.net.", "198.97.190.53"),
    ("h.root-servers.net.", "2001:500:1::53"),
    ("i.root-servers.net.", "192.36.148.17"),
    ("i.root-servers.net.", "2001:7fe::53"),
    ("j.root-servers.net.", "192.58.128.30"),
    ("j.root-servers.net.", "2001:503:c27::2:30"),
    ("k.root-servers.net.", "193.0.14.129"),
    ("k.root-servers.net.", "2001:7fd::1"),
    ("l.root-servers.net.", "199.7.83.42"),
    ("l.root-servers.net.", "2001:500:9f::42"),
    ("m.root-servers.net.", "2001:dc3::35"),
    ("m.root-servers.net.", "202.12.27.33"),
]

# RootZone object
RootZone   = None                         # Populated by get_root_zone()


class Prefs:
    """Preferences"""
    DEBUG      = False                    # -d: Print debugging output?
    MINIMIZE   = False                    # -m: Do qname minimization?
    TCPONLY    = False                    # -t: Use TCP only
    VERBOSE    = False                    # -v: Trace query->zone path
    VIOLATE    = False                    # -x: ENT nxdomain workaround
    STATS      = False                    # -s: Print statistics
    NSRESOLVE  = False                    # -n: Resolve all NS addresses
    BATCHFILE  = None                     # -b: batch file mode


class Stats:
    """Statistics counters"""

    def __init__(self):
        self.cnt_cname        = 0
        self.cnt_query1       = 0                  # regular queries
        self.cnt_query2       = 0                  # NS address queries
        self.cnt_fail         = 0
        self.cnt_tcp          = 0
        self.cnt_tcp_fallback = 0
        self.cnt_deleg        = 0
        self.delegation_depth = 0

    def update_query(self, is_nsQuery=False, tcp=False):
        if tcp:
            self.cnt_tcp += 1
        else:
            if is_nsQuery:
                self.cnt_query2 += 1
            else:
                self.cnt_query1 += 1

    def print_stats(self):
        print('')
        cnt_query_total = self.cnt_query1 + self.cnt_query2
        print("Qname Delegation depth: %d" % self.delegation_depth)
        print("Number of delegations traversed: %d" % self.cnt_deleg)
        print("Number of queries performed (regular): %d" % self.cnt_query1)
        print("Number of queries performed:(nsaddr)   %d" % self.cnt_query2)
        if self.cnt_tcp:
            print("Number of TCP queries: %d" % self.cnt_tcp)
        if self.cnt_tcp_fallback:
            print("Number of TCP fallbacks: %d" % self.cnt_tcp_fallback)
        if self.cnt_fail:
            print("Number of queries failed: %d (%.2f%%)" %
                  (self.cnt_fail, (100.0 * self.cnt_fail/cnt_query_total)))
        if self.cnt_cname:
            print("Number of CNAME indirections: %d" % self.cnt_cname)


class Cache:
    """Cache of Zone & NameServer objects"""

    ZoneDict   = dict()                   # dns.name.Name -> Zone
    NSDict     = dict()                   # dns.name.Name -> NameServer


def printCache():
    """Print zone and NS cache contents - for debugging"""
    print("---------------------------- Zone Cache ----------------")
    for zname, zobj in Cache.ZoneDict.items():
        print("Zone: %s" % zname)
        for ns in zobj.nslist:
            print("    NS: %s" % Cache.NSDict[ns].name)
    print("---------------------------- NS   Cache ----------------")
    for nsname, nsobj in Cache.NSDict.items():
        ipstring_list = " ".join([x.addr for x in nsobj.iplist])
        print("%s %s" % (nsname, ipstring_list))
    return


def usage():
    print("""
{0} version {1}

    Usage: {0} [-dmtvsnx] <qname> [<qtype>] [<qclass>]
           {0} [-dmtvsnx] -b <batchfile>

     -d: print debugging output
     -m: do qname minimization
     -t: use TCP only
     -v: verbose - trace query & zone path
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
     -b <batchfile>: batch file mode

When using -b, <batchfile> contains one (space separated) query name, type, 
class per line.
    """.format(PROGNAME, VERSION))
    sys.exit(1)


def dprint(msg):
    if Prefs.DEBUG: print(">> DEBUG: %s" % msg)
    return


class Query:
    """Query name class"""

    def __init__(self, qname, qtype, qclass, minimize=False, is_nsquery=False):
        if isinstance(qname, dns.name.Name):
            self.qname = qname
        else:
            self.qname = dns.name.from_text(qname)
        self.orig_qname = self.qname
        self.qtype = qtype
        self.qclass = qclass
        self.minimize = minimize
        self.is_nsquery = is_nsquery
        self.quiet = False                      # don't print anything
        self.rcode = None
        self.got_answer = False
        self.cname_chain = []
        self.answer_rrset = []
        self.full_answer_rrset = []

    def print_full_answer(self):
        if self.full_answer_rrset:
            print("\n".join([x.to_text() for x in self.full_answer_rrset]))

    def get_answer_ip_list(self):
        iplist = []
        for rrset in self.answer_rrset:
            if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                for rr in rrset:
                    iplist.append(rr.to_text())
        return iplist

    def set_minimized(self, zone):
        labels_qname = self.orig_qname.labels
        labels_zone = zone.name.labels
        minLabels = len(labels_zone) + 1
        self.qname = dns.name.Name(labels_qname[-minLabels:])

    def prepend_label(self):
        numLabels = len(self.qname) + 1
        self.qname = dns.name.Name(self.orig_qname[-numLabels:])

    def __repr__(self):
        return "<Query: %s,%s,%s>" % (self.qname, self.qtype, self.qclass)


class IPaddress:
    """IPaddress class"""

    def __init__(self, ip):
        self.addr = ip
        self.addrtype = None
        self.rtt = float('inf')                    # RTT for UDP
        self.query_count = 0

    def __repr__(self):
        return "<IPaddress: %s>" % self.addr


class NameServer:
    """NameServer class"""

    def __init__(self, name):
        self.name = name                           # dns.name.Name
        self.iplist = []                           # list of IPaddress

    def has_ip(self, ipstring):
        if ipstring in [x.addr for x in self.iplist]:
            return True
        else:
            return False

    def install_ip(self, ipstring):
        if not self.has_ip(ipstring):
            self.iplist.append(IPaddress(ipstring))
        return

    def __repr__(self):
        return "<NS: %s>" % self.name


class Zone:
    """Zone class"""

    def __init__(self, zone):
        self.name = zone                           # dns.name.Name
        self.nslist = []                           # list of dns.name.Name
        Cache.ZoneDict[zone] = self

    def has_ns(self, ns):
        if ns in self.nslist:
            return True
        else:
            return False

    def install_ns(self, nsname, clobber=False):
        """Install a nameserver record for this zone"""
        if nsname not in self.nslist:
            self.nslist.append(nsname)
        if clobber or (nsname not in Cache.NSDict):
            Cache.NSDict[nsname] = NameServer(nsname)
        return Cache.NSDict[nsname]

    def iplist(self):
        result = []
        for ns in self.nslist:
            result += Cache.NSDict[ns].iplist
        return result

    def iplist_sorted_by_rtt(self):
        return sorted(self.iplist(), key = lambda ip: ip.rtt)

    def print_details(self):
        print("ZONE: %s" % self.name)
        for nsname in self.nslist:
            nsobj = Cache.NSDict[nsname]
            addresses = [x.addr for x in nsobj.iplist]
            print("%s %s %s" % (self.name, nsobj.name, addresses))
        return

    def __repr__(self):
        return "<Zone: %s>" % self.name


def get_root_zone():
    """populate the Root Zone object from hints file"""
    z = Zone(dns.name.root)
    for name, addr in ROOTHINTS:
        name = dns.name.from_text(name)
        nsobj = z.install_ns(name, clobber=False)
        nsobj.install_ip(addr)
    return z


def closest_zone(qname):
    """given query name, find closest enclosing zone object in Cache"""
    for z in reversed(sorted(Cache.ZoneDict.keys())):
        if qname.is_subdomain(z):
            return Cache.ZoneDict[z]
    else:
        return Cache.ZoneDict[dns.name.root]


def is_authoritative(msg):
    """Does DNS message have Authoritative Answer (AA) flag set?"""
    return (msg.flags & dns.flags.AA == dns.flags.AA)


def is_truncated(msg):
    """Does DNS message have truncated (TC) flag set?"""
    return (msg.flags & dns.flags.TC == dns.flags.TC)


def is_referral(msg):
    """Is the DNS response message a referral?"""
    return (msg.rcode() == 0) and \
        (not is_authoritative(msg)) and \
        (len(msg.authority) > 0)


def get_ns_addrs(zone, message):
    """
    Populate nameserver addresses for zone.
    
    Note: by default, we only save and use NS record addresses we can find 
    in the additional section of the referral. To be complete, we should 
    really explicitly resolve all non-glue NS addresses, which results in a 
    large number of additional queries and corresponding latency. This 
    complete mode can be turned on with -n (NSRESOLVE). If no NS addresses
    can be found in the additional section, we resort to NSRESOLVE mode.
    """

    global Prefs

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
                    nsobj = Cache.NSDict[name]
                    nsobj.install_ip(rr.address)

    if not zone.iplist() or Prefs.NSRESOLVE:       
        for name in needToResolve:
            nsobj = Cache.NSDict[name]
            if nsobj.iplist:
                continue
            for addrtype in ['A', 'AAAA']:
                nsquery = Query(name, addrtype, 'IN', Prefs.MINIMIZE,
                                is_nsquery=True)
                nsquery.quiet = True
                resolve_name(nsquery, closest_zone(nsquery.qname), inPath=False)
                for ip in nsquery.get_answer_ip_list():
                    nsobj.install_ip(ip)

    return


def process_referral(message, query):

    """Process referral. Returns a zone object for the referred zone"""
    global Prefs

    for rrset in message.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            break
    else:
        print("ERROR: unable to find NS RRset in referral response")
        return None

    zonename = rrset.name
    if zonename in Cache.ZoneDict:
        zone = Cache.ZoneDict[zonename]
    else:
        zone = Zone(zonename)
        for rr in rrset:
            nsobj = zone.install_ns(rr.target)

    get_ns_addrs(zone, message)
    if Prefs.VERBOSE and not query.quiet:
        print(">>        [Got Referral to zone: %s]" % zonename)
        zone.print_details()

    return zone


def process_answer(response, query, addResults=None):

    """Process answer section, chasing aliases when needed"""

    global Prefs
    answer = response.answer

    # If minimizing, then we ignore answers for intermediate query names.
    if query.qname != query.orig_qname:
        return answer

    empty_answer = (len(answer) == 0)
    if empty_answer:
        if not query.quiet:
            print("ERROR: NODATA: %s of type %s not found" % \
                  (query.qname, query.qtype))
        return answer

    gotCNAME = False

    for rrset in answer:
        if rrset.rdtype == dns.rdatatype.from_text(query.qtype) and \
           rrset.name == query.qname:
            query.answer_rrset.append(rrset)
            if addResults:
                addResults.full_answer_rrset.append(rrset)
            query.got_answer = True
        elif rrset.rdtype == dns.rdatatype.DNAME:
            # Just add DNAME record to results. Technically a good resolver
            # should really do DNAME->CNAME synthesis itself here, but we
            # rely on the fact that most authorities provide the CNAMEs
            # themselves.
            query.answer_rrset.append(rrset)
            if addResults:
                addResults.full_answer_rrset.append(rrset)
            if Prefs.VERBOSE:
                print(rrset.to_text())
        elif rrset.rdtype == dns.rdatatype.CNAME:
            gotCNAME = True
            query.answer_rrset.append(rrset)
            if addResults:
                addResults.full_answer_rrset.append(rrset)
            if Prefs.VERBOSE:
                print(rrset.to_text())
            cname = rrset[0].target
            stats.cnt_cname += 1
            if stats.cnt_cname >= MAX_CNAME:
                print("ERROR: Too many (%d) CNAME indirections." % MAX_CNAME)
                return None

    if gotCNAME:
        # We query the last CNAME in the answer chain, making the assumption
        # that authority servers return CNAME chains in an ordered fashion.
        # Practically all of them do. But technically there is no intrinsic
        # RRset ordering requirement in the spec, so we should really fix this
        # code (TODO).
        dprint("CNAME found, resolving canonical name %s" % cname)
        cname_query = Query(cname, query.qtype, query.qclass, Prefs.MINIMIZE)
        if addResults:
            addResults.cname_chain.append(cname_query)
        resolve_name(cname_query, closest_zone(cname),
                     inPath=False, addResults=addResults)

    return answer


def process_response(response, query, addResults=None):

    """process a DNS response. Returns rcode, answer message, zone referral"""

    rc = None; ans = None; referral = None
    if not response:
        return (rc, ans, z)
    rc = response.rcode()
    query.rcode = rc
    aa = (response.flags & dns.flags.AA == dns.flags.AA)
    if rc == dns.rcode.NOERROR:
        if is_referral(response):
            referral = process_referral(response, query)
            if referral:
                dprint("Obtained referral to zone: %s" % referral.name)
            else:
                print("ERROR: processing referral")
        else:                                            # Answer
                ans = process_answer(response, query, addResults=addResults)
    elif rc == dns.rcode.NXDOMAIN:                       # NXDOMAIN
        if not query.quiet:
            print("ERROR: NXDOMAIN: %s not found" % query.qname)

    return (rc, ans, referral)


def send_query_tcp(msg, nsaddr, query, timeout=TIMEOUT):
    res = None
    stats.update_query(is_nsQuery=query.is_nsquery, tcp=True)
    try:
        res = dns.query.tcp(msg, nsaddr.addr, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(ip))
        pass
    return res


def send_query_udp(msg, nsaddr, query, timeout=TIMEOUT, retries=RETRIES):
    gotresponse = False
    res = None
    stats.update_query(is_nsQuery=query.is_nsquery)
    while (not gotresponse and (retries > 0)):
        retries -= 1
        try:
            t0 = time.time()
            res = dns.query.udp(msg, nsaddr.addr, timeout=timeout)
            nsaddr.rtt = time.time() - t0
            gotresponse = True
        except dns.exception.Timeout:
            print("WARN: UDP query timeout for {}".format(ip))
            pass
    return res


def send_query(msg, nsaddr, query, timeout=TIMEOUT, retries=RETRIES, newid=False):
    res = None
    if newid:
        msg.id = random.randint(1,65535)
    res = send_query_udp(msg, nsaddr, query)
    if res and is_truncated(res):
        print("WARN: response was truncated; retrying with TCP ..")
        stats.cnt_tcp_fallback += 1
        res = send_query_tcp(msg, nsaddr, query)
    return res


def make_query(qname, qtype, qclass):
    msg = dns.message.make_query(qname, qtype, rdclass=qclass,
                                 want_dnssec=WANT_DNSSEC, payload=UDPSIZE)
    msg.flags &= ~dns.flags.RD  # set RD=0
    return msg


def send_query_zone(query, zone, is_nsQuery=False):
    """send DNS query to nameservers of given zone"""
    global Prefs
    response = None

    if Prefs.DEBUG or (Prefs.VERBOSE and not query.quiet):
        print("\n>> Query: %s %s %s at zone %s" % \
               (query.qname, query.qtype, query.qclass, zone.name))

    msg = make_query(query.qname, query.qtype, query.qclass)

    nsaddr_list = zone.iplist_sorted_by_rtt();
    if len(nsaddr_list) == 0:
        print("ERROR: No nameserver addresses found for zone: %s." % zone.name)
        return None

    for nsaddr in nsaddr_list:
        if stats.cnt_query1 + stats.cnt_query2 >= MAX_QUERY:
            print("ERROR: Max number of queries (%d) exceeded." % MAX_QUERY)
            return None
        dprint("Querying zone %s at address %s" % (zone.name, nsaddr.addr))
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

    return response


def resolve_name(query, zone, inPath=True, addResults=None):
    """resolve a DNS query. addResults is an optional Query object to
    which the answer results are to be added."""

    global Prefs
    curr_zone = zone
    repeatZone = False

    while stats.cnt_deleg < MAX_DELEG:

        if Prefs.DEBUG:
            print("\n>> Current Zone: %s" % curr_zone.name)
            curr_zone.print_details()

        if query.minimize:
            if repeatZone:
                query.prepend_label()
                repeatZone = False
            else:
                query.set_minimized(curr_zone)

        response = send_query_zone(query, curr_zone)
        if not response:
            return

        rc, ans, referral = process_response(response, query, addResults=addResults)

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

    global Prefs
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

        stats = Stats()
        print("\n### INPUT: %s, %s, %s" % (qname, qtype, qclass))
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)
        starting_zone = closest_zone(query.qname)
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
    else:
        return 1


def process_args(arguments):
    """Process all command line arguments"""

    global Prefs

    try:
        (options, args) = getopt.getopt(arguments, 'dmtvsnxb:')
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
        elif opt == "-b":
            Prefs.BATCHFILE = optval

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
    RootZone = get_root_zone()
    stats = Stats()

    if Prefs.BATCHFILE:
        do_batchmode(infile=Prefs.BATCHFILE, cmdline=sys.argv)
        sys.exit(0)
    else:
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)
        resolve_name(query, RootZone, addResults=query)
        if Prefs.VERBOSE:
            print('')
        query.print_full_answer()

        if Prefs.DEBUG or Prefs.STATS:
            stats.print_stats()

        sys.exit(exit_status(query))
