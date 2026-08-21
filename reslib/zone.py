"""
Zone class
"""

from binascii import hexlify
from random import shuffle
from reslib.nameserver import NameServer, IPaddress
from reslib.deleg import format_deleg_rrset


class DS:
    """Delegation Signer class; holds DS rdata and match status"""

    def __init__(self, rdata):
        self.rdata = rdata
        self.matched = []

    def add_matched(self, dnskey):
        """add matching DNSKEY record"""
        self.matched.append(dnskey)

    def __repr__(self):
        return "{} {} {} {}...".format(self.rdata.key_tag,
                                       self.rdata.algorithm,
                                       self.rdata.digest_type,
                                       self.rdata.digest.hex()[0:16])


class Zone:
    """Zone class"""

    def __init__(self, zone, resolver, cache=None):
        self.resolver = resolver
        self.cache = cache if cache is not None else self.resolver.cache
        self.name = zone                           # dns.name.Name
        self.nslist = []                           # list of dns.name.Name
        self.dslist = []                           # list of DS objects
        self.ttl_ns = None
        self.ttl_ds = None
        self.secure = False
        self.via_deleg = False           # servers came from a DELEG record
        self.deleg_iplist = []           # list of IPaddress (DELEG source)
        self.deleg_rrset = None          # dns.rrset.RRset, for trace/print
        self.adt = False                 # delegating zone's DNSKEY ADT flag
        self.cache.install_zone(zone, self)

    def has_ns(self, ns):
        """Does zone have specified nameserver?"""
        return ns in self.nslist

    def install_ns_rrset_ttl(self, ttl):
        """Set NS RRset TTL"""
        self.ttl_ns = ttl

    def install_ns(self, nsname, clobber=False):
        """Install a nameserver record for this zone"""
        if nsname not in self.nslist:
            self.nslist.append(nsname)
        if clobber or (self.cache.get_ns(nsname) is None):
            self.cache.install_ns(nsname, NameServer(nsname))
        return self.cache.get_ns(nsname)

    def install_ds_rrset(self, ds_rrset):
        """Install DS rdata list, replacing any previously installed set.

        This is the authoritative DS RRset for the zone, so installing it
        is idempotent: re-fetching (e.g. when a referral is retried against
        multiple parent servers) must not accumulate duplicate DS entries.
        """
        self.ttl_ds = ds_rrset.ttl
        self.dslist = []
        for rdata in ds_rrset.to_rdataset():
            self.dslist.append(DS(rdata))

    def set_secure(self, action):
        """Set zone to secure; when signed DS matches signed DNSKEY below"""
        self.secure = action

    def install_deleg_addresses(self, ip_strings, deleg_rrset):
        """Install DELEG-derived server addresses. NS names are never stored
        (delext Section 5.2: accompanying NS MUST NOT be cached)."""
        self.via_deleg = True
        self.deleg_rrset = deleg_rrset
        self.deleg_iplist = [IPaddress(ip) for ip in ip_strings]

    def iplist(self):
        """Return list of nameserver addresses. When the zone was reached via
        a DELEG record, the addresses come from the DELEG server source, not
        from NS + glue."""
        if self.via_deleg:
            source = self.deleg_iplist
            if self.resolver.prefs.V6_ONLY:
                return [i for i in source if i.addr.find(':') != -1]
            if self.resolver.prefs.V4_ONLY:
                return [i for i in source if i.addr.find(':') == -1]
            return list(source)
        result = []
        for ns in self.nslist:
            iplist = self.cache.get_ns(ns).iplist
            if self.resolver.prefs.V6_ONLY:
                iplist = [i for i in iplist if i.addr.find(':') != -1]
            elif self.resolver.prefs.V4_ONLY:
                iplist = [i for i in iplist if i.addr.find(':') == -1]
            result += iplist
        return result

    def iplist_shuffled(self):
        """Return IP list randomly shuffled"""
        iplist = self.iplist()
        shuffle(iplist)
        return iplist

    def iplist_sorted_by_rtt(self):
        """Return IP list sorted by observed RTT"""
        return sorted(self.iplist(), key=lambda ip: ip.rtt)

    def print_nsinfo(self):
        """Print NS info"""
        for nsname in self.nslist:
            nsobj = self.cache.get_ns(nsname)
            addresses = " ".join([x.addr for x in nsobj.iplist])
            print("NS: {} {}".format(nsobj.name, addresses))

    def print_dsinfo(self):
        """Print DS info"""
        for ds in self.dslist:
            ds_data = ds.rdata
            print("DS: {} {} {} {}{}".format(
                ds_data.key_tag,
                ds_data.algorithm,
                ds_data.digest_type,
                hexlify(ds_data.digest).decode(),
                " OK" if ds.matched else ""))

    def print_details(self):
        """Print zone information"""
        print("ZONE: {}".format(self.name))
        if self.ttl_ds:
            print("TTL: Delegation: {}, Signer: {}".format(
                self.ttl_ns, self.ttl_ds))
        else:
            print("TTL: Delegation: {}".format(self.ttl_ns))
        if self.via_deleg:
            if self.deleg_rrset is not None:
                for line in format_deleg_rrset(self.deleg_rrset).split("\n"):
                    print("DELEG: {}".format(line))
            print("DELEG servers: {}".format(
                " ".join(ip.addr for ip in self.deleg_iplist)))
        self.print_nsinfo()
        self.print_dsinfo()

    def __repr__(self):
        return "<Zone: {}>".format(self.name)
