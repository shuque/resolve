"""
Simplistic DNS cache.
TODO: convert this to a more efficient tree data structure.
"""

import dns.name
from reslib.hints import ROOTHINTS, ROOT_NS_TTL
from reslib.zone import Zone


def get_root_zone(cache):
    """populate the Root Zone object from hints file"""
    zone = Zone(dns.name.root, cache)
    for name, addr in ROOTHINTS:
        name = dns.name.from_text(name)
        nsobj = zone.install_ns(name, clobber=False)
        nsobj.install_ip(addr)
    zone.install_ns_rrset_ttl(ROOT_NS_TTL)
    zone.secure = True
    return zone


class Cache:
    """Cache of Zone & NameServer objects"""

    def __init__(self):
        self.reset()

    def reset(self):
        """Initialize/empty caches"""
        self.ZoneDict = {}               # dns.name.Name -> Zone
        self.NSDict = {}                 # dns.name.Name -> NameServer
        self.RRsets = {}                 # (dns.name.Name, rrtype) -> RRset

    def get_zone(self, zonename):
        """Get zone object for given zone name"""
        if zonename in self.ZoneDict:
            return self.ZoneDict[zonename]
        return None

    def get_ns(self, nsname):
        """Get NS object for given nameserver name """
        if nsname in self.NSDict:
            return self.NSDict[nsname]
        return None

    def get_rrset(self, rrname, rrtype):
        """Get RRset object from cache"""
        if (rrname, rrtype) in self.RRsets:
            return self.RRsets[(rrname, rrtype)]
        return None

    def install_ns(self, nsname, nsobj):
        """Install nameserver object"""
        self.NSDict[nsname] = nsobj

    def install_zone(self, zonename, zoneobj):
        """Install zone object"""
        self.ZoneDict[zonename] = zoneobj

    def install_rrset(self, srrset):
        """Install RRset object"""
        key = (srrset.rrname, srrset.rrtype)
        self.RRsets[key] = srrset

    def closest_zone(self, name):
        """find closest enclosing zone object in Cache"""
        for z in reversed(sorted(self.ZoneDict.keys())):
            if name.is_subdomain(z):
                return self.get_zone(z)
        return None

    def dump(self):
        """Dump contents of Cache"""
        self.dump_zones()
        self.dump_nameservers()
        self.dump_rrsets()

    def dump_zones(self):
        """Dump cache of zones"""
        print("#### Zone Cache dump")
        for zname, zobj in self.ZoneDict.items():
            print("Zone: {}{}".format(zname,
                                      " (Secure)" if zobj.secure else ""))
            for ns in zobj.nslist:
                print("    NS: {}".format(self.NSDict[ns].name))
            for ds in zobj.dslist:
                print("    DS: {}{}".format(ds,
                                            " (matched)" if ds.matched else ""))
        print("#### END: Zone Cache dump")

    def dump_nameservers(self):
        """Dump cache of nameservers"""
        print("#### Nameserver Cache dump")
        for nsname, nsobj in self.NSDict.items():
            ipstring_list = " ".join([x.addr for x in nsobj.iplist])
            print("{} {}".format(nsname, ipstring_list))
        print("#### END: Nameserver Cache dump")

    def dump_rrsets(self):
        """Dump cache of RRsets"""
        print("### RRset Cache dump")
        for _, srrset in self.RRsets.items():
            print(srrset)
        print("### END: RRset Cache dump")



# Global cache and root zone object
cache = Cache()
RootZone = get_root_zone(cache)
