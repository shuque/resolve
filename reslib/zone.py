from reslib.nameserver import NameServer


class Zone:
    """Zone class"""

    def __init__(self, zone, cache):
        self.name = zone                           # dns.name.Name
        self.cache = cache                         # Cache class
        self.nslist = []                           # list of dns.name.Name
        self.cache.install_zone(zone, self)

    def has_ns(self, ns):
        return ns in self.nslist

    def install_ns(self, nsname, clobber=False):
        """Install a nameserver record for this zone"""
        if nsname not in self.nslist:
            self.nslist.append(nsname)
        if clobber or (self.cache.get_ns(nsname) is None):
            self.cache.install_ns(nsname, NameServer(nsname))
        return self.cache.get_ns(nsname)

    def iplist(self):
        result = []
        for ns in self.nslist:
            result += self.cache.get_ns(ns).iplist
        return result

    def iplist_sorted_by_rtt(self):
        return sorted(self.iplist(), key=lambda ip: ip.rtt)

    def print_details(self):
        print("ZONE: %s" % self.name)
        for nsname in self.nslist:
            nsobj = self.cache.get_ns(nsname)
            addresses = [x.addr for x in nsobj.iplist]
            print("%s %s %s" % (self.name, nsobj.name, addresses))
        return

    def __repr__(self):
        return "<Zone: %s>" % self.name


def get_root_zone(cache):
    """populate the Root Zone object from hints file"""
    z = Zone(dns.name.root, cache)
    for name, addr in ROOTHINTS:
        name = dns.name.from_text(name)
        nsobj = z.install_ns(name, clobber=False)
        nsobj.install_ip(addr)
    return z

