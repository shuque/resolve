"""
Zone class
"""

from reslib.nameserver import NameServer


class Zone:
    """Zone class"""

    def __init__(self, zone, cache):
        self.name = zone                           # dns.name.Name
        self.cache = cache                         # Cache class
        self.nslist = []                           # list of dns.name.Name
        self.cache.install_zone(zone, self)

    def has_ns(self, ns):
        """Does zone have specified nameserver?"""
        return ns in self.nslist

    def install_ns(self, nsname, clobber=False):
        """Install a nameserver record for this zone"""
        if nsname not in self.nslist:
            self.nslist.append(nsname)
        if clobber or (self.cache.get_ns(nsname) is None):
            self.cache.install_ns(nsname, NameServer(nsname))
        return self.cache.get_ns(nsname)

    def iplist(self):
        """Return list of nameserver addresses"""
        result = []
        for ns in self.nslist:
            result += self.cache.get_ns(ns).iplist
        return result

    def iplist_sorted_by_rtt(self):
        """Return IP list sorted by observed RTT"""
        return sorted(self.iplist(), key=lambda ip: ip.rtt)

    def print_details(self):
        """Print zone information"""
        print("ZONE: %s" % self.name)
        for nsname in self.nslist:
            nsobj = self.cache.get_ns(nsname)
            addresses = [x.addr for x in nsobj.iplist]
            print("%s %s %s" % (self.name, nsobj.name, addresses))
        return

    def __repr__(self):
        return "<Zone: %s>" % self.name
