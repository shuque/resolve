"""
Simplistic DNS cache.
TODO: convert this to a more efficient tree data structure.
"""

import dns.name
from reslib.hints import ROOTHINTS
from reslib.zone import Zone


def get_root_zone(cache):
    """populate the Root Zone object from hints file"""
    zone = Zone(dns.name.root, cache)
    for name, addr in ROOTHINTS:
        name = dns.name.from_text(name)
        nsobj = zone.install_ns(name, clobber=False)
        nsobj.install_ip(addr)
    return zone


class Cache:
    """Cache of Zone & NameServer objects"""

    def __init__(self):
        self.ZoneDict = {}               # dns.name.Name -> Zone
        self.NSDict = {}                 # dns.name.Name -> NameServer

    def get_ns(self, nsname):
        if nsname in self.NSDict:
            return self.NSDict[nsname]
        return None

    def get_zone(self, zonename):
        if zonename in self.ZoneDict:
            return self.ZoneDict[zonename]
        return None

    def install_ns(self, nsname, nsobj):
        self.NSDict[nsname] = nsobj

    def install_zone(self, zonename, zoneobj):
        self.ZoneDict[zonename] = zoneobj

    def closest_zone(self, name):
        """given query name, find closest enclosing zone object in Cache"""
        for z in reversed(sorted(self.ZoneDict.keys())):
            if name.is_subdomain(z):
                return self.get_zone(z)
        return None

    def dump(self):
        """Dump zone and NS cache contents - for debugging"""
        print("---------------------------- Zone Cache ----------------")
        for zname, zobj in self.ZoneDict.items():
            print("Zone: {}".format(zname))
            for ns in zobj.nslist:
                print("    NS: {}".format(self.NSDict[ns].name))
        print("---------------------------- NS   Cache ----------------")
        for nsname, nsobj in self.NSDict.items():
            ipstring_list = " ".join([x.addr for x in nsobj.iplist])
            print("{} {}".format(nsname, ipstring_list))

