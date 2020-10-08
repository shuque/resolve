"""
Zone class
"""

from binascii import hexlify
from random import shuffle
from reslib.nameserver import NameServer
from reslib.prefs import Prefs


class DS:
    """Delegation Signer class; holds DS rdata and match status"""

    def __init__(self, rdata):
        self.rdata = rdata
        self.matched = False

    def set_matched(self, boolean):
        self.matched = boolean

    def __repr__(self):
        return "{} {} {} {}...".format(self.rdata.key_tag,
                                       self.rdata.algorithm,
                                       self.rdata.digest_type,
                                       self.rdata.digest.hex()[0:16])


class Zone:
    """Zone class"""

    def __init__(self, zone, cache):
        self.name = zone                           # dns.name.Name
        self.cache = cache                         # Cache class
        self.nslist = []                           # list of dns.name.Name
        self.dslist = []                           # list of DS objects
        self.ttl_ns = None
        self.ttl_ds = None
        self.secure = False
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
        """Install DS rdata list"""
        self.ttl_ds = ds_rrset.ttl
        for rdata in ds_rrset.to_rdataset():
            self.dslist.append(DS(rdata))

    def set_secure(self, action):
        """Set zone to secure; when signed DS matches signed DNSKEY below"""
        self.secure = action

    def iplist(self):
        """Return list of nameserver addresses"""
        result = []
        for ns in self.nslist:
            iplist = self.cache.get_ns(ns).iplist
            if Prefs.V6_ONLY:
                iplist = [i for i in iplist if i.addr.find(':') != -1]
            elif Prefs.V4_ONLY:
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
        self.print_nsinfo()
        self.print_dsinfo()

    def __repr__(self):
        return "<Zone: {}>".format(self.name)
