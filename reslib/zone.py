"""
Zone class
"""

from binascii import hexlify
from random import shuffle
from reslib.nameserver import NameServer


class Zone:
    """Zone class"""

    def __init__(self, zone, cache):
        self.name = zone                           # dns.name.Name
        self.cache = cache                         # Cache class
        self.nslist = []                           # list of dns.name.Name
        self.dslist = []                           # list of DS rdata objects
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
        self.dslist = ds_rrset.to_rdataset()

    def set_secure(self, action):
        """Set zone to secure; when signed DS matches signed DNSKEY below"""
        self.secure = action

    def iplist(self):
        """Return list of nameserver addresses"""
        result = []
        for ns in self.nslist:
            result += self.cache.get_ns(ns).iplist
        return result

    def iplist_shuffled(self):
        """Return IP list randomly shuffled"""
        iplist = self.iplist()
        shuffle(iplist)
        return iplist

    def iplist_sorted_by_rtt(self):
        """Return IP list sorted by observed RTT"""
        return sorted(self.iplist(), key=lambda ip: ip.rtt)

    def print_details(self):
        """Print zone information"""
        print("ZONE: {}".format(self.name))
        if self.ttl_ds:
            print("TTL: Delegation: {}, Signer: {}".format(
                self.ttl_ns, self.ttl_ds))
        else:
            print("TTL: Delegation: {}".format(self.ttl_ns))
        for nsname in self.nslist:
            nsobj = self.cache.get_ns(nsname)
            addresses = " ".join([x.addr for x in nsobj.iplist])
            print("NS: {} {}".format(nsobj.name, addresses))
        for ds_data in self.dslist:
            print("DS: {} {} {} {}".format(
                ds_data.key_tag,
                ds_data.algorithm,
                ds_data.digest_type,
                hexlify(ds_data.digest).decode()))

    def __repr__(self):
        return "<Zone: {}>".format(self.name)
