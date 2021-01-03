"""
IPaddress and NameServer object classes.
"""

class IPaddress:
    """IPaddress class"""

    def __init__(self, ip):
        self.addr = ip
        self.addrtype = None
        self.rtt = float('inf')                    # RTT for UDP
        self.query_count = 0

    def __repr__(self):
        return "<IPaddress: {}>".format(self.addr)


class NameServer:
    """NameServer class"""

    def __init__(self, name):
        self.name = name                           # dns.name.Name
        self.iplist = []                           # list of IPaddress

    def has_ip(self, ipstring):
        """Do we have the given IP address string"""
        return ipstring in [x.addr for x in self.iplist]

    def install_ip(self, ipstring):
        """Install an IP address object for given IP string"""
        if not self.has_ip(ipstring):
            self.iplist.append(IPaddress(ipstring))

    def __repr__(self):
        return "<NS: {}: {}>".format(self.name,
                                     ",".join([x.addr for x in self.iplist]))
