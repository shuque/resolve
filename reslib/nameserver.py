

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
        return ipstring in [x.addr for x in self.iplist]

    def install_ip(self, ipstring):
        if not self.has_ip(ipstring):
            self.iplist.append(IPaddress(ipstring))
        return

    def __repr__(self):
        return "<NS: %s>" % self.name

