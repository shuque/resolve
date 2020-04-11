import dns.resolver
from reslib.common import *


def dprint(msg):
    """Print debugging message if DEBUG flag is set"""
    if Prefs.DEBUG:
        print(">> DEBUG: %s" % msg)
    return


def get_resolver(dnssec_ok=False, timeout=5):
    """return an appropriately configured Resolver object"""
    r = dns.resolver.Resolver()
    # Set query flags to RD=1, AD=1, CD=1
    #r.set_flags(0x0130)                      # binary 0000 0001 0011 0000
    r.lifetime = timeout
    if dnssec_ok:
        r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
    return r
                                    
