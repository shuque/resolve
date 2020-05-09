"""
Common globals for the package.
"""

from reslib.cache import Cache, get_root_zone


class Prefs:
    """Preferences"""
    MINIMIZE = False                 # -m: Do qname minimization?
    TCPONLY = False                  # -t: Use TCP only
    VERBOSE = 0                      # -v N: Verbosity level (0 default; 1/2)
    VIOLATE = False                  # -x: ENT nxdomain workaround
    STATS = False                    # -s: Print statistics
    NSRESOLVE = False                # -n: Resolve all NS addresses
    PAYLOAD = 1460                   # -e: no EDNS; set to None
    DNSSEC = False                   # -z: use DNSSEC
    DUMPCACHE = False                # -c: dump zone/ns/key caches
    BATCHFILE = None                 # -b: batch file mode
    TIMEOUT = 3                      # Query timeout in seconds
    RETRIES = 2                      # Number of retries per server
    RETRY = 1                        # of full list (not implemented yet)
    MAX_CNAME = 15                   # Max #CNAME indirections
    MAX_QUERY = 600                  # Max number of queries
    MAX_DELEG = 200                  # Max number of delegations
    N3_HASHLIMIT = 512               # Upper bound for NSEC3 hash iterations


class Stats:
    """Statistics counters"""

    def __init__(self):
        self.elapsed = 0
        self.cnt_cname = 0
        self.cnt_query1 = 0                  # regular queries
        self.cnt_query2 = 0                  # NS address queries
        self.cnt_fail = 0
        self.cnt_tcp = 0
        self.cnt_tcp_fallback = 0
        self.cnt_deleg = 0
        self.delegation_depth = 0

    def update_query(self, query, tcp=False):
        """update query counts"""
        if tcp:
            self.cnt_tcp += 1
        if query.is_nsquery:
            self.cnt_query2 += 1
        else:
            self.cnt_query1 += 1

    def print(self):
        """Print statistics"""
        print('\n### Statistics:')
        print("Elapsed time: {:.3f} sec".format(self.elapsed))
        cnt_query_total = self.cnt_query1 + self.cnt_query2
        print("Number of delegations traversed: {}".format(self.cnt_deleg))
        print("Number of queries (regular): {}".format(self.cnt_query1))
        print("Number of queries (nsaddr)   {}".format(self.cnt_query2))
        if self.cnt_tcp:
            print("Number of TCP queries: {}".format(self.cnt_tcp))
        if self.cnt_tcp_fallback:
            print("Number of TCP fallbacks: {}".format(self.cnt_tcp_fallback))
        if self.cnt_fail:
            print("Number of queries failed: {:d} ({:.2f}%%)".format(
                self.cnt_fail,
                (100.0 * self.cnt_fail/cnt_query_total)))
        if self.cnt_cname:
            print("Number of CNAME indirections: {}".format(self.cnt_cname))


# Global statistics object
stats = Stats()

# Global cache and root zone object
cache = Cache()
RootZone = get_root_zone(cache)
