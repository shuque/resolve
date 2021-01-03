"""
Common globals for the package.
"""


class Prefs:
    """Preferences"""
    MINIMIZE = False                 # -m: Do qname minimization?
    TCPONLY = False                  # -t: Use TCP only
    VERBOSE = 0                      # -v: Verbosity level (0 default)
    JSON = False                     # -j: JSON encoded output
    VIOLATE = False                  # -x: ENT nxdomain workaround
    STATS = False                    # -s: Print statistics
    NSRESOLVE = False                # -n: Resolve all NS addresses
    PAYLOAD = 1460                   # -e: no EDNS; set to None
    DNSSEC = False                   # -z: use DNSSEC
    DUMPCACHE = False                # -c: dump zone/ns/key caches
    V4_ONLY = False                  # -4: only use IPv4 transport
    V6_ONLY = False                  # -6: only use IPv6 transport
    BATCHFILE = None                 # -b: batch file mode
    TIMEOUT = 3                      # Query timeout in seconds
    RETRIES = 2                      # Number of retries per server
    RETRY = 1                        # of full list (not implemented yet)
    MAX_CNAME = 15                   # Max #CNAME indirections
    MAX_QUERY = 600                  # Max number of queries
    MAX_DELEG = 200                  # Max number of delegations
    N3_HASHLIMIT = 512               # Upper bound for NSEC3 hash iterations
