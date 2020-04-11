TIMEOUT    = 3                            # Query timeout in seconds
RETRIES    = 2                            # Number of retries per server
RETRY      = 1                            # of full list (not implemented yet)
MAX_CNAME  = 10                           # Max #CNAME indirections
MAX_QUERY  = 300                          # Max number of queries
MAX_DELEG  = 75                           # Max number of delegations


class Prefs:
    """Preferences"""
    DEBUG      = False                    # -d: Print debugging output?
    MINIMIZE   = False                    # -m: Do qname minimization?
    TCPONLY    = False                    # -t: Use TCP only
    VERBOSE    = False                    # -v: Trace query->zone path
    VIOLATE    = False                    # -x: ENT nxdomain workaround
    STATS      = False                    # -s: Print statistics
    NSRESOLVE  = False                    # -n: Resolve all NS addresses
    PAYLOAD    = 1460                     # -e: no EDNS; set to None
    DNSSEC_OK  = False                    # -z: set DO=1 EDNS flag
    BATCHFILE  = None                     # -b: batch file mode
