"""
Common globals for the package.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Prefs:
    """Preferences / resolver configuration."""
    MINIMIZE: bool = False           # -m: Do qname minimization?
    TCPONLY: bool = False            # -t: Use TCP only
    VERBOSE: int = 0                 # -v: Verbosity level (0 default)
    JSON: bool = False               # -j: JSON encoded output
    VIOLATE: bool = False            # -x: ENT nxdomain workaround
    STATS: bool = False              # -s: Print statistics
    NSRESOLVE: bool = False          # -n: Resolve all NS addresses
    PAYLOAD: int = 1460              # -e: EDNS payload (0 disables EDNS)
    DNSSEC: bool = False             # -z: use DNSSEC
    DUMPCACHE: bool = False          # -c: dump zone/ns/key caches
    V4_ONLY: bool = False            # -4: only use IPv4 transport
    V6_ONLY: bool = False            # -6: only use IPv6 transport
    BATCHFILE: Optional[str] = None  # -b: batch file mode
    TIMEOUT: int = 3                 # Query timeout in seconds
    RETRIES: int = 2                 # Number of retries per server
    RETRY: int = 1                   # of full list (not implemented yet)
    MAX_CNAME: int = 15              # Max #CNAME indirections
    MAX_QUERY: int = 600             # Max number of queries
    MAX_DELEG: int = 200             # Max number of delegations
    N3_HASHLIMIT: int = 512          # Upper bound for NSEC3 hash iterations
