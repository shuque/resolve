"""
usage string function
"""

import os
import sys
from reslib.version import VERSION
from reslib.prefs import Prefs

PROGNAME = os.path.basename(sys.argv[0])

def usage(message=None):
    """Print usage string, preceded by optional message"""
    if message:
        print(message)
    print("""
{0} version {1}
Perform iterative resolution of a DNS name, type, and class.

    Usage: {0} [Options] <qname> [<qtype>] [<qclass>]
           {0} [Options] -b <batchfile>

     Options:
     -v: increase verbosity level by 1 (default 0)
     -m: do qname minimization
     -t: use TCP only
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
     -eN: use EDNS0 buffer size N (default: {2}; 0=disable EDNS)
     -z: perform DNSSEC validation (default is no)
     -c: dump zone/ns/key caches at end
     -4: only use IPv4 transport
     -6: only use IPv6 transport
     -b <batchfile>: batch file mode

When using -b, <batchfile> contains one (space separated) query name, type,
class per line.
    """.format(PROGNAME, VERSION, Prefs.PAYLOAD))
    sys.exit(1)
