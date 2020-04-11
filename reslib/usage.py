"""
usage string function
"""

import os
import sys
from reslib.version import VERSION
from reslib.common import Prefs

PROGNAME = os.path.basename(sys.argv[0])

def usage(message=None):
    """Print usage string, preceded by optional message"""
    if message:
        print(message)
    print("""
{0} version {1}
Perform iterative resolution of a DNS name, type, and class.

    Usage: {0} [-dmtvsnxez] <qname> [<qtype>] [<qclass>]
           {0} [-dmtvsnxez] -b <batchfile>

     -d: print debugging output
     -m: do qname minimization
     -t: use TCP only
     -v: verbose - trace query & zone path
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
     -e: don't use EDNS0 (default is EDNS0 with payload={2})
     -z: set DNSSEC_OK flag (default is do not)
     -b <batchfile>: batch file mode

When using -b, <batchfile> contains one (space separated) query name, type,
class per line.
    """.format(PROGNAME, VERSION, Prefs.PAYLOAD))
    sys.exit(1)
