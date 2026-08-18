"""
Command line option processing.
"""

import argparse

from reslib.version import __version__
from reslib.prefs import Prefs


DESCRIPTION = "version {}\nPerform iterative resolution of a DNS name, type, and class.".format(
    __version__)

EPILOG = ("When using -b, <batchfile> contains one (space separated) query "
          "name, type, class per line.")


def make_parser():
    """Build and return the argparse ArgumentParser for resolve.py."""
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", action="count", default=0, dest="VERBOSE",
                        help="increase verbosity level by 1 (default 0)")
    parser.add_argument("-j", action="store_true", dest="JSON",
                        help="give JSON encoded output")
    parser.add_argument("-m", action="store_true", dest="MINIMIZE",
                        help="do qname minimization")
    parser.add_argument("-t", action="store_true", dest="TCPONLY",
                        help="use TCP only")
    parser.add_argument("-s", action="store_true", dest="STATS",
                        help="print summary statistics")
    parser.add_argument("-n", action="store_true", dest="NSRESOLVE",
                        help="resolve all non-glue NS addresses in referrals")
    parser.add_argument("-x", action="store_true", dest="VIOLATE",
                        help="workaround NXDOMAIN on empty non-terminals")
    parser.add_argument("-e", type=int, default=1460, metavar="N", dest="PAYLOAD",
                        help="use EDNS0 buffer size N (default: 1460; 0=disable EDNS)")
    parser.add_argument("-z", action="store_true", dest="DNSSEC",
                        help="perform DNSSEC validation (default is no)")
    parser.add_argument("-c", action="store_true", dest="DUMPCACHE",
                        help="dump zone/ns/key caches at end of program execution")
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("-4", action="store_true", dest="V4_ONLY",
                           help="only use IPv4 transport")
    transport.add_argument("-6", action="store_true", dest="V6_ONLY",
                           help="only use IPv6 transport")
    parser.add_argument("-b", metavar="batchfile", dest="BATCHFILE",
                        help="batch file mode")
    parser.add_argument("qargs", nargs="*", metavar="qname [qtype [qclass]]",
                        help="query name, optional type (default A), "
                             "optional class (default IN)")
    return parser


def process_args(arguments):
    """Process command line arguments, build and return a populated Prefs
    instance as (prefs, qname, qtype, qclass). Does NOT mutate any module
    global."""

    parser = make_parser()
    ns = parser.parse_args(arguments)

    # Populate a fresh, local Prefs instance.
    prefs = Prefs()
    prefs.VERBOSE = ns.VERBOSE
    prefs.JSON = ns.JSON
    prefs.MINIMIZE = ns.MINIMIZE
    prefs.TCPONLY = ns.TCPONLY
    prefs.STATS = ns.STATS
    prefs.NSRESOLVE = ns.NSRESOLVE
    prefs.VIOLATE = ns.VIOLATE
    prefs.PAYLOAD = ns.PAYLOAD
    prefs.DNSSEC = ns.DNSSEC
    prefs.DUMPCACHE = ns.DUMPCACHE
    prefs.V4_ONLY = ns.V4_ONLY
    prefs.V6_ONLY = ns.V6_ONLY
    prefs.BATCHFILE = ns.BATCHFILE

    if prefs.PAYLOAD == 0 and prefs.DNSSEC:
        parser.error("DNSSEC (-z) requires EDNS (non zero -e)")

    if prefs.JSON:
        prefs.VERBOSE = 0    # json output carries its own detail

    args = ns.qargs

    if prefs.BATCHFILE:
        if not args:
            return (prefs, None, None, None)
        parser.error("batch mode (-b) does not take positional arguments")

    numargs = len(args)
    if numargs == 1:
        qname, = args
        qtype = 'A'
        qclass = 'IN'
    elif numargs == 2:
        qname, qtype = args
        qclass = 'IN'
    elif numargs == 3:
        qname, qtype, qclass = args
    else:
        parser.error("expected <qname> [<qtype>] [<qclass>]")

    return (prefs, qname, qtype, qclass)
