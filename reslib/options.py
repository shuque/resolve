"""
Command line option processing.
"""


import getopt

from reslib.prefs import Prefs
from reslib.usage import usage


def process_args(arguments):
    """Process all command line arguments"""

    try:
        (options, args) = getopt.getopt(arguments, 'mtvsnxe:zc46b:')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-m":
            Prefs.MINIMIZE = True
        elif opt == "-t":
            Prefs.TCPONLY = True
        elif opt == "-v":
            Prefs.VERBOSE += 1
        elif opt == "-s":
            Prefs.STATS = True
        elif opt == "-n":
            Prefs.NSRESOLVE = True
        elif opt == "-x":
            Prefs.VIOLATE = True
        elif opt == "-e":
            Prefs.PAYLOAD = int(optval)
        elif opt == "-z":
            Prefs.DNSSEC = True
        elif opt == "-c":
            Prefs.DUMPCACHE = True
        elif opt == "-b":
            Prefs.BATCHFILE = optval
        elif opt == "-4":
            Prefs.V4_ONLY = True
        elif opt == "-6":
            Prefs.V6_ONLY = True

    if (Prefs.PAYLOAD == 0) and Prefs.DNSSEC:
        usage("ERROR: DNSSEC (-z) requires EDNS (non zero -e)")

    if Prefs.V4_ONLY and Prefs.V6_ONLY:
        usage("ERROR: -4 (IPv4 only) & -6 (IPv6 only) are mutually exclusive")

    if Prefs.BATCHFILE:
        if not args:
            return (None, None, None)
        else:
            usage()

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
        usage()

    return (qname, qtype, qclass)
