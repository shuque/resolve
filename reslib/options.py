"""
Command line option processing.
"""


import getopt

from reslib.common import Prefs
from reslib.usage import usage


def process_args(arguments):
    """Process all command line arguments"""

    try:
        (options, args) = getopt.getopt(arguments, 'mtv:snxe:zcb:')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-m":
            Prefs.MINIMIZE = True
        elif opt == "-t":
            Prefs.TCPONLY = True
        elif opt == "-v":
            Prefs.VERBOSE = int(optval)
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

    if (Prefs.PAYLOAD == 0) and Prefs.DNSSEC:
        usage("Error: DNSSEC (-z) requires EDNS (non zero -e)")

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
