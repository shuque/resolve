#!/usr/bin/env python3

"""
resolve.py
Perform iterative resolution of a DNS name, type, class.

Author: Shumon Huque <shuque - @ - gmail.com>
"""


import os
import sys
import getopt
import time
import random

from reslib.common import Prefs, stats, cache, RootZone
from reslib.usage import usage
from reslib.query import Query
from reslib.lookup import resolve_name, initialize_dnssec
from reslib.batch import batchmode


def exit_status(query):
    """Obtain final exit status code"""
    if query.cname_chain:
        last_cname = query.cname_chain.pop()
        rcode = last_cname.rcode
        got_answer = last_cname.got_answer
    else:
        rcode = query.rcode
        got_answer = query.got_answer

    if rcode == 0 and got_answer:
        return 0
    return 1


def process_args(arguments):
    """Process all command line arguments"""

    try:
        (options, args) = getopt.getopt(arguments, 'dmtvsnxezb:')
    except getopt.GetoptError:
        usage()

    for (opt, optval) in options:
        if opt == "-d":
            Prefs.DEBUG = True
        elif opt == "-m":
            Prefs.MINIMIZE = True
        elif opt == "-t":
            Prefs.TCPONLY = True
        elif opt == "-v":
            Prefs.VERBOSE = True
        elif opt == "-s":
            Prefs.STATS = True
        elif opt == "-n":
            Prefs.NSRESOLVE = True
        elif opt == "-x":
            Prefs.VIOLATE = True
        elif opt == "-e":
            Prefs.PAYLOAD = None
        elif opt == "-z":
            Prefs.DNSSEC = True
        elif opt == "-b":
            Prefs.BATCHFILE = optval

    if (Prefs.PAYLOAD is None) and Prefs.DNSSEC:
        usage("Error: -e and -z are mutually incompatible.")

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


if __name__ == '__main__':

    random.seed(os.urandom(64))
    qname, qtype, qclass = process_args(sys.argv[1:])

    if Prefs.DNSSEC:
        initialize_dnssec()

    if Prefs.BATCHFILE:
        time_start = time.time()
        batchmode(cache, Prefs.BATCHFILE,
                  info="Command: {}".format(" ".join(sys.argv)))
        stats.elapsed = time.time() - time_start
        if Prefs.STATS:
            stats.print_stats()
        sys.exit(0)
    else:
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)

        time_start = time.time()
        resolve_name(query, RootZone, addResults=query)
        stats.elapsed = time.time() - time_start

        if Prefs.VERBOSE and not query.quiet:
            print('')
        query.print_full_answer()

        if Prefs.STATS:
            stats.print_stats()

        sys.exit(exit_status(query))
