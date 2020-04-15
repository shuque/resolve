#!/usr/bin/env python3

"""
resolve.py
Perform iterative resolution of a DNS name, type, class.

Author: Shumon Huque <shuque - @ - gmail.com>
"""


import os
import sys
import time
import random

from reslib.common import Prefs, stats, cache, RootZone
from reslib.options import process_args
from reslib.query import Query
from reslib.dnssec import key_cache
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
        if Prefs.DUMPCACHE:
            cache.dump()
            key_cache.dump()
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

        if Prefs.DUMPCACHE:
            cache.dump()
            key_cache.dump()

        sys.exit(exit_status(query))
