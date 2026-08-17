"""
main() function for command line program resolve.py
"""


import os
import sys
import time
import random

from reslib.exception import ResError
from reslib.prefs import prefs
from reslib.cache import cache, RootZone
from reslib.stats import stats
from reslib.options import process_args
from reslib.query import Query
from reslib.dnssec import key_cache
from reslib.lookup import resolve_name, initialize_dnssec, print_root_zone
from reslib.batch import batchmode
from reslib.exit import exit_status
from reslib.result import jsonout


def main():
    """
    resolve.py main() function
    """

    random.seed(os.urandom(64))
    qname, qtype, qclass = process_args(sys.argv[1:])

    if prefs.DNSSEC:
        initialize_dnssec()

    if prefs.BATCHFILE:
        time_start = time.time()
        batchmode(cache, prefs.BATCHFILE,
                  info="Command: {}".format(" ".join(sys.argv)))
        stats.elapsed = time.time() - time_start
        if prefs.STATS:
            stats.print()
        if prefs.DUMPCACHE:
            print('')
            cache.dump()
            key_cache.dump()
        return 0

    query = Query(qname, qtype, qclass, minimize=prefs.MINIMIZE)

    time_start = time.time()
    if prefs.VERBOSE:
        print_root_zone()

    try:
        resolve_name(query, RootZone, addResults=query)
    except ResError as exc_info:
        print("\nERROR:", exc_info)
        return 255

    stats.elapsed = time.time() - time_start

    if prefs.JSON:
        jsonout(query)
        return exit_status(query)

    if prefs.VERBOSE and not query.quiet:
        print('')
    query.print_full_answer()

    if prefs.STATS:
        stats.print()

    if prefs.DUMPCACHE:
        print('')
        cache.dump()
        key_cache.dump()

    return exit_status(query)
