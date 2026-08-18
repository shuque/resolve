"""
main() function for command line program resolve.py
"""


import os
import sys
import time
import random

from reslib.exception import ResError
from reslib.options import process_args
from reslib.query import Query
from reslib.lookup import resolve_name, print_root_zone
from reslib.batch import batchmode
from reslib.exit import exit_status
from reslib.result import jsonout
from reslib.resolver import Resolver


def main():
    """
    resolve.py main() function
    """

    random.seed(os.urandom(64))
    prefs, qname, qtype, qclass = process_args(sys.argv[1:])

    resolver = Resolver(prefs)
    resolver.bootstrap()

    if prefs.BATCHFILE:
        time_start = time.time()
        batchmode(resolver, prefs.BATCHFILE,
                  info="Command: {}".format(" ".join(sys.argv)))
        resolver.stats.elapsed = time.time() - time_start
        if prefs.STATS:
            resolver.stats.print()
        if prefs.DUMPCACHE:
            print('')
            resolver.cache.dump()
            resolver.key_cache.dump()
        return 0

    query = Query(qname, qtype, qclass, minimize=prefs.MINIMIZE, resolver=resolver)

    time_start = time.time()
    if prefs.VERBOSE:
        print_root_zone(resolver)

    try:
        resolve_name(resolver, query, resolver.root_zone, addResults=query)
    except ResError as exc_info:
        print("\nERROR:", exc_info)
        return 255

    resolver.stats.elapsed = time.time() - time_start

    if prefs.JSON:
        jsonout(query)
        return exit_status(query)

    if prefs.VERBOSE and not query.quiet:
        print('')
    query.print_full_answer()

    if prefs.STATS:
        resolver.stats.print()

    if prefs.DUMPCACHE:
        print('')
        resolver.cache.dump()
        resolver.key_cache.dump()

    return exit_status(query)
