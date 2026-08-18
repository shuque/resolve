#!/usr/bin/env python3
#

"""
Simple test of main name resolution function.
"""

import sys

from reslib.prefs import Prefs
from reslib.query import Query
from reslib.lookup import resolve_name
from reslib.resolver import Resolver


if __name__ == '__main__':

    qname = sys.argv[1]
    qtype = sys.argv[2]
    qclass = 'IN'

    prefs = Prefs()
    prefs.DNSSEC = True
    resolver = Resolver(prefs)
    resolver.bootstrap()
    query = Query(qname, qtype, qclass, resolver=resolver)
    resolve_name(resolver, query, resolver.root_zone, addResults=query)
    query.print_full_answer()
