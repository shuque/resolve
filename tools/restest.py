#!/usr/bin/env python3
#

"""
Simple test of main name resolution function.
"""

import sys

from reslib.prefs import Prefs
from reslib.cache import RootZone
from reslib.query import Query
from reslib.lookup import initialize_dnssec, resolve_name


if __name__ == '__main__':

    qname = sys.argv[1]
    qtype = sys.argv[2]
    qclass = 'IN'

    Prefs.DNSSEC = True
    initialize_dnssec()
    query = Query(qname, qtype, qclass)
    resolve_name(query, RootZone, addResults=query)
    query.print_full_answer()
