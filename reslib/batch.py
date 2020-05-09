"""
batch mode operation.
"""

from reslib.prefs import Prefs
from reslib.cache import RootZone
from reslib.query import Query
from reslib.lookup import resolve_name, print_root_zone


def batchmode(cache, infile, info):
    """Execute batch mode on specified input file"""

    print("### resolve.py Batch Mode. File: {}".format(infile))
    print("### {}".format(info))

    linenum = 0
    for line in open(infile):
        linenum += 1
        line = line.rstrip('\n')
        parts = line.split()
        if len(parts) == 1:
            qname, = parts
            qtype = 'A'
            qclass = 'IN'
        elif len(parts) == 2:
            qname, qtype = parts
            qclass = 'IN'
        elif len(parts) == 3:
            qname, qtype, qclass = parts
        else:
            print("\nERROR input line {}: {}".format(linenum, line))
            continue

        print("\n###\n### Query: {}, {}, {}".format(qname, qtype, qclass))
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)
        starting_zone = cache.closest_zone(query.qname)
        print("### Starting at zone: {}\n###".format(starting_zone.name))
        if Prefs.VERBOSE and starting_zone == RootZone:
            print_root_zone()
        resolve_name(query, starting_zone, addResults=query)
        if Prefs.VERBOSE:
            print('')
        query.print_full_answer()

    print("\n### End Batch Mode.")
    return
