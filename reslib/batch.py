"""
batch mode operation.
"""

from reslib.common import Prefs
from reslib.query import Query
from reslib.lookup import resolve_name


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
            print("\nERROR input line %d: %s" % (linenum, line))
            continue

        print("\n### INPUT: %s, %s, %s" % (qname, qtype, qclass))
        query = Query(qname, qtype, qclass, minimize=Prefs.MINIMIZE)
        starting_zone = cache.closest_zone(query.qname)
        print("### Query: %s" % query)
        print("### Starting at zone: %s" % starting_zone)
        resolve_name(query, starting_zone, addResults=query)
        if Prefs.VERBOSE:
            print('')
        query.print_full_answer()

    print("\n### End Batch Mode.")
    return
