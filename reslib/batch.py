"""
batch mode operation.
"""

from reslib.query import Query
from reslib.lookup import resolve_name, print_root_zone


def batchmode(resolver, infile, info):
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
        resolver.stats.reset()
        query = Query(qname, qtype, qclass, minimize=resolver.prefs.MINIMIZE,
                      resolver=resolver)
        starting_zone = resolver.cache.closest_zone(query.qname)
        query.secure_so_far = starting_zone.secure
        print("### Starting at zone: {}\n###".format(starting_zone.name))
        if resolver.prefs.VERBOSE and starting_zone == resolver.root_zone:
            print_root_zone(resolver)
        resolve_name(resolver, query, starting_zone, addResults=query)
        if resolver.prefs.VERBOSE:
            print('')
        query.print_full_answer()

    print("\n### End Batch Mode.")
