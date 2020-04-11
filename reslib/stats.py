from reslib.common import *


class Stats:
    """Statistics counters"""

    def __init__(self):
        self.elapsed          = 0
        self.cnt_cname        = 0
        self.cnt_query1       = 0                  # regular queries
        self.cnt_query2       = 0                  # NS address queries
        self.cnt_fail         = 0
        self.cnt_tcp          = 0
        self.cnt_tcp_fallback = 0
        self.cnt_deleg        = 0
        self.delegation_depth = 0

    def update_query(self, query, tcp=False):
        """update query counts"""
        if tcp:
            self.cnt_tcp += 1
        if query.is_nsquery:
            self.cnt_query2 += 1
        else:
            self.cnt_query1 += 1

    def print_stats(self):
        """Print statistics"""
        print('\n### Statistics:')
        print("Elapsed time: {:.3f} sec".format(self.elapsed))
        cnt_query_total = self.cnt_query1 + self.cnt_query2
        if not Prefs.BATCHFILE:
            print("Qname Delegation depth: %d" % self.delegation_depth)
        print("Number of delegations traversed: %d" % self.cnt_deleg)
        print("Number of queries performed (regular): %d" % self.cnt_query1)
        print("Number of queries performed:(nsaddr)   %d" % self.cnt_query2)
        if self.cnt_tcp:
            print("Number of TCP queries: %d" % self.cnt_tcp)
        if self.cnt_tcp_fallback:
            print("Number of TCP fallbacks: %d" % self.cnt_tcp_fallback)
        if self.cnt_fail:
            print("Number of queries failed: %d (%.2f%%)" %
                  (self.cnt_fail, (100.0 * self.cnt_fail/cnt_query_total)))
        if self.cnt_cname:
            print("Number of CNAME indirections: %d" % self.cnt_cname)

