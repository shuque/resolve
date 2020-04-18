"""
DNS Query class
"""

import dns.name
import dns.rdatatype
import dns.rdataclass

from reslib.rrset import RRset
from reslib.common import Prefs


class Query:
    """Query name class"""

    def __init__(self, qname, qtype, qclass, minimize=Prefs.MINIMIZE,
                 is_nsquery=False):
        if isinstance(qname, dns.name.Name):
            self.qname = qname
        else:
            self.qname = dns.name.from_text(qname)
        self.orig_qname = self.qname
        if isinstance(qtype, int):
            self.qtype = qtype
        else:
            self.qtype = dns.rdatatype.from_text(qtype)
        if isinstance(qclass, int):
            self.qclass = qclass
        else:
            self.qclass = dns.rdataclass.from_text(qclass)
        self.minimize = minimize
        self.is_nsquery = is_nsquery
        self.quiet = False                # don't print query being issued
        self.rcode = None
        self.got_answer = False
        self.elapsed_last = None
        self.cname_chain = []
        self.answer_rrset = []
        self.full_answer_rrset = []
        self.dnssec_status = False
        self.responses = []               # list of full response messages

    def set_quiet(self, action=True):
        """
        quiet=True prevents the query from printing trace information
        when VERBOSE mode is set.
        """
        self.quiet = action

    def print_full_answer(self):
        """Print full set of answer records including aliases"""
        if Prefs.VERBOSE:
            print("# ANSWER:")
        if self.full_answer_rrset:
            print("\n".join([x.to_text() for x in self.full_answer_rrset]))

    def get_answer_ip_list(self):
        """get list of answer IP addresses if any"""
        iplist = []
        for rrset in self.answer_rrset:
            if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                for rr in rrset:
                    iplist.append(rr.to_text())
        return iplist

    def set_minimized(self, zone):
        """Minimize query labels based on target zone"""
        labels_qname = self.orig_qname.labels
        labels_zone = zone.name.labels
        minLabels = len(labels_zone) + 1
        self.qname = dns.name.Name(labels_qname[-minLabels:])

    def prepend_label(self):
        """Prepend next label"""
        numLabels = len(self.qname) + 1
        self.qname = dns.name.Name(self.orig_qname[-numLabels:])

    def __repr__(self):
        return "<Query: {},{},{}>".format(self.qname, self.qtype, self.qclass)
