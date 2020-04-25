"""
DNS Query class
"""

import dns.name
import dns.rdatatype
import dns.rdataclass

from reslib.common import Prefs
from reslib.exception import ResError


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
        self.dnskey_novalidate = False    # for pre-DS matching queries
        self.got_answer = False
        self.elapsed_last = None
        self.cname_chain = []
        self.answer_rrset = []
        self.full_answer_rrset = []
        self.dnssec_status = False
        self.response = None                # full response message
        self.latest_rcode = None

    def set_quiet(self, action=True):
        """
        quiet=True prevents the query from printing trace information
        when VERBOSE mode is set.
        """
        self.quiet = action

    def add_to_full_answer(self, srrset):
        """add rrset to full answer set"""
        names_and_types = [(x.rrset.name, x.rrset.rdtype) for x in
                           self.full_answer_rrset]
        if (srrset.rrname, srrset.rrtype) in names_and_types:
            raise ResError("RRset answer loop detected: {}".format(srrset.rrset))
        self.full_answer_rrset.append(srrset)

    def print_full_answer(self):
        """
        Print full set of answer records including aliases. Report
        security status if DNSSEC is being used.
        """
        count = 0
        secure_count = 0
        if self.full_answer_rrset:
            print("# ANSWER:")
            for x in self.full_answer_rrset:
                count += 1
                if x.validated:
                    secure_count += 1
                print(x.rrset.to_text())
            if Prefs.DNSSEC:
                print("# DNSSEC status: {}".format(
                    "SECURE" if (secure_count == count) else "INSECURE"))
        else:
            if self.response.rcode() == 0:
                print("# ANSWER: NODATA")
            elif self.response.rcode() == 3:
                print("# ANSWER: NXDOMAIN")

    def get_answer_ip_list(self):
        """get list of answer IP addresses if any"""
        iplist = []
        for srrset in self.answer_rrset:
            rrset = srrset.rrset
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
        return "<Query: {},{},{}>".format(self.qname,
                                          dns.rdatatype.to_text(self.qtype),
                                          dns.rdataclass.to_text(self.qclass))
