"""
DNS Query class
"""

import dns.name
import dns.rdatatype
import dns.rdataclass

from reslib.prefs import Prefs
from reslib.exception import ResError
from reslib.dnssec import key_cache, sig_validity


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
        self.quiet = False                  # don't print query being issued
        self.dnskey_novalidate = False      # for pre-DS matching queries
        self.nodata = False
        self.got_answer = False
        self.elapsed_last = None
        self.cname_chain = []
        self.answer_rrset = []              # list of RRset
        self.full_answer_rrset = []         # list of RRset
        self.dnssec_secure = False          # only set for negative responses?
        self.response = None                # full response message
        self.latest_rcode = None
        self.wildcard = None
        self.ent = None

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

    def is_secure(self):
        """Is full assembled answer secure?"""
        count = 0
        secure_count = 0
        if self.full_answer_rrset:
            for x in self.full_answer_rrset:
                count += 1
                if x.validated:
                    secure_count += 1
            return key_cache.SecureSoFar and (secure_count == count)
        return  self.dnssec_secure

    def print_full_answer(self):
        """
        Print full set of answer records including aliases. Report
        security status if DNSSEC is being used.
        """
        secure = self.is_secure()

        print("# ANSWER to QUERY: {}".format(self.orig_query_string()))
        rcode_text = dns.rcode.to_text(self.response.rcode())
        print("# RCODE: {}".format(rcode_text), end='')

        if self.response.rcode() == 0 and self.nodata:
            print(" (NODATA)")
        else:
            print('')

        if Prefs.DNSSEC:
            print("# DNSSEC status: {}".format(
                "SECURE" if secure else "INSECURE"))
            if self.wildcard:
                print("# WILDCARD match: {}".format(self.wildcard))
            if self.ent is not None:
                if self.ent == self.orig_qname:
                    print("# EMPTY NON-TERMINAL detected")

        if self.full_answer_rrset:
            for x in self.full_answer_rrset:
                print(x.rrset.to_text())
                if Prefs.DNSSEC and Prefs.VERBOSE > 1:
                    if x.rrsig is not None:
                        for sig_rr in x.rrsig:
                            print("{} {} {} {} {} # validity={}".format(
                                x.rrsig.name,
                                x.rrsig.ttl,
                                dns.rdataclass.to_text(x.rrsig.rdclass),
                                dns.rdatatype.to_text(x.rrsig.rdtype),
                                sig_rr,
                                sig_validity(sig_rr)))

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

    def orig_query_string(self):
        return "{} {} {}".format(self.orig_qname if self.minimize else self.qname,
                                 dns.rdatatype.to_text(self.qtype),
                                 dns.rdataclass.to_text(self.qclass))

    def __repr__(self):
        return "QUERY: {} {} {}".format(self.qname,
                                        dns.rdatatype.to_text(self.qtype),
                                        dns.rdataclass.to_text(self.qclass))
