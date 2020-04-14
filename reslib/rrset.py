"""
RRset class. Contains an RRset and associated signatures.
"""

import dns.rdatatype


class RRset:
    """Class to hold an RRset and signatures if any"""

    def __init__(self, rrname, rrtype, rrset=None, rrsig=None):
        self.rrname = rrname
        self.rrtype = rrtype
        self.validated = False
        if rrset:
            self.rrset = rrset
            self.rrsigs = None
        elif rrsig:
            self.rrsigs = rrsig
            self.rrset = None

    def set_rrsig(self, rrsig):
        self.rrsigs = rrsig

    def set_rrset(self, rrset):
        self.rrset = rrset

    def set_validated(self):
        self.validated = True

    def __repr__(self):
        return "<RRset: {}/{}{}>".format(self.rrset.name,
                                         dns.rdatatype.to_text(self.rrtype),
                                         " (signed)" if self.rrsigs else "")
