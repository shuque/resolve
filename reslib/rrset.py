"""
RRset class. Contains an RRset and associated signatures.
"""

import dns.rdatatype


class RRset:
    """Class to hold an RRset and associated signatures if any"""

    def __init__(self, rrname, rrtype, rrset=None, rrsig=None):
        self.rrname = rrname
        self.rrtype = rrtype
        self.validated = False
        self.rrset = rrset if rrset else None
        self.rrsig = rrsig if rrsig else None

    def set_rrsig(self, rrsig):
        """Set rrsig"""
        self.rrsig = rrsig

    def set_rrset(self, rrset):
        """Set rrset"""
        self.rrset = rrset

    def set_validated(self):
        """Set status to validated (after DNSSEC validation)"""
        self.validated = True

    def wildcard(self):
        """Return wildcard name, if wildcard synthesis present"""
        num_labels = len(self.rrname.labels)
        rrsig_lcount = self.rrsig[0].labels + 1
        if num_labels == rrsig_lcount:
            return None
        label_tuple = ('*',) + self.rrname.labels[num_labels-rrsig_lcount:]
        return dns.name.Name(label_tuple)

    def __repr__(self):
        return "<RRset: {}/{}{}>".format(self.rrset.name,
                                         dns.rdatatype.to_text(self.rrtype),
                                         " (signed)" if self.rrsig else "")
