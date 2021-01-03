"""
Results ...

"""

import json

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.dnssec

from reslib.prefs import Prefs


def jsonout(query):
    """
    Print JSON encoded results for given query
    """
    result = {}
    result['query'] = {
        "name": query.orig_qname.to_text(),
        "type": dns.rdatatype.to_text(query.qtype),
        "class": dns.rdataclass.to_text(query.qclass),
    }
    result['rcode'] = dns.rcode.to_text(query.response.rcode())
    if query.response.rcode() == 0 and query.nodata:
        result['nodata'] = True
    if Prefs.DNSSEC:
        result['secure'] = query.is_secure()
        if query.wildcard:
            result['wildcard'] = "{}".format(query.wildcard)
        if query.ent is not None:
            if query.ent == query.orig_qname:
                result['ent'] = True
    result['answers'] = []
    for x in query.full_answer_rrset:
        rrset = x.rrset
        #sig = x.rrsig
        rrset_dict = {
            "name": x.rrname.to_text(),
            "type": dns.rdatatype.to_text(x.rrtype),
            "class": dns.rdataclass.to_text(rrset.rdclass),
            "ttl": x.rrset.ttl,
            "rdata": [],
        }
        for rdata in x.rrset.to_rdataset():
            rrset_dict['rdata'].append(rdata.to_text())
        result['answers'].append(rrset_dict)
    print(json.dumps(result))
