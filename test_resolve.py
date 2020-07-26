#!/usr/bin/env python3

"""
Unit tests for resolve
"""

import unittest

from reslib.exception import ResError
from reslib.prefs import Prefs
from reslib.cache import cache, RootZone, get_root_zone
from reslib.query import Query
from reslib.dnssec import key_cache
from reslib.stats import stats
from reslib.lookup import resolve_name, initialize_dnssec
from reslib.reset import reset_all


#
# Test Vectors
# Note: the DNS is a dynamic system. Over the course of time, some of
# these inputs may have different results as DNS changes occur. But at
# the time of this writing, they are correct.
#
TEST_VECTORS = [

    # Secure Answer
    [('www.huque.com.', 'AAAA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Insecure Answer
    [('google.com.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Secure SOA answer
    [('upenn.edu.', 'SOA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # DS doesn't match DNSKEY
    [('dnssec-failed.org.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=ResError)],

    # Secure CNAME chain, target zone and parent on same server
    [('fda.my.salesforce.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure CNAME chain, target zone and parent on same server
    [('fda.lightning.force.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure CNAME chain, target zone and parent on same server, target F5!
    [('na107.inst.siteforce.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure Answer
    [('salesforce.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Insecure answer due to CNAME redirection to insecure zone
    [('www.salesforce.com.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Insecure; DNSSEC island
    [('csail.mit.edu.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Secure algorithm 13, NSEC zone
    [('d2a13n1.rootcanary.net.', 'SOA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Bogus answer (bad signature)
    [('bogus.d2a13n3.rootcanary.net.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=ResError)],

    # Secure algorithm 14, NSEC3 zone
    [('d2a14n3.rootcanary.net.', 'SOA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Bogus answer (bad signature)
    [('bogus.d2a14n3.rootcanary.net.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=ResError)],

    # Secure algorithm 15, NSEC zone
    [('d2a15n1.rootcanary.net.', 'SOA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure algorithm 15, NSEC3 zone
    [('d2a15n3.rootcanary.net.', 'SOA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # NXDOMAIN: Secure algorithm 15, NSEC3 zone
    [('nxd.d2a15n3.rootcanary.net.', 'SOA'),
     dict(rcode=3, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure algorithm 16, NSEC3 zone
    [('d2a16n3.rootcanary.net.', 'SOA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Bogus answer (bad signature) ED448
    [('bogus.d2a16n3.rootcanary.net.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=ResError)],

    # Secure CNAME out of zone
    [('seas-web-test.huque.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure Wildcard response
    [('foo.bar.wild.huque.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=True, ent=False, exc=None)],

    # Secure Empty Non-Terminal (NSEC)
    [('ent.nseczone.huque.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=True, exc=None)],

    # Secure Empty Non-Terminal (NSEC3)
    [('ent.huque.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=True, exc=None)],

    # In-zone CNAME loop
    [('cname1.dnsrakuda.com.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=True, exc=ResError)],

    # Secure TLSA record
    [('_443._tcp.www.huque.com.', 'TLSA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure DNAME redirection to another secure zone
    [('www.upenn.huque.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure DNAME redirection to an insecure zone
    [('www.princeton.huque.com.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # DNAME + TLSA secure
    [('_25._tcp.blue.xy1.nl.', 'TLSA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Secure Dangling CNAME
    [('dangling1.huque.com.', 'A'),
     dict(rcode=3, secure=True, wildcard=False, ent=False, exc=None)],

    # Expired signature
    [('_443._tcp.expiredsig.busted.huque.com.', 'TLSA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=ResError)],

    # NSEC NODATA
    [('upenn.edu.', 'TLSA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # NSEC3 NODATA + CNAME
    [('www.huque.com.', 'TLSA'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # NSEC NODATA, large RRTYPE
    [('upenn.edu.', 'TYPE65531'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # NSEC NXDOMAIN
    [('www7.blah.ietf.org.', 'A'),
     dict(rcode=3, secure=True, wildcard=False, ent=False, exc=None)],

    # NSEC3 NXDOMAIN
    [('www97.huque.com.', 'A'),
     dict(rcode=3, secure=True, wildcard=False, ent=False, exc=None)],

    # Insecure under Secure zone on NS1
    [('sub1.n.huque.com.', 'SOA'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Secure answer; Sibling glue in Cloudflare
    [('embley.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Insecure CNAME to secure zone
    [('insecure-to-secure.z.salesforce.com.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Insecure subzone on same server as parent
    [('a.root-servers.net.', 'A'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Insecure deep subzone on same server as parent
    [('foo.bar.n.huque.com', 'SOA'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

    # Wildcard NODATA - NSEC
    [('blah.wild.nseczone.huque.com.', 'MX'),
     dict(rcode=0, secure=True, wildcard=False, ent=False, exc=None)],

    # Wildcard NODATA - NSEC3
    [('blah.wild.huque.com.', 'MX'),
     dict(rcode=0, secure=True, wildcard=True, ent=False, exc=None)],

    # Wildcard CNAME
    [('blah.wildcname.huque.com.', 'A'),
     dict(rcode=0, secure=True, wildcard=True, ent=False, exc=None)],

    # Wildcard + Insecure referral (from Google resolver bug)
    [('hrcompass--sandbox.cs82.cloudforce.com.', 'A'),
     dict(rcode=0, secure=False, wildcard=True, ent=False, exc=None)],

    # FORMER for unknown type
    [('_25._tcp.nist-gov.mail.protection.outlook.com.', 'TLSA'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=ResError)],

    # Insecure PTR record
    [('23.63.116.50.in-addr.arpa.', 'PTR'),
     dict(rcode=0, secure=False, wildcard=False, ent=False, exc=None)],

]


class TestAll(unittest.TestCase):

    """
    Run tests on all test vectors.
    """

    def setUp(self):
        pass

    def xx_test_plain(self):
        """Plain DNS tests"""
        print('\nPlain DNS tests:')
        count = 0
        for vector in TEST_VECTORS:
            count += 1
            with self.subTest(vector=vector):
                Prefs.DNSSEC = False
                reset_all()
                components, expect = vector
                qname, qtype = components
                print("subtest: {} {} ...".format(qname, qtype))
                query = Query(qname, qtype, 'IN')
                if not expect['secure'] and expect['exc'] is not None:
                    with self.assertRaises(expect['exc']):
                        resolve_name(query, RootZone, addResults=query)
                    continue
                resolve_name(query, RootZone, addResults=query)
                self.assertEqual(query.response.rcode(), expect['rcode'])
        print("Total subtests: {}".format(count))

    def xx_test_dnssec(self):
        """DNSSEC tests"""
        print('\nDNSSEC tests:')
        count = 0
        for vector in TEST_VECTORS:
            count += 1
            with self.subTest(vector=vector):
                Prefs.DNSSEC = True
                reset_all()
                components, expect = vector
                qname, qtype = components
                print("subtest: {} {} ...".format(qname, qtype))
                query = Query(qname, qtype, 'IN')
                if expect['exc'] is not None:
                    with self.assertRaises(expect['exc']):
                        resolve_name(query, RootZone, addResults=query)
                    continue
                resolve_name(query, RootZone, addResults=query)
                self.assertEqual(query.response.rcode(), expect['rcode'])
                self.assertEqual(query.is_secure(), expect['secure'],
                                 msg="DNSSEC secured?")
                if expect['wildcard']:
                    self.assertTrue(query.wildcard, msg="Wildcard")
                if expect['ent']:
                    self.assertTrue(query.ent, msg="Empty Non-Terminal")
        print("Total subtests: {}".format(count))


if __name__ == '__main__':
    unittest.main()
