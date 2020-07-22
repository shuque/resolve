# resolve.py

resolve.py  
A command line iterative DNS resolution testing program  
Author: Shumon Huque

A command line tool to perform iterative DNS resolution of a single
DNS name, type, and class. If either type or class or both are omitted, 
then a default type of 'A' (IPv4 address record), and a default class 
of 'IN' (Internet class) are used.

I originally wrote this program to investigate the behavior of authoritative
servers in the presence of query name minimization. Since then I've gradually
developed it into a more full fledged iterative resolver. These days, I
typically use this program to debug a variety of DNS problems. I prefer it
over "dig +trace", because the latter only resolves the exact name given to
it and does not follow CNAME and DNAME redirections, does not support query
name minimization, and does not perform DNSSEC validation. (The newer "delv"
program that ships with ISC BIND, does do DNSSEC validation, but requires the
help of a DNSSEC aware resolver, and does not perform iterative name resolution
by itself).

Pre-requisites:  
- Python 3
- [dnspython module](http://www.dnspython.org/) (included with most Linux/*BSD distributions)
- for DNSSEC support:
  - [pycryptodome](https://www.pycryptodome.org/en/latest/) or pycryptodomex
  - [pynacl](https://pypi.org/project/PyNaCl/)

DNSSEC validation is supported. The most popular signing algorithms
are supported (RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512,
ECDSAP256SHA256, ECDSAP384SHA384, and ED25519). Support for ED448
(algorithm 16) will be done in the near future once I locate a crypto
library that supports it.

The included document, [DNSSEC.md](DNSSEC.md) has many examples of the
use of DNSSEC with this program.

If you need to use a version without DNSSEC, because you haven't or don't
want to install the pycryptodome and pynacl crypto libraries, you can
install an earlier version of this module: v0.15 or v0.20 should run fine
without them. Just checkout the corresponding tags from this repo, or
grab the release tarballs for those versions. Direct links to these
earlier versions:
- https://github.com/shuque/resolve/tree/v0.15
- https://github.com/shuque/resolve/tree/v0.20


### Usage

```
resolve.py version 0.4.2
Perform iterative resolution of a DNS name, type, and class.

    Usage: resolve.py [Options] <qname> [<qtype>] [<qclass>]
           resolve.py [Options] -b <batchfile>

     Options:
     -v: increase verbosity level by 1 (default 0)
     -m: do qname minimization
     -t: use TCP only
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
     -eN: use EDNS0 buffer size N (default: 1460; 0=disable EDNS)
     -z: perform DNSSEC validation (default is no)
     -c: dump zone/ns/key caches at end of program execution
     -4: only use IPv4 transport
     -6: only use IPv6 transport
     -b <batchfile>: batch file mode

When using -b, <batchfile> contains one (space separated) query name, type,
class per line.
```

### Installation

To install system wide:

* (as root) python3 setup.py install

To install for your own account:

* python3 setup.py install --user

To install in a python virtual environment, just:

* python3 setup.py install


### Examples

This program implements the normal iterative DNS resolution algorithm 
described in the DNS protocol specifications.

Here's a basic lookup of the IPv6 address of www.seas.upenn.edu:

```
$ resolve.py www.seas.upenn.edu. AAAA
# ANSWER to QUERY: www.seas.upenn.edu. AAAA IN
# RCODE: NOERROR
www.seas.upenn.edu. 120 IN AAAA 2607:f470:8:64:5ea5::9
```

A more complicated answer involving a chain of aliases:

```
$ resolve.py fda.my.salesforce.com
# ANSWER to QUERY: fda.my.salesforce.com. A IN
# RCODE: NOERROR
fda.my.salesforce.com. 300 IN CNAME na21.my.salesforce.com.
na21.my.salesforce.com. 300 IN CNAME na21-wax.gia1.my.salesforce.com.
na21-wax.gia1.my.salesforce.com. 30 IN CNAME na21-wax.my.salesforce.com.
na21-wax.my.salesforce.com. 120 IN A 96.43.153.40
na21-wax.my.salesforce.com. 120 IN A 96.43.153.168
```

Here's the first lookup with the -v switch added (increase verbosity
level), to show the iterative resolution path taken through the DNS
hierarchy:

```
$ resolve.py -v www.seas.upenn.edu AAAA
ZONE: .
TTL: Delegation: 518400
NS: a.root-servers.net. 198.41.0.4 2001:503:ba3e::2:30
NS: b.root-servers.net. 199.9.14.201 2001:500:200::b
NS: c.root-servers.net. 192.33.4.12 2001:500:2::c
NS: d.root-servers.net. 199.7.91.13 2001:500:2d::d
NS: e.root-servers.net. 192.203.230.10 2001:500:a8::e
NS: f.root-servers.net. 192.5.5.241 2001:500:2f::f
NS: g.root-servers.net. 192.112.36.4 2001:500:12::d0d
NS: h.root-servers.net. 198.97.190.53 2001:500:1::53
NS: i.root-servers.net. 192.36.148.17 2001:7fe::53
NS: j.root-servers.net. 192.58.128.30 2001:503:c27::2:30
NS: k.root-servers.net. 193.0.14.129 2001:7fd::1
NS: l.root-servers.net. 199.7.83.42 2001:500:9f::42
NS: m.root-servers.net. 202.12.27.33 2001:dc3::35

# QUERY: www.seas.upenn.edu. AAAA IN at zone . address 2001:503:ba3e::2:30
#        [Referral to zone: edu. in 0.013 s]
ZONE: edu.
TTL: Delegation: 172800
NS: a.edu-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: b.edu-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.edu-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.edu-servers.net. 192.31.80.30 2001:500:856e::30
NS: e.edu-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: f.edu-servers.net. 192.35.51.30 2001:503:d414::30
NS: g.edu-servers.net. 192.42.93.30 2001:503:eea3::30
NS: h.edu-servers.net. 192.54.112.30 2001:502:8cc::30
NS: i.edu-servers.net. 192.43.172.30 2001:503:39c1::30
NS: j.edu-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.edu-servers.net. 192.52.178.30 2001:503:d2d::30
NS: l.edu-servers.net. 192.41.162.30 2001:500:d937::30
NS: m.edu-servers.net. 192.55.83.30 2001:501:b1f9::30

# QUERY: www.seas.upenn.edu. AAAA IN at zone edu. address 2001:502:8cc::30
#        [Referral to zone: upenn.edu. in 0.029 s]
ZONE: upenn.edu.
TTL: Delegation: 172800
NS: dns1.udel.edu. 128.175.13.16
NS: dns2.udel.edu. 128.175.13.17
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
NS: adns4.upenn.edu. 208.94.148.32 2600:1800:5::1:0
NS: adns5.upenn.edu. 208.80.124.32 2600:1801:6::1:0
NS: adns6.upenn.edu. 208.80.126.32 2600:1802:7::1:0

# QUERY: www.seas.upenn.edu. AAAA IN at zone upenn.edu. address 2607:f470:1001::1:a
#        [Got answer in 0.015 s]

# ANSWER to QUERY: www.seas.upenn.edu. AAAA IN
# RCODE: NOERROR
www.seas.upenn.edu. 120 IN AAAA 2607:f470:8:64:5ea5::9
```

### DNSSEC validation mode

Use -z to turn on DNSSEC validation. In this mode, wih the -v switch,
the program additionally shows DS and DNSKEY record information, whether
the referrals encountered were secure or not, and whether the final
answer is end-to-end DNSSEC validated. Example output:

```
$ resolve.py -vz www.upenn.edu. A
ZONE: .
TTL: Delegation: 518400
NS: a.root-servers.net. 198.41.0.4 2001:503:ba3e::2:30
NS: b.root-servers.net. 199.9.14.201 2001:500:200::b
NS: c.root-servers.net. 192.33.4.12 2001:500:2::c
NS: d.root-servers.net. 199.7.91.13 2001:500:2d::d
NS: e.root-servers.net. 192.203.230.10 2001:500:a8::e
NS: f.root-servers.net. 192.5.5.241 2001:500:2f::f
NS: g.root-servers.net. 192.112.36.4 2001:500:12::d0d
NS: h.root-servers.net. 198.97.190.53 2001:500:1::53
NS: i.root-servers.net. 192.36.148.17 2001:7fe::53
NS: j.root-servers.net. 192.58.128.30 2001:503:c27::2:30
NS: k.root-servers.net. 193.0.14.129 2001:7fd::1
NS: l.root-servers.net. 199.7.83.42 2001:500:9f::42
NS: m.root-servers.net. 202.12.27.33 2001:dc3::35
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE

# QUERY: www.upenn.edu. A IN at zone . address 2001:500:9f::42
#        [SECURE Referral to zone: edu. in 0.024 s]
ZONE: edu.
TTL: Delegation: 172800, Signer: 86400
NS: a.edu-servers.net. 2001:503:a83e::2:30 192.5.6.30
NS: b.edu-servers.net. 2001:503:231d::2:30 192.33.14.30
NS: c.edu-servers.net. 2001:503:83eb::30 192.26.92.30
NS: d.edu-servers.net. 2001:500:856e::30 192.31.80.30
NS: e.edu-servers.net. 2001:502:1ca1::30 192.12.94.30
NS: f.edu-servers.net. 2001:503:d414::30 192.35.51.30
NS: g.edu-servers.net. 2001:503:eea3::30 192.42.93.30
NS: h.edu-servers.net. 2001:502:8cc::30 192.54.112.30
NS: i.edu-servers.net. 2001:503:39c1::30 192.43.172.30
NS: j.edu-servers.net. 2001:502:7094::30 192.48.79.30
NS: k.edu-servers.net. 2001:503:d2d::30 192.52.178.30
NS: l.edu-servers.net. 2001:500:d937::30 192.41.162.30
NS: m.edu-servers.net. 2001:501:b1f9::30 192.55.83.30
DS: 28065 8 2 4172496cde85534e51129040355bd04b1fcfebae996dfdde652006f6f8b2ce76
DNSKEY: edu. 257 28065 RSASHA256 (8) 2048-bits ZONE SEP
DNSKEY: edu. 256 8663 RSASHA256 (8) 1280-bits ZONE

# QUERY: www.upenn.edu. A IN at zone edu. address 2001:501:b1f9::30
#        [SECURE Referral to zone: upenn.edu. in 0.006 s]
ZONE: upenn.edu.
TTL: Delegation: 172800, Signer: 86400
NS: dns1.udel.edu. 128.175.13.16
NS: dns2.udel.edu. 128.175.13.17
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
NS: adns4.upenn.edu. 208.94.148.32 2600:1800:5::1:0
NS: adns5.upenn.edu. 208.80.124.32 2600:1801:6::1:0
NS: adns6.upenn.edu. 208.80.126.32 2600:1802:7::1:0
DS: 10500 13 2 4629d71f8f9dd9ceac6a047041b161c9a7812406e449a80c0b319c3925b48c52
DNSKEY: upenn.edu. 257 10500 ECDSA-P256 (13) 512-bits ZONE SEP
DNSKEY: upenn.edu. 256 54481 ECDSA-P256 (13) 512-bits ZONE

# QUERY: www.upenn.edu. A IN at zone upenn.edu. address 208.80.126.32
#        [Got answer in 0.007 s]
# SECURE: www.upenn.edu. 300 IN A 151.101.130.217
# SECURE: www.upenn.edu. 300 IN A 151.101.194.217
# SECURE: www.upenn.edu. 300 IN A 151.101.66.217
# SECURE: www.upenn.edu. 300 IN A 151.101.2.217

# ANSWER to QUERY: www.upenn.edu. A IN
# RCODE: NOERROR
# DNSSEC status: SECURE
www.upenn.edu. 300 IN A 151.101.130.217
www.upenn.edu. 300 IN A 151.101.194.217
www.upenn.edu. 300 IN A 151.101.66.217
www.upenn.edu. 300 IN A 151.101.2.217
```

Many more examples of DNSSEC, including both successful and failed responses
of various kinds (DS mismatch, signature verification failures, signature
expirations, and more) are included in the accompanying document
[DNSSEC.md](DNSSEC.md).


### Batch mode

If executing many different queries, then it is recommended to use
the batch mode (-b inputfile). This will cause the program to use its
cache of previously queried zones and nameserver records, increasing
performance, and reducing the possibility of responses being rate
limited by authoritative servers.

The format of the batch input file is a space-separated query-name,
query-type, and query-class per line. The type and class if omitted
default to 'A' and 'IN'.


### Query-name minimization mode

When invoked with the -m switch, this program uses a **query name 
minimization** algorithm that exposes only the needed query labels to 
authoritative servers as it traverses the DNS delegation hierarchy down 
to the target DNS zone. This is a more *privacy preserving* mode of DNS 
resolution, that is specified in
[RFC 7816](https://tools.ietf.org/html/rfc7816). The program deviates
slightly from that specification, in that it makes no attempt to hide
the query-type (e.g. by issuing NS record queries until it reaches the
target zone). Experience in the field has shown that there are many
nameservers that unfortunately don't respond to NS queries.

Here's an example run with qname minimization (-m) and the verbose (-v)
option:

```
$ resolve.py -vm www.seas.upenn.edu AAAA
ZONE: .
TTL: Delegation: 518400
NS: a.root-servers.net. 198.41.0.4 2001:503:ba3e::2:30
NS: b.root-servers.net. 199.9.14.201 2001:500:200::b
NS: c.root-servers.net. 192.33.4.12 2001:500:2::c
NS: d.root-servers.net. 199.7.91.13 2001:500:2d::d
NS: e.root-servers.net. 192.203.230.10 2001:500:a8::e
NS: f.root-servers.net. 192.5.5.241 2001:500:2f::f
NS: g.root-servers.net. 192.112.36.4 2001:500:12::d0d
NS: h.root-servers.net. 198.97.190.53 2001:500:1::53
NS: i.root-servers.net. 192.36.148.17 2001:7fe::53
NS: j.root-servers.net. 192.58.128.30 2001:503:c27::2:30
NS: k.root-servers.net. 193.0.14.129 2001:7fd::1
NS: l.root-servers.net. 199.7.83.42 2001:500:9f::42
NS: m.root-servers.net. 202.12.27.33 2001:dc3::35

# QUERY: edu. AAAA IN at zone . address 2001:500:2::c
#        [Referral to zone: edu. in 0.014 s]
ZONE: edu.
TTL: Delegation: 172800
NS: d.edu-servers.net. 2001:500:856e::30 192.31.80.30
NS: f.edu-servers.net. 2001:503:d414::30 192.35.51.30
NS: l.edu-servers.net. 2001:500:d937::30 192.41.162.30
NS: e.edu-servers.net. 2001:502:1ca1::30 192.12.94.30
NS: c.edu-servers.net. 2001:503:83eb::30 192.26.92.30
NS: m.edu-servers.net. 2001:501:b1f9::30 192.55.83.30
NS: h.edu-servers.net. 2001:502:8cc::30 192.54.112.30
NS: i.edu-servers.net. 2001:503:39c1::30 192.43.172.30
NS: j.edu-servers.net. 2001:502:7094::30 192.48.79.30
NS: a.edu-servers.net. 2001:503:a83e::2:30 192.5.6.30
NS: k.edu-servers.net. 2001:503:d2d::30 192.52.178.30
NS: b.edu-servers.net. 2001:503:231d::2:30 192.33.14.30
NS: g.edu-servers.net. 2001:503:eea3::30 192.42.93.30

# QUERY: upenn.edu. AAAA IN at zone edu. address 192.12.94.30
#        [Referral to zone: upenn.edu. in 0.050 s]
ZONE: upenn.edu.
TTL: Delegation: 172800
NS: dns1.udel.edu. 128.175.13.16
NS: dns2.udel.edu. 128.175.13.17
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
NS: adns4.upenn.edu. 208.94.148.32 2600:1800:5::1:0
NS: adns5.upenn.edu. 208.80.124.32 2600:1801:6::1:0
NS: adns6.upenn.edu. 208.80.126.32 2600:1802:7::1:0

# QUERY: seas.upenn.edu. AAAA IN at zone upenn.edu. address 2607:f470:1001::1:a
#        [Got answer in 0.009 s]

# QUERY: www.seas.upenn.edu. AAAA IN at zone upenn.edu. address 2600:1802:7::1:0
#        [Got answer in 0.006 s]

# ANSWER to QUERY: www.seas.upenn.edu. AAAA IN
# RCODE: NOERROR
www.seas.upenn.edu. 120 IN AAAA 2607:f470:8:64:5ea5::9
```

Some Content Delivery Networks (CDN) like Akamai and Cloudflare have 
problems with minimized query names, because they respond incorrectly
to intermediate query names with NXDOMAIN (response code 3). The correct
response should be NOERROR, AA-bit set, and an empty answer section. 
Invoking resolve.py with the -x switch implements a hack that works 
around this incorrect behavior by ignoring intermediate NXDOMAIN 
responses. The Cloudflare servers additionally appear to respond to 
some intermediate qnames with REFUSED.

This behavior of the Akamai and Cloudflare DNS servers was observed 
in January 2015. Further details can be found in a
[presentation I did on this topic at the summer 2015 DNS-OARC workshop](https://indico.dns-oarc.net/event/21/contributions/298/attachments/267/487/qname-min.pdf). Cloudflare has already fixed their DNS implementation (April 2015).
Akamai has partially done so.

The examples below used an older version of the program that shows
a bit less information (namely, it doesn't show the server IP address
queried or associated referral data).

Attempted resolution of www.upenn.edu (on Akamai, January 2015):

```
$ resolve.py -vm www.upenn.edu. A
>> Query: edu. A IN at zone .
>>        [Got Referral to zone: edu.]
>> Query: upenn.edu. A IN at zone edu.
>>        [Got Referral to zone: upenn.edu.]
>> Query: www.upenn.edu. A IN at zone upenn.edu.
www.upenn.edu. 300 IN CNAME www.upenn.edu-dscg.edgesuite.net.
>> Query: net. A IN at zone .
>>        [Got Referral to zone: net.]
>> Query: edgesuite.net. A IN at zone net.
>>        [Got Referral to zone: edgesuite.net.]
>> Query: edu-dscg.edgesuite.net. A IN at zone edgesuite.net.
ERROR: NXDOMAIN: edu-dscg.edgesuite.net. not found
www.upenn.edu. 300 IN CNAME www.upenn.edu-dscg.edgesuite.net.
```

Repeating the query with -x (intermediate NXDOMAIN workaround) allows
the program to proceed to the final answer:

```
$ resolve.py -vmx www.upenn.edu
>> Query: edu. A IN at zone .
>>        [Got Referral to zone: edu.]
>> Query: upenn.edu. A IN at zone edu.
>>        [Got Referral to zone: upenn.edu.]
>> Query: www.upenn.edu. A IN at zone upenn.edu.
www.upenn.edu. 300 IN CNAME www.upenn.edu-dscg.edgesuite.net.
>> Query: net. A IN at zone .
>>        [Got Referral to zone: net.]
>> Query: edgesuite.net. A IN at zone net.
>>        [Got Referral to zone: edgesuite.net.]
>> Query: edu-dscg.edgesuite.net. A IN at zone edgesuite.net.
ERROR: NXDOMAIN: edu-dscg.edgesuite.net. not found
>> Query: upenn.edu-dscg.edgesuite.net. A IN at zone edgesuite.net.
ERROR: NXDOMAIN: upenn.edu-dscg.edgesuite.net. not found
>> Query: www.upenn.edu-dscg.edgesuite.net. A IN at zone edgesuite.net.
www.upenn.edu-dscg.edgesuite.net. 21600 IN CNAME a1165.dscg.akamai.net.
>> Query: akamai.net. A IN at zone net.
>>        [Got Referral to zone: akamai.net.]
>> Query: dscg.akamai.net. A IN at zone akamai.net.
>> Query: a1165.dscg.akamai.net. A IN at zone akamai.net.
>>        [Got Referral to zone: dscg.akamai.net.]
>> Query: a1165.dscg.akamai.net. A IN at zone dscg.akamai.net.
www.upenn.edu. 300 IN CNAME www.upenn.edu-dscg.edgesuite.net.
www.upenn.edu-dscg.edgesuite.net. 21600 IN CNAME a1165.dscg.akamai.net.
a1165.dscg.akamai.net. 20 IN A 23.62.6.59
a1165.dscg.akamai.net. 20 IN A 23.62.6.81
```

Resolving www.ietf.org (on Cloudflare, January 2015) with the NXDOMAIN
workaround shows the following:

In this case, the first empty non-terminal, cdn.cloudflare.net returns
NXDOMAIN, the next one, org.cdn.cloudflare.net returns REFUSED, the
next one, ietf.org.cdn.cloudflare.net responds correctly (NOERROR, AA-bit,
empty answer), and the final name www.ietf.org.cdn.cloudflare.net produces
the answer records.

```
$ resolve.py -vmx www.ietf.org
>> Query: org. A IN at zone .
>>        [Got Referral to zone: org.]
>> Query: ietf.org. A IN at zone org.
>>        [Got Referral to zone: ietf.org.]
>> Query: www.ietf.org. A IN at zone ietf.org.
www.ietf.org. 1800 IN CNAME www.ietf.org.cdn.cloudflare.net.
>> Query: cloudflare.net. A IN at zone net.
>>        [Got Referral to zone: cloudflare.net.]
>> Query: cdn.cloudflare.net. A IN at zone cloudflare.net.
ERROR: NXDOMAIN: cdn.cloudflare.net. not found
>> Query: org.cdn.cloudflare.net. A IN at zone cloudflare.net.
WARNING: response REFUSED from 173.245.59.31
WARNING: response REFUSED from 2400:cb00:2049:1::adf5:3b1f
WARNING: response REFUSED from 198.41.222.131
WARNING: response REFUSED from 2400:cb00:2049:1::c629:de83
WARNING: response REFUSED from 198.41.222.31
WARNING: response REFUSED from 2400:cb00:2049:1::c629:de1f
WARNING: response REFUSED from 198.41.223.131
WARNING: response REFUSED from 2400:cb00:2049:1::c629:df83
WARNING: response REFUSED from 198.41.223.31
WARNING: response REFUSED from 2400:cb00:2049:1::c629:df1f
ERROR: Queries to all servers for zone cloudflare.net. failed.
>> Query: ietf.org.cdn.cloudflare.net. A IN at zone cloudflare.net.
>> Query: www.ietf.org.cdn.cloudflare.net. A IN at zone cloudflare.net.
www.ietf.org. 1800 IN CNAME www.ietf.org.cdn.cloudflare.net.
www.ietf.org.cdn.cloudflare.net. 300 IN A 104.20.0.85
www.ietf.org.cdn.cloudflare.net. 300 IN A 104.20.1.85
```
