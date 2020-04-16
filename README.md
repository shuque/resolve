# resolve.py

resolve.py  
A command line iterative DNS resolution testing program  
Author: Shumon Huque

A command line tool to perform iterative DNS resolution of a single
DNS name, type, and class. If either type or class or both are omitted, 
then a  default type of 'A' (IPv4 address record), and a default class 
of 'IN' (Internet class) are used.

I often use this program to debug a variety of DNS configuration
problems. I prefer it these days to "dig +trace", because the latter
only resolves the exact name given to it, and does not follow CNAME
and DNAME redirections, and also does not support qname minimization.

Pre-requisites:  
- Python 3
- [dnspython module](http://www.dnspython.org/) (included with most Linux/*BSD distributions)
- DNSSEC support (in development) requires additional modules:
  - [pycryptodome](https://www.pycryptodome.org/en/latest/)
  - [pynacl](https://pypi.org/project/PyNaCl/)

DNSSEC validation is still under development. A preliminary implementation
of full chain authentication of positive answers is done, although some
fine tuning is needed. Authenticated denial of existence is not yet implemented.
The most popular signing algorithms are supported (5, 7, 8, 10, 13, 14, 15).
Algorithm 16 is planned for the future.

If you need to use a version without DNSSEC, because you haven't or don't
want to install the pycryptodome and pynacl crypto libraries, you can
install an earlier version of this module: v0.15 or v0.20 should run fine
without them. Just checkout the corresponding tags from this repo, or
grab the release tarballs for those versions. Direct links to these
earlier versions:
- https://github.com/shuque/resolve/tree/v0.15
- https://github.com/shuque/resolve/tree/v0.20


```
resolve.py version 0.22
Perform iterative resolution of a DNS name, type, and class.

    Usage: resolve.py [-mtv:snxe:zc] <qname> [<qtype>] [<qclass>]
           resolve.py [-mtv:snxe:zc] -b <batchfile>

     -m: do qname minimization
     -t: use TCP only
     -v N: verbosity level: 0,1,2 (0 default)
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
     -e N: use EDNS0 buffer size N (default: 0; 0=disable EDNS)
     -z: use DNSSEC (default is no; work in progress)
     -c: dump zone/ns/key caches at end
     -b <batchfile>: batch file mode

When using -b, <batchfile> contains one (space separated) query name, type,
class per line.
```

This program implements the normal iterative DNS resolution algorithm 
described in the DNS protocol specifications.

Here's a basic lookup of the IPv6 address of www.seas.upenn.edu:

```
$ resolve.py www.seas.upenn.edu. AAAA
www.seas.upenn.edu. 120 IN AAAA 2607:f470:8:64:5ea5::9
```

Here's the same lookup with the -v1 switch (increase verbosity level
to 1) to show the iterative resolution path taken through the DNS
hierarchy:

```
$ resolve.py -v1 www.seas.upenn.edu AAAA

# QUERY: www.seas.upenn.edu. AAAA IN at zone . address 198.41.0.4
#        [Referral to zone: edu. in 0.012 s]
ZONE: edu.
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

# QUERY: www.seas.upenn.edu. AAAA IN at zone edu. address 192.5.6.30
#        [Referral to zone: upenn.edu. in 0.012 s]
ZONE: upenn.edu.
NS: dns1.udel.edu. 128.175.13.16
NS: dns2.udel.edu. 128.175.13.17
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
NS: adns4.upenn.edu. 208.94.148.32 2600:1800:5::1:0
NS: adns5.upenn.edu. 208.80.124.32 2600:1801:6::1:0
NS: adns6.upenn.edu. 208.80.126.32 2600:1802:7::1:0

# QUERY: www.seas.upenn.edu. AAAA IN at zone upenn.edu. address 128.175.13.16
#        [Got answer in 0.018 s]

# ANSWER:
www.seas.upenn.edu. 120 IN AAAA 2607:f470:8:64:5ea5::9
```

### DNSSEC validation mode

Use -z to turn on DNSSEC validation. Example output:

```
$ resolve.py -v1 -z www.huque.com. A

# QUERY: www.huque.com. A IN at zone . address 198.41.0.4
#        [Referral to zone: com. in 0.015 s]
ZONE: com.
NS: e.gtld-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: b.gtld-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: j.gtld-servers.net. 192.48.79.30 2001:502:7094::30
NS: m.gtld-servers.net. 192.55.83.30 2001:501:b1f9::30
NS: i.gtld-servers.net. 192.43.172.30 2001:503:39c1::30
NS: f.gtld-servers.net. 192.35.51.30 2001:503:d414::30
NS: a.gtld-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: g.gtld-servers.net. 192.42.93.30 2001:503:eea3::30
NS: h.gtld-servers.net. 192.54.112.30 2001:502:8cc::30
NS: l.gtld-servers.net. 192.41.162.30 2001:500:d937::30
NS: k.gtld-servers.net. 192.52.178.30 2001:503:d2d::30
NS: c.gtld-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.gtld-servers.net. 192.31.80.30 2001:500:856e::30
DS: 30909 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766
DNSKEY: com. 256 56311 8
DNSKEY: com. 256 39844 8
DNSKEY: com. 257 30909 8

# QUERY: www.huque.com. A IN at zone com. address 192.12.94.30
#        [Referral to zone: huque.com. in 0.037 s]
ZONE: huque.com.
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
DS: 40924 8 2 816524eb1c3b7d1315ae8330652dd17909c95de0533c1f2dc023bffedb1f5e9b
DNSKEY: huque.com. 257 40924 8
DNSKEY: huque.com. 256 14703 8

# QUERY: www.huque.com. A IN at zone huque.com. address 128.91.254.22
#        [Got answer in 0.011 s]
SECURE: www.huque.com. 300 IN CNAME cheetara.huque.com.
www.huque.com. 300 IN CNAME cheetara.huque.com.
SECURE: cheetara.huque.com. 86400 IN A 50.116.63.23

# QUERY: cheetara.huque.com. A IN at zone huque.com. address 128.91.254.22
#        [Got answer in 0.010 s]
SECURE: cheetara.huque.com. 86400 IN A 50.116.63.23

# ANSWER:
www.huque.com. 300 IN CNAME cheetara.huque.com.
cheetara.huque.com. 86400 IN A 50.116.63.23
```

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
$ resolve.py -v1 -m www.seas.upenn.edu AAAA

# QUERY: edu. AAAA IN at zone . address 198.41.0.4
#        [Referral to zone: edu. in 0.011 s]
ZONE: edu.
NS: b.edu-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: f.edu-servers.net. 192.35.51.30 2001:503:d414::30
NS: i.edu-servers.net. 192.43.172.30 2001:503:39c1::30
NS: a.edu-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: g.edu-servers.net. 192.42.93.30 2001:503:eea3::30
NS: j.edu-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.edu-servers.net. 192.52.178.30 2001:503:d2d::30
NS: m.edu-servers.net. 192.55.83.30 2001:501:b1f9::30
NS: l.edu-servers.net. 192.41.162.30 2001:500:d937::30
NS: h.edu-servers.net. 192.54.112.30 2001:502:8cc::30
NS: c.edu-servers.net. 192.26.92.30 2001:503:83eb::30
NS: e.edu-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: d.edu-servers.net. 192.31.80.30 2001:500:856e::30

# QUERY: upenn.edu. AAAA IN at zone edu. address 192.33.14.30
#        [Referral to zone: upenn.edu. in 0.032 s]
ZONE: upenn.edu.
NS: dns1.udel.edu. 128.175.13.16
NS: dns2.udel.edu. 128.175.13.17
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
NS: adns4.upenn.edu. 208.94.148.32 2600:1800:5::1:0
NS: adns5.upenn.edu. 208.80.124.32 2600:1801:6::1:0
NS: adns6.upenn.edu. 208.80.126.32 2600:1802:7::1:0

# QUERY: seas.upenn.edu. AAAA IN at zone upenn.edu. address 128.175.13.16
#        [Got answer in 0.010 s]
ERROR: NODATA: seas.upenn.edu. of type AAAA not found

# QUERY: www.seas.upenn.edu. AAAA IN at zone upenn.edu. address 128.175.13.16
#        [Got answer in 0.013 s]

# ANSWER:
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
