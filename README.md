# resolve.py

resolve.py  
A command line iterative DNS resolution testing program  
Author: Shumon Huque

A command line tool to perform iterative DNS resolution of a single
DNS name, type, and class. If either type or class or both are omitted, 
then a  default type of 'A' (IPv4 address record), and a default class 
of 'IN' (Internet class) are used.

Pre-requisites:  
- Python 3
- [dnspython module](http://www.dnspython.org/) (included with most Linux/*BSD distributions)

```
resolve.py version 0.15

Usage: resolve.py [-dmtsnxez] <qname> [<qtype>] [<qclass>]
       resolve.py [-dmtsnxez] -b <batchfile>

     -d: print debugging output
     -m: do qname minimization
     -t: use TCP only
     -v: verbose - trace query & zone path
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
     -e: don't use EDNS0 (default is EDNS0 with payload=1460)
     -z: set DNSSEC_OK flag (default is do not)
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

Here's the same lookup with the -v (verbose) switch to show the iterative
resolution path taken through the DNS hierarchy:

```
$ resolve.py -v www.seas.upenn.edu. AAAA

>> Query: www.seas.upenn.edu. AAAA IN at zone .
>>   Send to zone . at address 198.41.0.4
>>        [Got Referral to zone: edu.]
ZONE: edu.
edu. b.edu-servers.net. ['192.33.14.30', '2001:503:231d::2:30']
edu. f.edu-servers.net. ['192.35.51.30', '2001:503:d414::30']
edu. i.edu-servers.net. ['192.43.172.30', '2001:503:39c1::30']
edu. a.edu-servers.net. ['192.5.6.30', '2001:503:a83e::2:30']
edu. g.edu-servers.net. ['192.42.93.30', '2001:503:eea3::30']
edu. j.edu-servers.net. ['192.48.79.30', '2001:502:7094::30']
edu. k.edu-servers.net. ['192.52.178.30', '2001:503:d2d::30']
edu. m.edu-servers.net. ['192.55.83.30', '2001:501:b1f9::30']
edu. l.edu-servers.net. ['192.41.162.30', '2001:500:d937::30']
edu. h.edu-servers.net. ['192.54.112.30', '2001:502:8cc::30']
edu. c.edu-servers.net. ['192.26.92.30', '2001:503:83eb::30']
edu. e.edu-servers.net. ['192.12.94.30', '2001:502:1ca1::30']
edu. d.edu-servers.net. ['192.31.80.30', '2001:500:856e::30']

>> Query: www.seas.upenn.edu. AAAA IN at zone edu.
>>   Send to zone edu. at address 192.33.14.30
>>        [Got Referral to zone: upenn.edu.]
ZONE: upenn.edu.
upenn.edu. dns1.udel.edu. ['128.175.13.16']
upenn.edu. dns2.udel.edu. ['128.175.13.17']
upenn.edu. sns-pb.isc.org. []
upenn.edu. adns2.upenn.edu. ['128.91.254.22', '2607:f470:1002::2:3']
upenn.edu. adns1.upenn.edu. ['128.91.3.128', '2607:f470:1001::1:a']
upenn.edu. adns3.upenn.edu. ['128.91.251.33', '2607:f470:1003::3:c']

>> Query: www.seas.upenn.edu. AAAA IN at zone upenn.edu.
>>   Send to zone upenn.edu. at address 128.175.13.16

www.seas.upenn.edu. 120 IN AAAA 2607:f470:8:64:5ea5::9
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
$ resolve.py -vm www.seas.upenn.edu. A

>> Query: edu. A IN at zone .
>>   Send to zone . at address 198.41.0.4
>>        [Got Referral to zone: edu.]
ZONE: edu.
edu. b.edu-servers.net. ['192.33.14.30', '2001:503:231d::2:30']
edu. f.edu-servers.net. ['192.35.51.30', '2001:503:d414::30']
edu. i.edu-servers.net. ['192.43.172.30', '2001:503:39c1::30']
edu. a.edu-servers.net. ['192.5.6.30', '2001:503:a83e::2:30']
edu. g.edu-servers.net. ['192.42.93.30', '2001:503:eea3::30']
edu. j.edu-servers.net. ['192.48.79.30', '2001:502:7094::30']
edu. k.edu-servers.net. ['192.52.178.30', '2001:503:d2d::30']
edu. m.edu-servers.net. ['192.55.83.30', '2001:501:b1f9::30']
edu. l.edu-servers.net. ['192.41.162.30', '2001:500:d937::30']
edu. h.edu-servers.net. ['192.54.112.30', '2001:502:8cc::30']
edu. c.edu-servers.net. ['192.26.92.30', '2001:503:83eb::30']
edu. e.edu-servers.net. ['192.12.94.30', '2001:502:1ca1::30']
edu. d.edu-servers.net. ['192.31.80.30', '2001:500:856e::30']

>> Query: upenn.edu. A IN at zone edu.
>>   Send to zone edu. at address 192.33.14.30
>>        [Got Referral to zone: upenn.edu.]
ZONE: upenn.edu.
upenn.edu. dns1.udel.edu. ['128.175.13.16']
upenn.edu. dns2.udel.edu. ['128.175.13.17']
upenn.edu. sns-pb.isc.org. []
upenn.edu. adns2.upenn.edu. ['128.91.254.22', '2607:f470:1002::2:3']
upenn.edu. adns1.upenn.edu. ['128.91.3.128', '2607:f470:1001::1:a']
upenn.edu. adns3.upenn.edu. ['128.91.251.33', '2607:f470:1003::3:c']

>> Query: seas.upenn.edu. A IN at zone upenn.edu.
>>   Send to zone upenn.edu. at address 128.175.13.16

>> Query: www.seas.upenn.edu. A IN at zone upenn.edu.
>>   Send to zone upenn.edu. at address 128.175.13.16

www.seas.upenn.edu. 600 IN A 158.130.68.91
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
$ ./resolve.py -vm www.upenn.edu. A
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
$ ./resolve.py -vmx www.upenn.edu
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
$ ./resolve.py -vmx www.ietf.org
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
