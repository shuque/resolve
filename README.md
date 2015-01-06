resolve
=======

resolve.py  
Command line iterative DNS resolution testing program  
Author: Shumon Huque

A command line tool to perform iterative DNS resolution of a single
DNS name, type, and class. If either type or class or both are omitted, 
then a  default type of 'A' (IPv4 address record), and a default class 
of 'IN' (Internet class) are used.

Pre-requisites:  
- Python 2.7 or later, or Python 3
- dnspython module

```
$ ./resolve.py

resolve.py version 0.11

Usage: resolve.py [-dmtsnx] <qname> [<qtype>] [<qclass>]
     -d: print debugging output
     -m: do qname minimization
     -t: trace query & zone path
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
```

This program implements the normal iterative DNS resolution algorithm 
described in the DNS protocol specifications.

With the -m switch, it uses a query name minimization algorithm that
exposes only the needed query labels to authoritative servers as it
traverses the DNS delegation hierarchy down to the target DNS zone. There
are a number of different ways a query name minimization algorithm could 
be implemented. I chose to implement the simplest one that starts with 
one non-root label at the root DNS servers, and successively prepends 
additional labels as it follows referrals and descends zones.

Here's an example run with qname minimization (-m) and the trace (-t)
option, to resolve the amazon.com website:

```
$ ./resolve.py -tm www.amazon.com
>> Query: com. A IN at zone .
>>        [Got Referral to zone: com.]
>> Query: amazon.com. A IN at zone com.
>>        [Got Referral to zone: amazon.com.]
>> Query: www.amazon.com. A IN at zone amazon.com.
>>        [Got Referral to zone: www.amazon.com.]
>> Query: www.amazon.com. A IN at zone www.amazon.com.
www.amazon.com. 60 IN A 176.32.98.166
```

