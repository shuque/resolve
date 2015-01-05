resolve
=======

resolve.py
Command line iterative DNS resolution testing program
Author: Shumon Huque

A command line tool to perform iterative DNS resolution of a single
DNS name, type, and class.

```
$ ./resolve.py

resolve.py version 0.10

Usage: resolve.py [-dmtsnx] <qname> [<qtype>] [<qclass>]
     -d: print debugging output
     -m: do qname minimization
     -t: trace query & zone path
     -s: print summary statistics
     -n: resolve all non-glue NS addresses in referrals
     -x: workaround NXDOMAIN on empty non-terminals
```
