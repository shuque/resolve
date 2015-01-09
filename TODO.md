## TODO List

* DNSSEC - support DNSSEC enabled queries and verification of RRSIGs
* Remember zone cuts, and depth of node traversal. This might help for
  some specific query names, to reduce repeated queries to the same zone. 
  This would be useful if this program did multiple queries. 
* Re-query NS rrset in child zone apex.
* Cache individual RRsets with TTL
* Implement a negative cache
* Option to turn this into a caching resolver daemon
