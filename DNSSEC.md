# resolve.py DNSSEC examples

Invoking the prorgram with -z turns on DNSSEC validation. In this mode,
it shows the DNSSEC status of the response (SECURE or INSECURE). Additionally,
with the -v switch, the program shows the full iterative trace annotated
with DNSSEC validation related information, such as DS and DNSKEY RRset
information, and whether the referrals encountered were secure or not. For
negative answers, the NSEC/NSEC3 set is shown, and for NSEC3 the computed
closest encloser, next closer, and wildcard at closest encloser and their
hashes are shown, to make it easy to visually inspect the proof of non
existence. The program intentionally doesn't show the actual RRSIG records
or the DNSKEY key material, as that is mostly unintelligible to (normal)
human beings, although I might in a future version, optionally show this
information at a greater verbosity level.

With just -z:

```
$ resolve.py -z www.upenn.edu. A
# ANSWER to QUERY: www.upenn.edu. A IN
# RCODE: NOERROR
# DNSSEC status: SECURE
www.upenn.edu. 300 IN A 151.101.2.217
www.upenn.edu. 300 IN A 151.101.66.217
www.upenn.edu. 300 IN A 151.101.130.217
www.upenn.edu. 300 IN A 151.101.194.217
```


An insecure name (i.e., the name resolves fine, but is not DNSSEC signed, so
cannot be authenticated):

```
$ resolve.py -z google.com. A
# ANSWER to QUERY: google.com. A IN
# RCODE: NOERROR
# DNSSEC status: INSECURE
google.com. 300 IN A 142.250.64.78
```


Adding -v, shows the full iterative trace:

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
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE

# QUERY: www.upenn.edu. A IN at zone . address 192.5.5.241
#        [SECURE Referral to zone: edu. in 0.014 s]
ZONE: edu.
TTL: Delegation: 172800, Signer: 86400
NS: l.edu-servers.net. 192.41.162.30 2001:500:d937::30
NS: b.edu-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.edu-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.edu-servers.net. 192.31.80.30 2001:500:856e::30
NS: e.edu-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: f.edu-servers.net. 192.35.51.30 2001:503:d414::30
NS: g.edu-servers.net. 192.42.93.30 2001:503:eea3::30
NS: a.edu-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: h.edu-servers.net. 192.54.112.30 2001:502:8cc::30
NS: i.edu-servers.net. 192.43.172.30 2001:503:39c1::30
NS: j.edu-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.edu-servers.net. 192.52.178.30 2001:503:d2d::30
NS: m.edu-servers.net. 192.55.83.30 2001:501:b1f9::30
DS: 28065 8 2 4172496cde85534e51129040355bd04b1fcfebae996dfdde652006f6f8b2ce76
DNSKEY: edu. 257 28065 RSASHA256 (8) 2048-bits ZONE SEP
DNSKEY: edu. 256 8663 RSASHA256 (8) 1280-bits ZONE

# QUERY: www.upenn.edu. A IN at zone edu. address 2001:503:eea3::30
#        [SECURE Referral to zone: upenn.edu. in 0.042 s]
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
# SECURE: www.upenn.edu. 300 IN A 151.101.2.217
# SECURE: www.upenn.edu. 300 IN A 151.101.194.217
# SECURE: www.upenn.edu. 300 IN A 151.101.66.217

# ANSWER to QUERY: www.upenn.edu. A IN
# RCODE: NOERROR
# DNSSEC status: SECURE
www.upenn.edu. 300 IN A 151.101.130.217
www.upenn.edu. 300 IN A 151.101.2.217
www.upenn.edu. 300 IN A 151.101.194.217
www.upenn.edu. 300 IN A 151.101.66.217
```


A response that results in a validation failure, like the example below,
will print an appropriate error message. In this case, the failure is due
to an incorrect DS record in the parent zone, that does not match the DNSKEY
RRset in the zone containing the answer.

```
$ resolve.py -vz dnssec-failed.org

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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE

# QUERY: dnssec-failed.org. A IN at zone . address 2001:7fd::1
#        [SECURE Referral to zone: org. in 0.046 s]
ZONE: org.
TTL: Delegation: 172800, Signer: 86400
NS: b0.org.afilias-nst.org. 2001:500:c::1 199.19.54.1
NS: d0.org.afilias-nst.org. 2001:500:f::1 199.19.57.1
NS: a0.org.afilias-nst.info. 2001:500:e::1 199.19.56.1
NS: a2.org.afilias-nst.info. 2001:500:40::1 199.249.112.1
NS: c0.org.afilias-nst.info. 2001:500:b::1 199.19.53.1
NS: b2.org.afilias-nst.org. 2001:500:48::1 199.249.120.1
DS: 17883 7 1 38c5cf93b369c7557e0515faaa57060f1bfb12c1
DS: 17883 7 2 d889cad790f01979e860d6627b58f85ab554e0e491fe06515f35548d1eb4e6ee
DNSKEY: org. 256 27353 NSEC3-RSASHA1 (7) 1024-bits ZONE
DNSKEY: org. 257 17883 NSEC3-RSASHA1 (7) 2048-bits ZONE SEP
DNSKEY: org. 256 62165 NSEC3-RSASHA1 (7) 1024-bits ZONE

# QUERY: dnssec-failed.org. A IN at zone org. address 199.249.112.1
#        [SECURE Referral to zone: dnssec-failed.org. in 0.016 s]
ZONE: dnssec-failed.org.
TTL: Delegation: 86400, Signer: 86400
NS: dns101.comcast.net. 2001:558:fe23:8:69:252:250:103 69.252.250.103
NS: dns102.comcast.net. 2001:558:1004:7:68:87:85:132 68.87.85.132
NS: dns103.comcast.net. 2001:558:1014:c:68:87:76:228 68.87.76.228
NS: dns104.comcast.net. 2001:558:100a:5:68:87:68:244 68.87.68.244
NS: dns105.comcast.net. 2001:558:100e:5:68:87:72:244 68.87.72.244
DS: 106 5 1 4f219dce274f820ea81ea1150638dabe21eb27fc
DS: 106 5 2 ae3424c9b171af3b202203767e5703426130d76ef6847175f2eed355f86ef1ce
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 2001:558:100a:5:68:87:68:244
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 2001:558:1004:7:68:87:85:132
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 2001:558:1014:c:68:87:76:228
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 68.87.72.244
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 68.87.76.228
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 2001:558:100e:5:68:87:72:244
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 68.87.85.132
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 68.87.68.244
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 69.252.250.103
ERROR: DS did not match DNSKEY: dnssec-failed.org. at 2001:558:fe23:8:69:252:250:103

DNSKEY: dnssec-failed.org. 257 29521 RSASHA1 (5) 2048-bits ZONE SEP
DNSKEY: dnssec-failed.org. 256 44973 RSASHA1 (5) 1024-bits ZONE

ERROR: DS did not match DNSKEY for dnssec-failed.org.
```

Querying a record with an invalid signature. Here we retry all available
authoritative servers for the zone, looking for a valid signature, before
giving up with an error.

```
$ resolve.py -vz bogus.d2a15n3.rootcanary.net. A

ZONE: .
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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits

# QUERY: bogus.d2a15n3.rootcanary.net. A IN at zone . address 198.41.0.4
#        [SECURE Referral to zone: net. in 0.013 s]
ZONE: net.
NS: a.gtld-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: b.gtld-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.gtld-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.gtld-servers.net. 192.31.80.30 2001:500:856e::30
NS: e.gtld-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: f.gtld-servers.net. 192.35.51.30 2001:503:d414::30
NS: g.gtld-servers.net. 192.42.93.30 2001:503:eea3::30
NS: h.gtld-servers.net. 192.54.112.30 2001:502:8cc::30
NS: i.gtld-servers.net. 192.43.172.30 2001:503:39c1::30
NS: j.gtld-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.gtld-servers.net. 192.52.178.30 2001:503:d2d::30
NS: l.gtld-servers.net. 192.41.162.30 2001:500:d937::30
NS: m.gtld-servers.net. 192.55.83.30 2001:501:b1f9::30
DS: 35886 8 2 7862b27f5f516ebe19680444d4ce5e762981931842c465f00236401d8bd973ee
DNSKEY: net. 257 35886 RSASHA256 (8) 2048-bits
DNSKEY: net. 256 36059 RSASHA256 (8) 1280-bits

# QUERY: bogus.d2a15n3.rootcanary.net. A IN at zone net. address 192.5.6.30
#        [SECURE Referral to zone: rootcanary.net. in 0.078 s]
ZONE: rootcanary.net.
NS: ns1.surfnet.nl.
NS: ns2.surfnet.nl.
NS: ns3.surfnet.nl.
NS: ns1.zurich.surf.net. 195.176.255.9 2001:620:0:9::1103
DS: 64786 8 2 5cd8f125f5487708121a497bd0b1079406add42002b3c195ee0669d2aeb763c9
DNSKEY: rootcanary.net. 256 25188 RSASHA256 (8) 1024-bits
DNSKEY: rootcanary.net. 257 64786 RSASHA256 (8) 1024-bits

# QUERY: bogus.d2a15n3.rootcanary.net. A IN at zone rootcanary.net. address 195.176.255.9
#        [Got answer in 0.102 s]
# FETCH: NS/DS/DNSKEY for d2a15n3.rootcanary.net.
WARNING: 195.176.255.9 error Validation fail: bogus.d2a15n3.rootcanary.net. 60 IN A 145.97.20.17, keys=[(DNSKEY: d2a15n3.rootcanary.net. 257 50165 ED25519 (15) 256-bits, BadSignatureError('Signature was forged or corrupt',))]

# QUERY: bogus.d2a15n3.rootcanary.net. A IN at zone rootcanary.net. address 2001:620:0:9::1103
#        [Got answer in 0.510 s]
WARNING: 2001:620:0:9::1103 error Validation fail: bogus.d2a15n3.rootcanary.net. 60 IN A 145.97.20.17, keys=[(DNSKEY: d2a15n3.rootcanary.net. 257 50165 ED25519 (15) 256-bits, BadSignatureError('Signature was forged or corrupt',))]

ERROR: Queries to all servers for zone rootcanary.net. failed.
```

The following example shows a NODATA response that has been authenticated:

```
$ resolve.py -z www.huque.com. TLSA
ERROR: NODATA: cheetara.huque.com. of type TLSA not found
# ANSWER to QUERY: www.huque.com. TLSA IN
# RCODE: NOERROR (NODATA)
# DNSSEC status: SECURE
www.huque.com. 300 IN CNAME cheetara.huque.com.
```

To see more details of how we got to that previous authenticated NODATA
response, including the relevant NSEC/NSEC3 type bitmap, supply the -v
switch too:

```
$ resolve.py -vz www.huque.com. TLSA

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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: www.huque.com. TLSA IN at zone . address 199.7.83.42
#        [SECURE Referral to zone: com. in 0.020 s]
ZONE: com.
TTL: Delegation: 172800, Signer: 86400
NS: a.gtld-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: b.gtld-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.gtld-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.gtld-servers.net. 192.31.80.30 2001:500:856e::30
NS: e.gtld-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: f.gtld-servers.net. 192.35.51.30 2001:503:d414::30
NS: g.gtld-servers.net. 192.42.93.30 2001:503:eea3::30
NS: h.gtld-servers.net. 192.54.112.30 2001:502:8cc::30
NS: i.gtld-servers.net. 192.43.172.30 2001:503:39c1::30
NS: j.gtld-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.gtld-servers.net. 192.52.178.30 2001:503:d2d::30
NS: l.gtld-servers.net. 192.41.162.30 2001:500:d937::30
NS: m.gtld-servers.net. 192.55.83.30 2001:501:b1f9::30
DS: 30909 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766
DNSKEY: com. 256 39844 RSASHA256 (8) 1280-bits ZONE
DNSKEY: com. 257 30909 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: www.huque.com. TLSA IN at zone com. address 2001:500:d937::30
#        [SECURE Referral to zone: huque.com. in 0.003 s]
ZONE: huque.com.
TTL: Delegation: 172800, Signer: 86400
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
DS: 61352 13 2 466df2e888988bca2c5388adfb19cb8f29d93edbd6d5b0717b9f770aaf190489
DNSKEY: huque.com. 257 61352 ECDSA-P256 (13) 512-bits ZONE SEP
DNSKEY: huque.com. 256 4682 ECDSA-P256 (13) 512-bits ZONE

# QUERY: www.huque.com. TLSA IN at zone huque.com. address 128.91.254.22
#        [Got answer in 0.015 s]
# SECURE: www.huque.com. 300 IN CNAME cheetara.huque.com.
www.huque.com. 300 IN CNAME cheetara.huque.com.

# QUERY: cheetara.huque.com. TLSA IN at zone huque.com. address 2607:f470:1001::1:a
#        [Got answer in 0.008 s]
ERROR: NODATA: cheetara.huque.com. of type TLSA not found
# SECURE: huque.com. 3600 IN SOA mname.huque.com. hostmaster.huque.com. 1000015128 43200 3600 3628800 3600
# SECURE: 33Q996NVAUKA6LERAAPRR2TTBPO5G2MG.huque.com. 3600 IN NSEC3 1 0 5 9eba4228 37nvtrv4kghasplvv0039bt7ep026aag A TXT AAAA SSHFP RRSIG
# INFO: H(cheetara.huque.com.) = 33Q996NVAUKA6LERAAPRR2TTBPO5G2MG.huque.com.

# ANSWER to QUERY: www.huque.com. TLSA IN
# RCODE: NOERROR (NODATA)
# DNSSEC status: SECURE
www.huque.com. 300 IN CNAME cheetara.huque.com.
```

The following example queries a record with an (intentionally) expired
DNSSEC signature. The program retried the query against all authoritative
servers and then gave up with an error:

```
$ resolve.py -z _443._tcp.expiredsig.busted.huque.com. TLSA

WARNING: 162.159.27.72 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 162.159.25.129 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 2400:cb00:2049:1::a29f:1981 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 162.159.24.25 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 2400:cb00:2049:1::a29f:1819 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 162.159.26.99 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 2400:cb00:2049:1::a29f:1b48 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 162.159.24.39 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 2400:cb00:2049:1::a29f:1827 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]
WARNING: 2400:cb00:2049:1::a29f:1a63 error Validation fail: _443._tcp.expiredsig.busted.huque.com./TLSA, keys=[(DNSKEY: busted.huque.com. 256 7101 RSASHA256 (8) 1024-bits, ResError('Signature has expired',))]

ERROR: Queries to all servers for zone busted.huque.com. failed.
```

Example of an NSEC Authenticated NXDOMAIN response:

```
$ resolve.py -vz www7.blah.ietf.org. A

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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: www7.blah.ietf.org. A IN at zone . address 192.36.148.17
#        [SECURE Referral to zone: org. in 0.020 s]
ZONE: org.
TTL: Delegation: 172800, Signer: 86400
NS: a0.org.afilias-nst.info. 199.19.56.1 2001:500:e::1
NS: c0.org.afilias-nst.info. 199.19.53.1 2001:500:b::1
NS: b0.org.afilias-nst.org. 199.19.54.1 2001:500:c::1
NS: a2.org.afilias-nst.info. 199.249.112.1 2001:500:40::1
NS: b2.org.afilias-nst.org. 199.249.120.1 2001:500:48::1
NS: d0.org.afilias-nst.org. 199.19.57.1 2001:500:f::1
DS: 17883 7 2 d889cad790f01979e860d6627b58f85ab554e0e491fe06515f35548d1eb4e6ee
DS: 17883 7 1 38c5cf93b369c7557e0515faaa57060f1bfb12c1
DNSKEY: org. 256 62165 NSEC3-RSASHA1 (7) 1024-bits ZONE
DNSKEY: org. 256 27353 NSEC3-RSASHA1 (7) 1024-bits ZONE
DNSKEY: org. 257 17883 NSEC3-RSASHA1 (7) 2048-bits ZONE SEP

# QUERY: www7.blah.ietf.org. A IN at zone org. address 199.19.56.1
#        [SECURE Referral to zone: ietf.org. in 0.004 s]
WARN: response from 2001:500:19::1 was truncated; retrying with TCP
ZONE: ietf.org.
TTL: Delegation: 86400, Signer: 86400
NS: ns1.sea1.afilias-nst.info. 65.22.8.1 2a01:8840:8::1
NS: ns0.amsl.com. 2001:1900:3001:11::28 4.31.198.40
NS: ns1.ams1.afilias-nst.info. 65.22.6.79
NS: ns1.mia1.afilias-nst.info. 65.22.7.1 2a01:8840:7::1
NS: ns1.yyz1.afilias-nst.info. 65.22.9.1 2a01:8840:9::1
NS: ns1.hkg1.afilias-nst.info. 65.22.6.1 2a01:8840:6::1
DS: 45586 5 1 d0fdf996d1af2ccdbdc942b02cb02d379629e20b
DS: 45586 5 2 67fcd7e0b9e0366309f3b6f7476dff931d5226edc5348cd80fd82a081dfcf6ee
DNSKEY: ietf.org. 256 40452 RSASHA1 (5) 2048-bits ZONE
DNSKEY: ietf.org. 257 45586 RSASHA1 (5) 2048-bits ZONE SEP

# QUERY: www7.blah.ietf.org. A IN at zone ietf.org. address 65.22.9.1
#        [Got answer in 0.007 s]
ERROR: NXDOMAIN: www7.blah.ietf.org. not found
# SECURE: ietf.org. 1800 IN SOA ns0.amsl.com. glen.amsl.com. 1200000472 1800 1800 604800 1800
# SECURE: ietf.org. 1800 IN NSEC _dmarc.ietf.org. A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY SPF
# SECURE: beta.ietf.org. 1800 IN NSEC codimd.ietf.org. CNAME RRSIG NSEC

# ANSWER to QUERY: www7.blah.ietf.org. A IN
# RCODE: NXDOMAIN
# DNSSEC status: SECURE
```

An NXDOMAIN response from an NSEC3 signed zone follows. With -v, the program
additionally prints the NSEC3 records and the computed hash values for the
closest encloser, next closer name, and wildcard at closest encloser names.
This makes it easier to visually inspect the proof against the NSEC3 records,
if desired.

```
$ resolve.py -vz foo.bar.www.huque.com

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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: foo.bar.www.huque.com. A IN at zone . address 2001:503:c27::2:30
#        [SECURE Referral to zone: com. in 0.016 s]
ZONE: com.
TTL: Delegation: 172800, Signer: 86400
NS: a.gtld-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: b.gtld-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.gtld-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.gtld-servers.net. 192.31.80.30 2001:500:856e::30
NS: e.gtld-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: f.gtld-servers.net. 192.35.51.30 2001:503:d414::30
NS: g.gtld-servers.net. 192.42.93.30 2001:503:eea3::30
NS: h.gtld-servers.net. 192.54.112.30 2001:502:8cc::30
NS: i.gtld-servers.net. 192.43.172.30 2001:503:39c1::30
NS: j.gtld-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.gtld-servers.net. 192.52.178.30 2001:503:d2d::30
NS: l.gtld-servers.net. 192.41.162.30 2001:500:d937::30
NS: m.gtld-servers.net. 192.55.83.30 2001:501:b1f9::30
DS: 30909 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766
DNSKEY: com. 256 39844 RSASHA256 (8) 1280-bits ZONE
DNSKEY: com. 257 30909 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: foo.bar.www.huque.com. A IN at zone com. address 2001:503:d2d::30
#        [SECURE Referral to zone: huque.com. in 0.003 s]
ZONE: huque.com.
TTL: Delegation: 172800, Signer: 86400
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
DS: 61352 13 2 466df2e888988bca2c5388adfb19cb8f29d93edbd6d5b0717b9f770aaf190489
DNSKEY: huque.com. 256 4682 ECDSA-P256 (13) 512-bits ZONE
DNSKEY: huque.com. 257 61352 ECDSA-P256 (13) 512-bits ZONE SEP

# QUERY: foo.bar.www.huque.com. A IN at zone huque.com. address 2607:f470:1003::3:c
#        [Got answer in 0.021 s]
ERROR: NXDOMAIN: foo.bar.www.huque.com. not found
# SECURE: huque.com. 3600 IN SOA mname.huque.com. hostmaster.huque.com. 1000015128 43200 3600 3628800 3600
# SECURE: BHC26OBVA5IVSSUNCIM9IBSKP9LDHTF3.huque.com. 3600 IN NSEC3 1 0 5 9eba4228 bliqgpljj9u1ls10e24o7admh19jt83d CNAME RRSIG
# SECURE: I6F6LIVI2B99V5KSG7JEE4UNIGAHFQDE.huque.com. 3600 IN NSEC3 1 0 5 9eba4228 ib131cn8g5grn6h660pcldgvqg64peud
# SECURE: 8A4IH6GUN04T65I6UNBN3CJ43VNONT2P.huque.com. 3600 IN NSEC3 1 0 5 9eba4228 8soph4cq7137p93bnsuna23rmqn3e8ec
# INFO: closest encloser: www.huque.com. BHC26OBVA5IVSSUNCIM9IBSKP9LDHTF3
# INFO: next closer: bar.www.huque.com. IAPTN5EOPL2CA48BOVVPQQV7RDVHGEQB
# INFO: wildcard: *.www.huque.com. 8D3IP64KO9RESL73HP4DMUPS7SNORBT1

# ANSWER to QUERY: foo.bar.www.huque.com. A IN
# RCODE: NXDOMAIN
# DNSSEC status: SECURE
```

Wildcard synthesized responses are correctly validated (including proof of
no closer match), and the program reports the wildcard name that matched.

```
$ resolve.py -vz foo.bar.wild.huque.com.

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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: foo.bar.wild.huque.com. A IN at zone . address 2001:500:2d::d
#        [SECURE Referral to zone: com. in 0.022 s]
ZONE: com.
TTL: Delegation: 172800, Signer: 86400
NS: a.gtld-servers.net. 2001:503:a83e::2:30 192.5.6.30
NS: b.gtld-servers.net. 2001:503:231d::2:30 192.33.14.30
NS: c.gtld-servers.net. 2001:503:83eb::30 192.26.92.30
NS: d.gtld-servers.net. 2001:500:856e::30 192.31.80.30
NS: e.gtld-servers.net. 2001:502:1ca1::30 192.12.94.30
NS: f.gtld-servers.net. 2001:503:d414::30 192.35.51.30
NS: g.gtld-servers.net. 2001:503:eea3::30 192.42.93.30
NS: h.gtld-servers.net. 2001:502:8cc::30 192.54.112.30
NS: i.gtld-servers.net. 2001:503:39c1::30 192.43.172.30
NS: j.gtld-servers.net. 2001:502:7094::30 192.48.79.30
NS: k.gtld-servers.net. 2001:503:d2d::30 192.52.178.30
NS: l.gtld-servers.net. 2001:500:d937::30 192.41.162.30
NS: m.gtld-servers.net. 2001:501:b1f9::30 192.55.83.30
DS: 30909 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766
DNSKEY: com. 256 39844 RSASHA256 (8) 1280-bits ZONE
DNSKEY: com. 257 30909 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: foo.bar.wild.huque.com. A IN at zone com. address 2001:503:83eb::30
#        [SECURE Referral to zone: huque.com. in 0.009 s]
ZONE: huque.com.
TTL: Delegation: 172800, Signer: 86400
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
DS: 61352 13 2 466df2e888988bca2c5388adfb19cb8f29d93edbd6d5b0717b9f770aaf190489
DNSKEY: huque.com. 256 4682 ECDSA-P256 (13) 512-bits ZONE
DNSKEY: huque.com. 257 61352 ECDSA-P256 (13) 512-bits ZONE SEP

# QUERY: foo.bar.wild.huque.com. A IN at zone huque.com. address 2607:f470:1002::2:3
#        [Got answer in 0.017 s]
# INFO: Wildcard match: *.wild.huque.com.
# INFO next closer: bar.wild.huque.com. ANV14RHJQQAUF559EUEIJ1UTSL90OH2O
# INFO: NSEC3: AG7BTFID7V5PHS4RHVU6GKGBD12JRKL1.huque.com. 3600 IN NSEC3 1 0 5 9eba4228 aslt6fvrnnd5ptempr26d15u8m4alpda CNAME RRSIG
# SECURE: foo.bar.wild.huque.com. 600 IN A 127.0.99.1

# ANSWER to QUERY: foo.bar.wild.huque.com. A IN
# RCODE: NOERROR
# DNSSEC status: SECURE
# WILDCARD match: *.wild.huque.com.
foo.bar.wild.huque.com. 600 IN A 127.0.99.1
```

An opt-out insecure referral to amazon.com from com:

```
$ resolve.py -vz amazon.com.

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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: amazon.com. A IN at zone . address 2001:dc3::35
#        [SECURE Referral to zone: com. in 0.078 s]
ZONE: com.
TTL: Delegation: 172800, Signer: 86400
NS: k.gtld-servers.net. 192.52.178.30 2001:503:d2d::30
NS: b.gtld-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.gtld-servers.net. 192.26.92.30 2001:503:83eb::30
NS: l.gtld-servers.net. 192.41.162.30 2001:500:d937::30
NS: i.gtld-servers.net. 192.43.172.30 2001:503:39c1::30
NS: m.gtld-servers.net. 192.55.83.30 2001:501:b1f9::30
NS: h.gtld-servers.net. 192.54.112.30 2001:502:8cc::30
NS: j.gtld-servers.net. 192.48.79.30 2001:502:7094::30
NS: a.gtld-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: g.gtld-servers.net. 192.42.93.30 2001:503:eea3::30
NS: f.gtld-servers.net. 192.35.51.30 2001:503:d414::30
NS: e.gtld-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: d.gtld-servers.net. 192.31.80.30 2001:500:856e::30
DS: 30909 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766
DNSKEY: com. 256 39844 RSASHA256 (8) 1280-bits ZONE
DNSKEY: com. 257 30909 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: amazon.com. A IN at zone com. address 192.41.162.30
# SECURE: CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 86400 IN NSEC3 1 1 0 - ck0q1gin43n1arrc9osm6qpqr81h5m9a NS SOA RRSIG DNSKEY NSEC3PARAM
# SECURE: K200TO4JESGR0FQHPJ8VS4JH890ITN4T.com. 86400 IN NSEC3 1 1 0 - k201dagiualssfgadn4dhe7n9q0iroj1 NS DS RRSIG
# INFO: closest provable encloser: com. CK0POJMG874LJREF7EFN8430QVIT8BSM
# INFO: next closer: amazon.com. K201BQSV52HID9F4GFEU8D70JL1218CH
# INFO: NSEC3 opt-out insecure referral
#        [INSECURE Referral to zone: amazon.com. in 0.010 s]
ZONE: amazon.com.
TTL: Delegation: 172800
NS: pdns1.ultradns.net. 204.74.108.1 2001:502:f3ff::1
NS: pdns6.ultradns.co.uk. 204.74.115.1 2610:a1:1017::1
NS: ns1.p31.dynect.net. 208.78.70.31 2001:500:90:1::31
NS: ns3.p31.dynect.net. 208.78.71.31 2001:500:94:1::31
NS: ns2.p31.dynect.net. 204.13.250.31
NS: ns4.p31.dynect.net. 204.13.251.31

# QUERY: amazon.com. A IN at zone amazon.com. address 208.78.71.31
#        [Got answer in 0.005 s]

# ANSWER to QUERY: amazon.com. A IN
# RCODE: NOERROR
# DNSSEC status: INSECURE
amazon.com. 60 IN A 176.32.103.205
amazon.com. 60 IN A 176.32.98.166
amazon.com. 60 IN A 205.251.242.103
```

An NSEC3 empty non-terminal NODATA response:

```
$ resolve.py -vz ent.huque.com
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
DNSKEY: . 256 48903 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 256 46594 RSASHA256 (8) 2048-bits ZONE
DNSKEY: . 257 20326 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: ent.huque.com. A IN at zone . address 199.7.91.13
#        [SECURE Referral to zone: com. in 0.023 s]
ZONE: com.
TTL: Delegation: 172800, Signer: 86400
NS: a.gtld-servers.net. 192.5.6.30 2001:503:a83e::2:30
NS: b.gtld-servers.net. 192.33.14.30 2001:503:231d::2:30
NS: c.gtld-servers.net. 192.26.92.30 2001:503:83eb::30
NS: d.gtld-servers.net. 192.31.80.30 2001:500:856e::30
NS: e.gtld-servers.net. 192.12.94.30 2001:502:1ca1::30
NS: f.gtld-servers.net. 192.35.51.30 2001:503:d414::30
NS: g.gtld-servers.net. 192.42.93.30 2001:503:eea3::30
NS: h.gtld-servers.net. 192.54.112.30 2001:502:8cc::30
NS: i.gtld-servers.net. 192.43.172.30 2001:503:39c1::30
NS: j.gtld-servers.net. 192.48.79.30 2001:502:7094::30
NS: k.gtld-servers.net. 192.52.178.30 2001:503:d2d::30
NS: l.gtld-servers.net. 192.41.162.30 2001:500:d937::30
NS: m.gtld-servers.net. 192.55.83.30 2001:501:b1f9::30
DS: 30909 8 2 e2d3c916f6deeac73294e8268fb5885044a833fc5459588f4a9184cfc41a5766
DNSKEY: com. 256 39844 RSASHA256 (8) 1280-bits ZONE
DNSKEY: com. 257 30909 RSASHA256 (8) 2048-bits ZONE SEP

# QUERY: ent.huque.com. A IN at zone com. address 192.31.80.30
#        [SECURE Referral to zone: huque.com. in 0.008 s]
ZONE: huque.com.
TTL: Delegation: 172800, Signer: 86400
NS: adns2.upenn.edu. 128.91.254.22 2607:f470:1002::2:3
NS: adns1.upenn.edu. 128.91.3.128 2607:f470:1001::1:a
NS: adns3.upenn.edu. 128.91.251.33 2607:f470:1003::3:c
DS: 61352 13 2 466df2e888988bca2c5388adfb19cb8f29d93edbd6d5b0717b9f770aaf190489
DNSKEY: huque.com. 257 61352 ECDSA-P256 (13) 512-bits ZONE SEP
DNSKEY: huque.com. 256 4682 ECDSA-P256 (13) 512-bits ZONE

# QUERY: ent.huque.com. A IN at zone huque.com. address 128.91.254.22
#        [Got answer in 0.019 s]
ERROR: NODATA: ent.huque.com. of type A not found
# SECURE: huque.com. 3600 IN SOA mname.huque.com. hostmaster.huque.com. 1000015128 43200 3600 3628800 3600
# SECURE: JKMTK1KEBTJK445C6RI85U840L92QKJ1.huque.com. 3600 IN NSEC3 1 0 5 9eba4228 jmf9echsc75o5td1u9a5hghnh6uehhn3
# INFO: Empty Non-Terminal found
# INFO: H(ent.huque.com.) = JKMTK1KEBTJK445C6RI85U840L92QKJ1.huque.com.

# ANSWER to QUERY: ent.huque.com. A IN
# RCODE: NOERROR (NODATA)
# DNSSEC status: SECURE
# EMPTY NON-TERMINAL detected
```
