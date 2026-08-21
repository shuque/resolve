# ML-DSA-44 support in resolve

Implementation notes for DNSSEC validation of **algorithm 18 (ML-DSA-44)**, the
post-quantum signature scheme, in the iterative resolver `resolve.py` /
`reslib/`. This is the validating-resolver counterpart to the signing-side work
in the companion `adns_server` project (key generation, offline/online signing,
and serving of live alg-18 zones); see `~/git/adns_server/MLDSA.md`.

## Specifications

- **draft-westerbaan-dnssec-mldsa** — "Algorithm for ML-DSA for DNSSEC". Assigns
  a single DNSSEC algorithm number to the smallest ML-DSA parameter set:
  **algorithm 18 = ML-DSA-44** (mnemonic `MLDSA44`), NIST security category 2.
  Only ML-DSA-44 is a DNSSEC algorithm; the larger ML-DSA-65 and ML-DSA-87
  parameter sets are *not* assigned DNSSEC codepoints and are not implemented.
- **FIPS 204** — Module-Lattice-Based Digital Signature Standard, the underlying
  primitive (the standardized form of Dilithium).

The DNSSEC profile uses **"pure" ML-DSA with an empty context** (not the
pre-hash HashML-DSA variant). The message signed is the ordinary
RFC 4034 §3.1.8.1 data-to-be-signed. DS is entirely standard: it is computed
over `owner-name-wire || DNSKEY-RDATA` with the chosen digest, with nothing
ML-DSA-specific about it.

## What ML-DSA-44 looks like on the wire

- **DNSKEY public key: 1312 octets** — the raw FIPS 204 public key, carried
  directly in the DNSKEY public-key field with no wrapper or prefix.
- **RRSIG signature: 2420 octets.** Because of this size, signed alg-18
  responses routinely exceed the UDP/EDNS budget and force **TCP fallback**
  (TC=1) — expect it on essentially every signed alg-18 answer. The resolver
  already retries over TCP on truncation, so this needs no special handling.
- **Signatures are hedged (randomized):** the same RRset signed twice yields two
  different, both-valid signatures. This never matters to a validator (you
  verify whatever signature arrived), but it means there is no fixed-vector
  RRSIG to compare against — verification is the only correctness check.
- **keytag and DS are algorithm-independent.** `dns.dnssec.key_id()` and
  `dns.dnssec.make_ds()` operate on the DNSKEY rdata opaquely and work unchanged
  for alg 18, so DS-matching up the chain needs no special case — only the RRSIG
  signature check does.

## The library situation

alg-18 support hinges on one external fact: **dnspython (2.7.0, the latest
version at the time of writing) does not implement algorithm 18** — though a
future version is expected to. `dns.dnssec.validate()` raises `UnsupportedAlgorithm`
for it and will not build the DNSKEY into a usable public-key object, so alg-18
validation cannot be routed through dnspython's validator. resolve.py already
builds its own RFC 4034 §3.1.8.1 signing input (see below), so this is a natural
fit — the only missing piece is the primitive itself.

The cryptographic primitive lives in the **`cryptography`** package,
`cryptography.hazmat.primitives.asymmetric.mldsa`, and requires a `cryptography`
build whose bundled OpenSSL includes ML-DSA — **50.0.0 or later is known good**.
Older `cryptography` lacks the `mldsa` module entirely. Because the PyPI binary
wheels statically bundle their own OpenSSL, the host OS and system OpenSSL are
irrelevant; the single requirement is `cryptography >= 50.0.0` installed via
`pip` into the venv (a distro `python3-cryptography`, built against system
OpenSSL, is the realistic trap — see `adns_server/MLDSA.md` for the full
analysis).

The dependency is therefore **optional and probed at runtime**, never a hard
import. resolve degrades gracefully on hosts without it (next section).

## The two behaviors

### 1. Degrade-to-insecure when alg 18 can't be verified

When a zone is signed solely with an algorithm the resolver cannot verify —
either genuinely unknown, or alg 18 on a host whose `cryptography` lacks ML-DSA —
the resolver treats the data as **insecure/unsigned**, returns the answer RRs,
and emits a diagnostic. This is standard DNSSEC behavior (RFC 4035 §5.2,
RFC 6840 §5.11): an unsupported DNSKEY algorithm is *not* a validation failure,
so the result is INSECURE, not BOGUS.

The decision is made from the **DS algorithm set at the secure entry point**, in
`supported_algorithm_present(zone.dslist)` (`reslib/lookup.py:1223`) — *before*
fetching the child DNSKEY or attempting any RRSIG verify, which is the cleanest
place for it. If no DS algorithm is verifiable, the resolver clears
`secure_so_far`, logs (verbose) `INFO: no supported DNSSEC algorithm (DS alg 18)
for zone <name>; treating as insecure`, and continues. A DS set with even one
supported algorithm still validates via the normal path.

This matches the reference behavior in the wild: the Cloudflare public resolver
(1.1.1.1) returns the answer for `mldsa.huque.com` with **AD absent** and
**EDE 1 (Unsupported DNSKEY Algorithm)**.

### 2. Full alg-18 verification (SECURE)

On a host with `cryptography >= 50.0.0`, `mldsa.available()` is true,
`algorithm_is_verifiable(18)` returns true, and the DS-algorithm gate above lets
resolution proceed into the child zone. The DNSKEY loads (its key field is the
raw 1312-octet FIPS 204 public key) and each alg-18 RRSIG is verified with the
ML-DSA primitive, so a correctly signed chain reaches **SECURE / AD**.

## How verification works in resolve

resolve does **not** use `dns.dnssec.validate()` for any algorithm — it builds
the RFC 4034 §3.1.8.1 data-to-be-signed itself. In `get_sig_info()`
(`reslib/dnssec.py`) it assembles the signing input (RRSIG RDATA through the
labels/TTL fields, the signer name, then the canonical RRset) and stores it on
each `Signature` object as `self.indata`. Alg-18 verification is then simply:

```python
mldsa.verify(pubkey, self.rdata.signature, self.indata)   # context=None
```

in `Signature.verify()` (`reslib/dnssec.py`), alongside the existing RSA / ECDSA
/ EdDSA branches. Because the signing input is already built, dnspython's
private `_make_rrsig_signature_data` is **not** needed on the resolve side (the
`adns_server` signer uses that helper; resolve does not).

Two important details:

- **`context=None` is mandatory.** It *is* the spec's empty context / "pure"
  ML-DSA mode. Any other context value fails verification against every
  conformant signature.
- **The 1312-octet DNSKEY field is the raw public key.** It is passed straight to
  `MLDSA44PublicKey.from_public_bytes()` with no decoding.

## The `reslib/mldsa.py` quarantine module

All contact with the optional `cryptography` ML-DSA surface is confined to one
small leaf module, `reslib/mldsa.py`, so the rest of the resolver never imports
`mldsa` at top level. It exposes three functions, each lazy-importing the
primitive inside the call:

| Function | Role |
|----------|------|
| `available()` | Cached capability probe: true iff `cryptography.hazmat.primitives.asymmetric.mldsa` imports and exposes `MLDSA44PublicKey`. Returns false (never raises) on any older `cryptography`. |
| `load_public_key(raw)` | `MLDSA44PublicKey.from_public_bytes(raw)` from the 1312-octet DNSKEY key field. |
| `verify(pubkey, signature, data)` | `pubkey.verify(signature, data, context=None)`; raises `InvalidSignature` on failure. |

This keeps the crypto dependency both optional (a host without ML-DSA loses
alg-18 verification but nothing else) and centralized (one place to adjust if
the `cryptography` API moves).

## Relevant functions and symbols

| Symbol | File | Role |
|--------|------|------|
| `available()` / `load_public_key()` / `verify()` | `mldsa.py` | The entire optional-dependency surface |
| `ALG[18] = "MLDSA44"` | `dnssec.py` | Algorithm-number mnemonic |
| `VERIFIABLE_ALGORITHMS` | `dnssec.py` | Statically verifiable algs (RSA/ECDSA/EdDSA); alg 18 is *not* in it |
| `algorithm_is_verifiable(algnum)` | `dnssec.py` | Alg 18 → `mldsa.available()` runtime probe; others → static set |
| `supported_algorithm_present(dslist)` | `dnssec.py` | Degrade-to-insecure decision from the DS algorithm set |
| `DNSKEY.__init__` alg-18 branch | `dnssec.py` | Load raw key if available; else mark unusable (`supported = False`) |
| `Signature.verify()` alg-18 branch | `dnssec.py` | `mldsa.verify(pubkey, sig, indata)` |
| `get_sig_info()` / `Signature.indata` | `dnssec.py` | Builds the RFC 4034 §3.1.8.1 signing input the verify consumes |
| DS-algorithm gate | `lookup.py:1223` | Where alg 18 degrades to insecure on an unsupported host |

## Interoperability and testing

- **Live test zone:** `mldsa.huque.com` — an online-signed alg-18 CSK zone
  served by `guvnor.huque.com`, with the matching DS published in the parent
  (`huque.com`). See the `mldsa-test-zone` project note.
- **Expected outcomes:** on a host without ML-DSA, `mldsa.huque.com` returns the
  answer marked **INSECURE** (behavior #1, matching Cloudflare 1.1.1.1); on a
  host with `cryptography >= 50.0.0`, the chain validates **SECURE** (behavior
  #2), assuming the `huque.com` DS is reachable from the trust anchor.
- The signer's own independent verify oracle — a second reference implementation
  of the verify path — lives in `~/git/adns_server/tests/pytest/`
  (`test_mldsa_online.py`, `test_mldsa_serving.py`).
</content>
</invoke>
