# ML-DSA-44 (DNSSEC algorithm 18) — notes for the validating resolver

Portable reference for adding **ML-DSA-44** (DNSSEC algorithm 18) validation
support to `resolve.py`. Written from the signing side of the work (the
`adns_server` project, `~/git/adns_server`), which already generates keys,
signs zones (offline and online), and serves live alg-18 zones. This doc is the
mirror image of that: what a *validator* must do, and the exact recipe that the
signer's own test oracle uses to verify alg-18 RRSIGs.

> **Provenance.** Cross-project reference distilled 2026-08-16 from
> `adns_server`. The authoritative signing-side write-up is
> `~/git/adns_server/Design.md` §11; the spec is
> draft-westerbaan-dnssec-mldsa (copy committed in `adns_server/specs/`, and
> recommended to copy into this repo's tree too). Verify any code detail below
> against the current libraries before relying on it — library APIs move.

## What ML-DSA-44 is

- DNSSEC **algorithm number 18**, the post-quantum signature scheme of FIPS 204
  (ML-DSA, the standardized form of Dilithium). Tracking
  **draft-westerbaan-dnssec-mldsa**.
- Only **ML-DSA-44** is defined for DNSSEC. The larger parameter sets (ML-DSA-65
  = 65, ML-DSA-87 = 87) are *not* DNSSEC algorithms — do not implement them.
- **Sizes (memorize these — they drive both parsing and transport):**
  - DNSKEY public key: **1312 octets** (the raw FIPS 204 public key).
  - RRSIG signature: **2420 octets**.
  - Because of the signature size, alg-18 responses routinely exceed the UDP/
    EDNS budget and force **TCP fallback** (TC=1). A validator that talks
    directly to auth servers must already handle TCP retry — but expect to hit
    it on essentially every signed alg-18 answer. (This is exactly why the live
    test target below returns over TCP.)
- **Signatures are hedged (randomized).** The same RRset signed twice yields two
  different, both-valid signatures. This never matters to a *validator* (you
  verify whatever signature arrived), but it means there is no fixed-vector RRSIG
  to compare against — verification is the only correctness check.

## The library situation (this is the crux)

- **dnspython (through 2.7.0) does NOT implement algorithm 18.**
  `dns.dnssec.validate()` raises `UnsupportedAlgorithm` for it, and dnspython
  will not build the DNSKEY into a usable public key object either. So you
  **cannot** route alg-18 validation through `dns.dnssec.validate()`.
- The cryptographic primitive lives in the **`cryptography`** package:
  `cryptography.hazmat.primitives.asymmetric.mldsa`. It requires a
  `cryptography` build whose bundled OpenSSL has ML-DSA — **50.0.0 or later is
  known good**. Older `cryptography` will not have the `mldsa` module at all.
- **Import it lazily**, inside the alg-18 code path, never at module top level.
  A top-level `from ...asymmetric import mldsa` will `ImportError` on any host
  with an older `cryptography` and break validation of *all* other algorithms.
  Guard/skip gracefully when it's absent.

## The two behaviors a validator needs

### 1. Unknown-algorithm graceful degradation (the current bug)

`resolve.py -vz mldsa.huque.com. SOA` currently errors out at the end instead of
returning the answer records. **Correct behavior:** when a zone is signed solely
with an algorithm the resolver cannot verify, the resolver must treat the data
as **Insecure / Indeterminate — unverifiable but still answerable**, return the
answer RRs, and emit a diagnostic noting the unrecognized algorithm. It must
*not* fail the whole resolution.

This is standard DNSSEC behavior for unsupported algorithms (an unsupported
DNSKEY algorithm is not a validation *failure* → not Bogus; the name is treated
as unsigned/insecure for that resolver). Reference behavior in the wild: the
**Cloudflare public resolver (1.1.1.1)** does exactly this for
`mldsa.huque.com` — returns the answer with **AD absent** and attaches
**EDE 1 (Unsupported DNSKEY Algorithm)**. That's the target behavior to match.

Fixing this is the natural first task and does **not** require any ML-DSA crypto
— it's about the resolver's algorithm-dispatch / error-handling path recognizing
"algorithm I don't support" as a degrade-to-insecure signal rather than a fatal
error. (The verbose output already *notices* the unknown algorithm; the bug is
that noticing it aborts instead of degrading.)

### 2. Actual alg-18 verification (the larger project)

To genuinely *validate* alg-18 (return Secure/AD when the chain checks out),
verify each RRSIG with `cryptography`'s MLDSA44 primitive. The recipe below is
the exact one the signer's test suite uses as an independent oracle, so it is
known to interoperate with what `adns_server` produces (and, being spec-correct,
with any conformant signer).

## The verification recipe (known-good, copy this)

> **resolve.py note:** resolve.py does NOT use `dns.dnssec.validate()`; it builds
> the RFC 4034 §3.1.8.1 signing input itself in `reslib.dnssec.get_sig_info()`
> (stored as `Signature.indata`), so the resolve-native verify is
> `reslib.mldsa.verify(pubkey, rrsig.signature, indata)` with `context=None`.
> dnspython's private `_make_rrsig_signature_data` is not required here. Keep the
> existing recipe below as the adns_server reference.

Two ingredients: the **raw public key bytes** (from the DNSKEY) and the
**data-to-be-signed** (RFC 4034 §3.1.8.1, reconstructed from the RRset + an
empty-signature RRSIG template).

```python
# Lazy import — never at module top level.
from cryptography.hazmat.primitives.asymmetric import mldsa
import dns.dnssec
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.RRSIG

def verify_mldsa_rrsig(rrset, rrsig, dnskey):
    """
    Verify one alg-18 RRSIG (a single RRSIG rdata) over `rrset`, using `dnskey`
    (the DNSKEY rdata whose key_tag matches rrsig.key_tag and algorithm == 18).
    Returns True on success; MLDSA44PublicKey.verify() raises InvalidSignature
    on failure.
    """
    assert rrsig.algorithm == 18 and dnskey.algorithm == 18

    # (a) Raw 1312-octet public key straight out of the DNSKEY rdata.
    #     For alg 18 the DNSKEY "public key" field IS the FIPS 204 raw public
    #     key, so dnskey.key is exactly what from_public_bytes() wants.
    pub = mldsa.MLDSA44PublicKey.from_public_bytes(dnskey.key)

    # (b) Rebuild the RFC 4034 3.1.8.1 signing input. Build an RRSIG template
    #     identical to the received RRSIG but with an EMPTY signature, then let
    #     dnspython's algorithm-agnostic private helper assemble the wire data.
    labels = len(rrset.name) - 1
    if rrset.name.is_wild():
        labels -= 1
    template = dns.rdtypes.ANY.RRSIG.RRSIG(
        rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.RRSIG,
        type_covered=rrset.rdtype, algorithm=18, labels=labels,
        original_ttl=rrsig.original_ttl, expiration=rrsig.expiration,
        inception=rrsig.inception, key_tag=rrsig.key_tag,
        signer=rrsig.signer, signature=b"")
    data = dns.dnssec._make_rrsig_signature_data(rrset, template, None)  # noqa

    # (c) Pure ML-DSA, empty context. context=None IS the spec's empty context.
    pub.verify(rrsig.signature, data, context=None)   # raises on failure
    return True
```

Critical details, each a place things silently go wrong:

- **`context=None` is mandatory and correct.** The DNSSEC profile uses "pure"
  ML-DSA with an empty context. Passing any other context value will fail
  verification against every conformant signature.
- **`dns.dnssec._make_rrsig_signature_data` is a *private* dnspython API** but is
  algorithm-agnostic and is what makes this work without native alg-18 support.
  Guard for its presence (`hasattr(dns.dnssec, "_make_rrsig_signature_data")`)
  and degrade to insecure if a future dnspython drops it — don't let its absence
  crash the resolver. (The signer does exactly this guard.)
- **`labels`** = owner-name label count minus 1 (root), minus 1 more for a
  wildcard owner. This must match what the signer put in the RRSIG; the RRset's
  canonical form and TTL handling are all inside `_make_rrsig_signature_data`,
  so don't reimplement §3.1.8.1 by hand.
- **`original_ttl`** comes from the RRSIG, and the RRset passed in must be in the
  form the helper expects. If you already validate other algorithms via
  dnspython, mirror whatever RRset/TTL normalization that path does.
- **keytag / DS are algorithm-independent.** `dns.dnssec.key_id(dnskey)` and
  `dns.dnssec.make_ds(...)` work unchanged for alg 18 (they operate on the
  DNSKEY rdata opaquely), so DS-matching up the chain needs no special case —
  only the RRSIG signature check does.

## Live end-to-end test target

`adns_server` runs a live signed alg-18 zone you can validate against
end-to-end:

- **Zone:** `mldsa.huque.com` (online-signed, alg-18 CSK), served by
  **guvnor.huque.com**, with the matching **DS published in the parent**
  (`huque.com`). Deployed and confirmed 2026-08-16.
- **Zscaler / transport:** iterative resolution from the laptop is blocked by
  Zscaler (same reason `resolve.py` is installed on **toolbox**). Run validation
  tests from toolbox: `ssh toolbox`, then the resolver in
  `/home/shuque/virt/adns`.
- **Expected outcomes:**
  - *Before* alg-18 support (bug fix only): answer returned, marked
    **insecure/unverifiable**, diagnostic naming the unsupported algorithm — no
    fatal error. Compare against Cloudflare's `1.1.1.1` behavior on the same
    name (answer + no AD + EDE 1).
  - *After* full alg-18 verification: the SOA/DNSKEY/etc. RRSIGs verify and the
    chain is **Secure** (assuming the resolver is anchored such that the
    `huque.com` DS is reachable — note guvnor is authoritative-only).
- The signer's own independent oracle (which this recipe is lifted from) lives
  at `~/git/adns_server/tests/pytest/test_mldsa_online.py` and
  `test_mldsa_serving.py` — useful as a second reference implementation of the
  verify path.

## Status

- **Behavior #1 (degrade-to-insecure) — DONE, confirmed 2026-08-16.**
  `resolve.py -vz mldsa.huque.com. SOA` now returns the answer unverified
  instead of erroring. Notably it degrades at the **DS algorithm check on the
  SECURE referral** (the secure-entry-point), *before* fetching the DNSKEY or
  attempting any RRSIG verify — the cleanest place to do it:
  `INFO: no supported DNSSEC algorithm (DS alg 18) ...; treating as insecure`,
  TCP fallback on the truncated SOA, then answer with
  `DNSSEC status: INSECURE`, RCODE NOERROR. Matches Cloudflare 1.1.1.1.
- **Behavior #2 (actual alg-18 verification) — NEXT.** Make it reach
  SECURE/AD instead of degrading, using the recipe above.

## Kickoff sequence for the verification work (behavior #2)

Do this work in the **resolve session, rooted at `~/git/resolve`** (not from the
adns_server cwd — that session lacks this repo's CLAUDE.md, code layout, and
existing validation path). Suggested opening moves:

1. **Load context.** Read this file, then the existing DNSSEC-validation and
   algorithm-dispatch code (`reslib/`, `DNSSEC.md`) and the secure-entry-point /
   DS-algorithm check that currently degrades alg 18 to insecure — that check is
   exactly what behavior #2 must turn from "unsupported → insecure" into
   "supported → verify".
2. **Brainstorm → plan.** Invoke the brainstorming skill, then writing-plans, to
   produce an implementation plan *in this repo* before touching code. Gate the
   alg-18 primitive on `cryptography >= 50.0.0` with graceful skip; lazy-import
   `mldsa`; guard `_make_rrsig_signature_data`.
3. **Feature branch.** Cut a feature branch off master and do the work there.
   **Merge-commit** it back to master when done (this repo's convention —
   *not* squash, which is the adns_server convention; don't conflate them).
4. **Verify end-to-end** on toolbox against `mldsa.huque.com` (guvnor + parent
   DS): before = INSECURE (behavior #1); after = SECURE, with the SOA/DNSKEY
   RRSIGs verifying. Cross-check the verify path against the signer's oracle in
   `~/git/adns_server/tests/pytest/test_mldsa_online.py`.

Consider committing this file (and a copy of the draft from
`adns_server/specs/`) into the resolve repo so it stays in that session's
context.
