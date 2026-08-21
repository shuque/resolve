# DELEG support in resolve

Implementation notes for the DELEG (extensible delegation) mechanism in the
iterative resolver, `resolve.py` / `reslib/`. This is the resolver (validating
client) counterpart to the authoritative-server notes in the companion
`adns_server` project.

## Specifications

This resolver implements the validating-resolver behavior described in:

- **draft-ietf-deleg-11** — the DELEG/DELEGPARAM record types, the DelegInfos
  RDATA format (an SVCB-style `SvcParams` encoding), the "finding the best
  servers" algorithm (Section 4.2 / 5.1.2), and the delegation semantics.
- **draft-ietf-dnsop-delext-10** — the EDNS(0) DE flag, the Delegation Type
  code range, the DNSKEY-ADT flag, referral handling, and the DNSSEC
  anti-downgrade proof rules (Sections 6 and 8).

The resolver only engages DELEG behavior when explicitly asked to (the
`--deleg` flag). Without it, the resolver sends DE=0 and expects — and
processes — ordinary NS referrals exactly as it always has; any DELEG RRset in
an authority section is ignored. This mirrors the delext §4.1 rule that a DE=0
client is served as though DELEG did not exist.

## Type codes and signaling

These are pre-standardization placeholders, agreed with collaborators, and are
defined in `reslib/deleg.py`:

- **DELEG = 61440** (`0xF000`, from the proposed delext Delegation-Type range).
  Creates a zone cut with DS-like (authoritative-at-the-cut, signed-there)
  semantics. dnspython has no native rdata class for it, so on the wire it is
  handled as an RFC 3597 generic (`TYPE61440`) type and its RDATA is decoded by
  this project's own codec.
- **DELEGPARAM = 65433** — the indirection target reached via the
  `include-delegparam` DelegInfo key. Shares the DelegInfos wire format with
  DELEG.
- **EDNS(0) DE flag** (Delegation Extensions), bit 2 = `0x2000`, constant
  `EDNS_DE_FLAG`. The resolver sets it on every outgoing query when `--deleg`
  is in effect (see `reslib/utils.py`), signaling that it understands DELEG and
  wishes to receive DELEG referrals.
- **DNSKEY-ADT flag**, DNSKEY flags bit `0x0002`, decoded as `adt_flag` in
  `reslib/dnssec.py`. For a combined KSK/ZSK signing key this makes the numeric
  flags value **259** (ZONE `0x0100` + ADT `0x0002` + SEP `0x0001`). The
  resolver reads this flag off each validated DNSKEY and records it on the zone
  object (`Zone.adt`); it is the trigger for anti-downgrade enforcement (below).

## Enabling DELEG: the `--deleg` flag

DELEG behavior is entirely opt-in and driven by one preference,
`prefs.DELEG`, set by `--deleg` (`reslib/options.py`). Turning it on does two
things:

1. **Egress signaling.** Every query message sets the EDNS DE flag. Because DE
   travels in EDNS(0), `--deleg` requires a non-zero EDNS buffer size; combining
   it with `-e 0` is rejected at argument-parse time.
2. **Ingress handling.** The resolver will *follow* a DELEG RRset in a referral
   (sourcing the child zone's servers from it) instead of the accompanying NS,
   and will enforce the DELEG anti-downgrade proofs described below.

`prefs.DELEG` is the resolver's **local standing intent**, not a copy of the
on-wire DE bit. That distinction is deliberate and load-bearing for downgrade
resistance (see §8.2.2 discussion below): an on-path attacker can clear the DE
bit in a query in flight, but cannot reach into the resolver and change
`prefs.DELEG`. Every DELEG decision keys off the local preference, so a
DE-stripping attacker cannot also suppress the resolver's demand for proof.

Two further bounds are configurable via `prefs`:

- `MAX_DELEGPARAM` (default 10) — maximum `include-delegparam` chain depth.
- `MAX_DELEG` (default 200) — maximum number of delegations followed in one
  resolution (a general loop guard, shared with the legacy NS path).

## Functional summary

The DELEG record defines a zone cut much like NS, but with DS-like semantics.
When `--deleg` is set the resolver sends DE=1 and processes referrals in
`process_referral()` (`reslib/lookup.py`), which first parses the authority
section into at most one each of NS, DS, and DELEG RRsets, then dispatches.

### DELEG referral (DE=1, DELEG present) — `_process_deleg_referral()`

When `prefs.DELEG` is set and the referral carries a DELEG RRset, the resolver
takes the DELEG path:

- **NS is ignored.** Any accompanying NS RRset is neither validated nor cached
  (delext §5.2: an NS accompanying a DELEG MUST NOT be cached). To guarantee
  this, the authority section is decoded with auto-caching disabled, and only
  DELEG, DS, and the NSEC/NSEC3 proof records are explicitly re-installed.
- **DELEG is validated like DS.** In a secure chain the DELEG RRset is
  DNSSEC-validated, and secure/insecure status is decided by the DS RRset
  exactly as on the NS path: a DS present (and owner-matching) means a secure
  delegation continues the chain; no DS means the resolver authenticates the
  insecure delegation (NSEC/NSEC3 proving DS absence) and drops
  `secure_so_far`.
- **DELEG-only cuts are legal.** Unlike the NS path (which errors if no NS is
  found), a referral with a DELEG and no NS is a normal, fully supported case.
- **No NS fallback.** If the DELEG RRset is present but yields no usable server
  (see "present-but-unusable" below), resolution fails with a terminal error;
  the resolver does **not** fall back to any NS in the message
  (draft-ietf-deleg §4.4).
- The child zone's server addresses come from the DELEG record via the slist
  builder (next section); they are stored on the `Zone` as a DELEG-sourced
  address list, and the full DELEG RRset is retained for `-v` trace output.

### NS referral (DELEG absent, or `--deleg` off) — `_process_ns_referral()`

If `prefs.DELEG` is off, or the referral carries no DELEG RRset, the resolver
uses the unchanged legacy path: validate everything except NS, install NS + DS
(+ proofs), decide secure/insecure via DS, and populate the zone from NS +
glue. This path is byte-for-byte the pre-DELEG behavior.

### Stacked cuts

A "stacked" cut publishes **both** NS and DELEG. On a DE=1 referral the server
sends the DELEG (per §5.2) and omits the NS, so from the resolver's point of
view a stacked cut is indistinguishable from a DELEG-only cut at referral time
— which is correct, because with `--deleg` the resolver wants the DELEG. The
significance of stacked cuts is confined to the anti-downgrade bitmap check
(below), where the zone's signed NSEC legitimately lists NS even though the
referral does not carry it.

## The DelegInfos wire codec — `reslib/deleg.py`

DELEG and DELEGPARAM RDATA is the DelegInfos list of draft-ietf-deleg Section 3,
which reuses the SVCB `SvcParams` wire encoding [RFC 9460 §2.2]: a sequence of
`(key, 2-byte length, value)` triples in strictly increasing key order with no
duplicate keys. `reslib/deleg.py` is an **I/O-free leaf module** — it imports
only stdlib and dnspython (`dns.name`, `dns.rdataclass`) and no `reslib`
modules — so the decode/classify/build logic is unit-testable in isolation. Its
decode primitives are ported from `adns_server/adns/deleg.py`.

DelegInfo key registry (draft-ietf-deleg §8.2.2) recognized by the resolver:
`mandatory` (0), `server-ipv4` (1), `server-ipv6` (2), `server-name` (3),
`include-delegparam` (4). Any other key number is retained as an unknown key.

The codec has three layers:

### 1. Parse — `parse_deleginfos()`

Decodes the RDATA blob into a `DelegInfo`, enforcing the wire-format rules:
keys strictly increasing, no duplicates, no truncation, and no empty values.
Address values must be a whole number of 4- (v4) or 16-octet (v6) chunks;
wire-format names are decoded uncompressed; `mandatory` decodes to a set of key
numbers. A malformed blob raises `DelegParseError`.

### 2. Classify one record — `classify_record()`

Implements the per-record selection of draft-ietf-deleg §5.1.2:

1. Discard unsupported keys; if nothing supported remains, the record
   contributes nothing (`"none"`).
2. Every `mandatory`-referenced key must still be present, else the record is
   dropped (`DelegRecordError`).
3. The set of server-information keys must be exactly one **allowed shape**:
   `{server-ipv4}`, `{server-ipv6}`, `{server-ipv4, server-ipv6}`,
   `{server-name}`, or `{include-delegparam}` (§3.4). Any other combination is
   a malformed record.
4. `server-name` / `include-delegparam` targets must **not** be at or below the
   originally delegated owner name (an in-bailiwick target would create a
   resolution dependency loop); such a record is dropped.
5. Otherwise the record resolves to one of: inline addresses (`"addrs"`), a
   list of server names to resolve (`"names"`), or an indirection to
   DELEGPARAM targets (`"delegparam"`).

### 3. Build the server list — `build_slist()`

Walks every rdata in the DELEG RRset, classifies each, and accumulates a
**deduplicated** address list. `server-name` records are resolved to addresses
via a resolver-supplied callback (a normal recursive A/AAAA lookup);
`include-delegparam` records are followed by fetching the DELEGPARAM RRset at
the target and recursing, bounded by `max_chain` (`prefs.MAX_DELEGPARAM`). A
record that raises during parse or classify is simply skipped, so one malformed
rdata cannot poison the whole RRset.

`build_slist()` returns a **tri-state** result, which is what lets the caller
honor the no-fallback rule precisely:

| State | Meaning | Resolver action |
|-------|---------|-----------------|
| `absent` | No DELEG RRset at all | Not reached on the DELEG path |
| `usable` | At least one address was produced | Proceed using those addresses |
| `present-but-unusable` | A DELEG RRset exists but yielded zero usable addresses | **Terminal failure, no NS fallback** (§4.4) |

The resolver-side driver, `_build_deleg_slist()` in `reslib/lookup.py`,
supplies the two callbacks. Note a deliberate divergence recorded there: the
draft's §4.2 step 7 counts a CNAME/DNAME hop against the *same* loop budget as
a DELEGPARAM hop, but the callback contract does not expose per-resolution hop
counts. Instead every path is independently bounded — the `include-delegparam`
chain by `MAX_DELEGPARAM`, and each nested name resolution by the resolver's
global `MAX_CNAME` counter — so there is no unbounded-recursion hole; it is two
finite budgets rather than one shared budget.

## Signing, the DNSKEY-ADT flag, and downgrade resistance

Following a DELEG and offering *downgrade resistance* for it are two separate
things. The resolver will follow a DELEG referral whenever `--deleg` is set,
signed or not. Anti-downgrade enforcement is an additional layer that engages
only under specific conditions.

### When enforcement is active — the `adt_active` gate

In `process_referral()`, delegation-type-proof enforcement runs only when all
of the following hold:

- `prefs.DELEG` — this resolver actually sent DE=1. A resolver that did not
  send DE=1 expects a traditional referral and has no delegation-type proof to
  demand.
- `prefs.DNSSEC` and `query.secure_so_far` — DNSSEC validation is on and the
  chain is still secure up to the delegating zone.
- `not query.is_nsquery` — this isn't an internal helper (glue-resolution)
  query.
- `referring_zone.adt` — the **delegating** zone's validated DNSKEY carries the
  ADT flag.

Gating on `prefs.DELEG` (local intent), not the echoed wire DE bit, is what
makes the check resistant to DE-flag stripping: see §8.2.2 below.

### What enforcement requires — `enforce_adt_proof()` / `adt_bitmap_consistent()`

When active, the referral MUST include a validated NSEC or NSEC3 record
matching the delegated name whose type bitmap is **consistent with the
delegation types actually present** in the referral (delext §6.2). "Consistent"
is defined narrowly by `adt_bitmap_consistent()`:

> The DELEG (61440) bit in the bitmap MUST be set **iff** a DELEG RRset is
> present in the authority section.

A bitmap that proves a DELEG exists while the referral carries none — or
carries a DELEG the bitmap denies — signals a stripped or injected DELEG and
the response is rejected as bogus ("referral tampered"). A referral from an
ADT zone that lacks any matching NSEC/NSEC3 proof is likewise rejected.

**The NS direction is deliberately not checked.** For a stacked cut the zone's
signed NSEC legitimately lists NS (it is zone truth), yet a DE=1 referral omits
the NS RRset because the server sent the DELEG in its place (§5.2). "NS in the
bitmap but NS absent from the authority section" is therefore a normal,
non-tampered state, and checking the NS direction would raise false tampering
alarms on every stacked cut. Only the DELEG bit carries anti-downgrade signal,
so only the DELEG bit is checked. (`ns_present` is still threaded through the
call for symmetry, but does not gate the result.)

### The two attacks this defeats

Both are downgrade attacks from delext §8.2, and both are detectable *only*
when the delegating zone is signed **and** publishes the DNSKEY-ADT flag —
which is exactly the `adt_active` precondition:

- **DELEG-strip → NS-fallback (§8.2.1).** An attacker removes the DELEG RRset
  and substitutes (or leaves) an NS referral, hoping the resolver falls back to
  the weaker NS delegation. With ADT set, the zone's signed NSEC at the cut
  carries the DELEG bit; a referral that omits the DELEG while its own proof
  asserts one is caught by the bitmap-consistency check. (And on the DELEG
  path the resolver never falls back to NS regardless — §4.4.)
- **DE-flag strip (§8.2.2).** An on-path attacker clears the DE bit in the
  resolver's query so the server, now seeing DE=0, answers as a non-DELEG
  server would (an occlusion NXDOMAIN below a DELEG-only cut, or a plain NS
  referral). The defense is the split between wire state and local intent: the
  resolver's enforcement keys off `prefs.DELEG`, which the attacker cannot
  touch. The resolver still demands the ADT delegation-type proof, and the
  DELEG bit that the delegating zone's signed NSEC carries at the cut is what
  lets the resolver detect that a Delegation Type exists and reject the
  downgraded answer. This is the resolver-side counterpart to the authoritative
  server's obligation (delext §4.1.1 / §8.4) to keep the DELEG bit visible in
  the NSEC bitmap even in a DE=0 occlusion response — including Compact Denial
  zones, which must emit a classic covering proof rather than an NXNAME black
  lie precisely so this bit survives.

In short, the DNSKEY-ADT flag and the signed NSEC bitmap are two halves of one
mechanism: ADT is what *compels* the resolver to inspect the delegation-type
bit, and the bitmap is the proof material it inspects. Absent either (unsigned
zone, or signed zone without ADT), the DELEG can still be followed but these
strip attacks are not detectable — matching the protection tiers described on
the authoritative-server side.

## Relevant functions and symbols

| Symbol | File | Role |
|--------|------|------|
| `DELEG_RDTYPE`, `DELEGPARAM_RDTYPE` | `deleg.py` | Type codes 61440 / 65433 |
| `EDNS_DE_FLAG` | `deleg.py` | EDNS(0) DE flag (`0x2000`) |
| `parse_deleginfos()` | `deleg.py` | Decode DelegInfos RDATA, enforce wire rules |
| `classify_record()` | `deleg.py` | Per-record §5.1.2 shape selection |
| `build_slist()` / `SlistResult` | `deleg.py` | Tri-state server-list builder from a DELEG RRset |
| `format_deleginfo()` / `format_deleg_rrset()` | `deleg.py` | Presentation form for `-v` / answer output |
| `prefs.DELEG` | `prefs.py` | Local intent: send DE=1 and follow DELEG (`--deleg`) |
| `prefs.MAX_DELEGPARAM` | `prefs.py` | `include-delegparam` chain-depth bound |
| `make_query_message()` | `utils.py` | Sets the EDNS DE flag when `prefs.DELEG` |
| `adt_flag` (`DNSKEY`) / `Zone.adt` | `dnssec.py` / `zone.py` | DNSKEY-ADT flag decode and per-zone record |
| `process_referral()` | `lookup.py` | Parse authority section; `adt_active` gate; dispatch |
| `_process_deleg_referral()` | `lookup.py` | DE=1 DELEG referral (validate-like-DS, no NS, no fallback) |
| `_process_ns_referral()` | `lookup.py` | Legacy NS referral (unchanged) |
| `_build_deleg_slist()` | `lookup.py` | Resolver-backed `server-name` / DELEGPARAM callbacks |
| `enforce_adt_proof()` | `lookup.py` | Require a consistent, validated NSEC/NSEC3 delegation-type proof |
| `adt_bitmap_consistent()` | `lookup.py` | DELEG-bit == DELEG-present bitmap check (NS direction not checked) |

## Interoperability notes

The resolver is developed and tested against the companion `adns_server`
authoritative implementation and against the live `deleg.huque.com` test zone
(a signed, DNSKEY-ADT zone with a matrix of secure/insecure and
DELEG-only/stacked sub-delegations).
