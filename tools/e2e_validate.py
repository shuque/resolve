#!/usr/bin/env python3
#
"""
End-to-end DNSSEC validation harness for resolve.py.

NETWORK-GATED: this drives the real resolver against live zones on the
Internet, so it is NOT part of the offline unit-test suite and is never
collected by pytest. Run it by hand from a host with clean DNS egress
(e.g. toolbox), not from behind an intercepting resolver.

It invokes the resolve.py CLI as a subprocess for each target and checks:
  - SECURE   -> exit 0 and a "# DNSSEC status: SECURE" line
  - INSECURE -> exit 0 and a "# DNSSEC status: INSECURE" line
  - BOGUS    -> non-zero exit and no "SECURE" status (validation refused)

Targets change over time (zones get signed, keys roll, test beds move).
The TARGETS table below is meant to be edited; treat a failure as "check
the zone first", not necessarily "the resolver regressed".

Usage:
    tools/e2e_validate.py                 # run all targets
    tools/e2e_validate.py -c ~/.local/bin/resolve.py
    tools/e2e_validate.py --only mldsa    # substring filter on target name
    RESOLVE_CMD=resolve.py tools/e2e_validate.py

Exit status is 0 only if every (selected) target matched its expectation.
"""

import os
import sys
import shlex
import argparse
import subprocess

SECURE = "SECURE"
INSECURE = "INSECURE"
BOGUS = "BOGUS"

# (name, qtype, expectation). Edit freely as the live DNS changes.
TARGETS = [
    # Signed, in-band algorithms.
    (".", "SOA", SECURE),                    # alg 8 (root KSK/ZSK)
    ("iana.org.", "SOA", SECURE),            # alg 8 RSASHA256
    ("cloudflare.com.", "SOA", SECURE),      # alg 13 ECDSAP256SHA256
    # Post-quantum test bed (alg 18, ML-DSA-44). See MLDSA44.md.
    ("mldsa.huque.com.", "SOA", SECURE),
    # Deliberately broken signatures -> must be refused, never SECURE.
    ("dnssec-failed.org.", "SOA", BOGUS),
    ("sigfail.verteiltesysteme.net.", "A", BOGUS),
    # Unsigned zone under a signed parent (no DS) -> proven INSECURE.
    # (A large, long-unsigned apex; swap if it ever gets a DS record.)
    ("amazon.com.", "SOA", INSECURE),
]


def resolve_cmd():
    """Determine the resolve.py invocation (list of argv tokens)."""
    env = os.environ.get("RESOLVE_CMD")
    if env:
        return shlex.split(env)
    return ["resolve.py"]


def run_one(base_cmd, name, qtype):
    """Run one DNSSEC-validating query; return (exit_code, combined_output)."""
    argv = base_cmd + ["-z", name, qtype]
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    return proc.returncode, proc.stdout


def classify(code, output):
    """Map a run's (exit_code, output) to SECURE / INSECURE / BOGUS."""
    if "# DNSSEC status: SECURE" in output:
        return SECURE
    if "# DNSSEC status: INSECURE" in output:
        return INSECURE
    if code != 0:
        return BOGUS
    return "UNKNOWN"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-c", "--resolve-cmd", dest="cmd",
                        help="resolve.py command (overrides $RESOLVE_CMD)")
    parser.add_argument("--only", dest="only",
                        help="run only targets whose name contains this substring")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print each query's full output")
    opts = parser.parse_args()

    base_cmd = shlex.split(opts.cmd) if opts.cmd else resolve_cmd()
    targets = [t for t in TARGETS if not opts.only or opts.only in t[0]]
    if not targets:
        print("No targets matched --only {!r}".format(opts.only), file=sys.stderr)
        return 2

    print("# resolve.py: {}".format(" ".join(base_cmd)))
    failures = 0
    for name, qtype, expected in targets:
        code, output = run_one(base_cmd, name, qtype)
        got = classify(code, output)
        ok = (got == expected)
        failures += not ok
        print("{:4}  {:40} {:5}  expect={:8} got={:8} exit={}".format(
            "PASS" if ok else "FAIL", name, qtype, expected, got, code))
        if opts.verbose or not ok:
            for line in output.rstrip().splitlines():
                print("      | {}".format(line))

    print("# {} passed, {} failed, {} total".format(
        len(targets) - failures, failures, len(targets)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
