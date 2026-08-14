#!/usr/bin/env python3
"""Generate v3 FRESHNESS fixtures (SPEC §10).

Freshness in v3 is deliberately narrow: the verifier binds the quote to *its own*
nonce (never the document's), and enforces no higher-level collateral-expiry or
anti-rollback bound today (capability `freshness_enforced=false`).

FR1 (nonce binding) is the one enforced, fixturable rule end-to-end: the golden
document accepts when the verifier's nonce matches, and rejects when the
verifier supplies a different nonce than the one bound into the quote's
REPORT_DATA ladder — proving the verifier trusts its own nonce, not the
document's. FR3 (multiple endorsed stacks accepted, no rollback bound) is the
ST2 positive `st2-multi-measurement`; FR2 (freshness witness) is a deferred,
not-yet-specified proposal with nothing to enforce.
"""

import json
import os

import gen_golden as gg


def main():
    out = "vectors/v3/freshness"
    os.makedirs(out, exist_ok=True)
    _, inp = gg.golden()

    fresh = {"id": "fr1-nonce-fresh", "stage": "verify-attestation-v3",
             "input": inp, "expected": {"accepted": True}}

    # Verifier supplies a different nonce than the one bound into the document;
    # verify-attestation-v3 must reject (it uses its own nonce, not the doc's).
    stale_inp = dict(inp)
    stale_inp["nonce_hex"] = "ff" * 32
    stale = {"id": "fr1-nonce-stale", "stage": "verify-attestation-v3",
             "input": stale_inp, "expected": {"accepted": False, "code": "ENVELOPE_REJECTED"}}

    for f in (fresh, stale):
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote 2 freshness fixtures to {out}/")


if __name__ == "__main__":
    main()
