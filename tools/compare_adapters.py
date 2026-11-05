#!/usr/bin/env python3
"""Deep-compare adapter reports (run_adapter.py --report) fixture by fixture.

Stricter than the fixtures themselves: beyond the asserted expectations, the
FULL wire output (exit code, accepted, rejection code, every accept fact) must
be identical between the SDKs. Any divergence — even in a field no fixture
declares — is reported. Exit nonzero on any difference.

Usage: compare_adapters.py reference.json other.json [other2.json ...]

The first report is the reference; every other report is compared against it.
"""

import json
import sys


def compare(a, b):
    """Compare two loaded reports. Returns (agree, diffs, only_a, only_b) where
    diffs is a list of (fixture key, [differing field descriptions])."""
    ra, rb = a["results"], b["results"]
    only_a = sorted(set(ra) - set(rb))
    only_b = sorted(set(rb) - set(ra))
    diffs = []
    agree = 0
    for key in sorted(set(ra) & set(rb)):
        xa, xb = ra[key], rb[key]
        fields = []
        if xa["exit"] != xb["exit"]:
            fields.append(f"exit {xa['exit']} vs {xb['exit']}")
        oa, ob = xa.get("output") or {}, xb.get("output") or {}
        if oa.get("accepted") != ob.get("accepted"):
            fields.append(f"accepted {oa.get('accepted')} vs {ob.get('accepted')}")
        ca, cb = (oa.get("rejection") or {}).get("code"), (ob.get("rejection") or {}).get("code")
        if ca != cb:
            fields.append(f"code {ca} vs {cb}")
        fa, fb = oa.get("outputs") or {}, ob.get("outputs") or {}
        for k in sorted(set(fa) | set(fb)):
            if fa.get(k) != fb.get(k):
                fields.append(f"outputs.{k}: {json.dumps(fa.get(k))[:60]} vs {json.dumps(fb.get(k))[:60]}")
        if fields:
            diffs.append((key, fields))
        else:
            agree += 1
    return agree, diffs, only_a, only_b


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__.strip())
    a = json.load(open(sys.argv[1]))
    ok = True
    for b_path in sys.argv[2:]:
        b = json.load(open(b_path))
        agree, diffs, only_a, only_b = compare(a, b)
        print(f"A: {a['adapter']}\nB: {b['adapter']}\n")
        print(f"compared {agree + len(diffs)} fixtures: {agree} identical, {len(diffs)} divergent"
              + (f", {len(only_a)}+{len(only_b)} unmatched" if only_a or only_b else ""))
        for key, fields in diffs:
            print(f"  DIVERGE {key}")
            for f in fields:
                print(f"    {f}")
        for key in only_a:
            print(f"  ONLY-A {key}")
        for key in only_b:
            print(f"  ONLY-B {key}")
        print()
        ok = ok and not (diffs or only_a or only_b)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
