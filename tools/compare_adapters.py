#!/usr/bin/env python3
"""Deep-compare two adapter reports (run_adapter.py --report) fixture by fixture.

Stricter than the fixtures themselves: beyond the asserted expectations, the
FULL wire output (exit code, accepted, rejection code, every accept fact) must
be identical between the two SDKs. Any divergence — even in a field no fixture
declares — is reported. Exit nonzero on any difference.

Usage: compare_adapters.py go-report.json js-report.json
"""

import json
import sys


def main():
    a_path, b_path = sys.argv[1], sys.argv[2]
    a, b = json.load(open(a_path)), json.load(open(b_path))
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
    sys.exit(1 if diffs or only_a or only_b else 0)


if __name__ == "__main__":
    main()
