#!/usr/bin/env python3
"""Render a markdown summary of v3 adapter reports (run_adapter.py --report).

Usage: v3_report.py --out report.md reference.json [other.json ...]

Per SDK: pass/skip/fail totals and a per-suite breakdown. With two or more
reports, every other report is deep-compared against the first (the
reference) with compare_adapters.compare, and the identical/divergent counts
plus the divergent fixtures are listed. Each report is named after its file
stem (results/v3/tinfoil-go.json → tinfoil-go).

Pure transform: always exits 0. Failures surface through run_adapter.py and
compare_adapters.py exit codes; this only makes them readable.
"""

import argparse
import json
import os
from collections import Counter, defaultdict

from compare_adapters import compare


def load(path):
    name = os.path.splitext(os.path.basename(path))[0]
    return name, json.load(open(path))


def counts(report):
    """Return ({status: n}, {suite: {status: n}}) for one report."""
    total = Counter()
    per_suite = defaultdict(Counter)
    for key, r in report["results"].items():
        suite = key.split("/", 1)[0]
        total[r["status"]] += 1
        per_suite[suite][r["status"]] += 1
    return total, per_suite


def cell(c):
    n = sum(c.values())
    s = f"{c['PASS']}/{n}"
    if c["SKIP"]:
        s += f" ({c['SKIP']} skip)"
    if c["FAIL"]:
        s += f" (**{c['FAIL']} FAIL**)"
    return s


def render(named):
    L = ["## v3 adapter lane", ""]
    L += ["| SDK | pass | skip | fail | total |", "|---|--:|--:|--:|--:|"]
    totals = {}
    suites = {}
    for name, rep in named:
        totals[name], suites[name] = counts(rep)
        t = totals[name]
        L.append(f"| `{name}` | {t['PASS']} | {t['SKIP']} | {t['FAIL']} | {sum(t.values())} |")

    all_suites = sorted({s for per in suites.values() for s in per})
    L += ["", "### Per-suite", "",
          "| suite | " + " | ".join(f"`{n}`" for n, _ in named) + " |",
          "|---|" + "|".join(["---"] * len(named)) + "|"]
    for suite in all_suites:
        L.append(f"| `{suite}` | " + " | ".join(cell(suites[n][suite]) for n, _ in named) + " |")

    fails = [(n, key, r.get("detail", "")) for n, rep in named
             for key, r in sorted(rep["results"].items()) if r["status"] == "FAIL"]
    if fails:
        L += ["", f"<details><summary>{len(fails)} failing fixture(s)</summary>", ""]
        L += [f"- `{n}` `{key}`: {detail}" for n, key, detail in fails]
        L += ["", "</details>"]

    if len(named) >= 2:
        ref_name, ref = named[0]
        L += ["", f"### Cross-SDK comparison (reference: `{ref_name}`)", "",
              "Full wire output (exit code, verdict, rejection code, every accept fact) "
              "must be identical to the reference.", "",
              "| SDK | identical | divergent | unmatched |", "|---|--:|--:|--:|"]
        details = []
        for name, rep in named[1:]:
            agree, diffs, only_a, only_b = compare(ref, rep)
            L.append(f"| `{name}` | {agree} | {len(diffs)} | {len(only_a) + len(only_b)} |")
            for key, fields in diffs:
                details.append(f"- `{name}` `{key}`: " + "; ".join(fields))
            details += [f"- `{name}` missing `{key}`" for key in only_a]
            details += [f"- `{name}` extra `{key}`" for key in only_b]
        if details:
            L += ["", f"<details><summary>{len(details)} divergence(s)</summary>", ""]
            L += details
            L += ["", "</details>"]
    else:
        L += ["", "_Only one SDK ran the v3 lane; nothing to compare._"]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="markdown output path")
    ap.add_argument("reports", nargs="+", help="run_adapter.py reports; the first is the reference")
    args = ap.parse_args()
    named = [load(p) for p in args.reports]
    md = render(named)
    with open(args.out, "w") as fh:
        fh.write(md)
    for name, rep in named:
        t, _ = counts(rep)
        print(f"{name:14} {t['PASS']} pass, {t['SKIP']} skip, {t['FAIL']} fail")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
