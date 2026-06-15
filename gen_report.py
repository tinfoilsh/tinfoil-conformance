#!/usr/bin/env python3
"""Generate homogenization-targeting artifacts from a conformance results.json.

Reuses the harness's divergence.analyze() for consensus/skip/rejection data,
then layers on:
  * a consensus-based capability GAP LEADERBOARD (ranks flags by how many SDKs
    deviate, and whether it's a lone-deviator quick win or an even split that
    needs a SPEC decision),
  * a color HTML heatmap (capability matrix + per-test behavior matrix), and
  * machine-readable CSV/JSON for spreadsheet filtering.

Run:
  .harness-venv/bin/python gen_report.py \
      --results results/latest/results.json \
      --vectors vectors/ \
      --out results/latest/report

Output is written under --out (default results/latest/report); `results/` is
gitignored, so these are throwaway action artifacts, not committed.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from tinfoil_conformance.divergence import analyze, _capability_matrix


# ---- explanatory metadata -----------------------------------------------
def load_cap_descriptions(schema_path: Path) -> dict[str, str]:
    """Flatten capabilities.schema.json into {dotted.path: description}.

    The descriptions document enum values inline (e.g. what 'system-clock-only'
    means), so they answer 'what does this flag/value mean' directly."""
    if not schema_path.exists():
        return {}
    schema = json.loads(schema_path.read_text())
    out: dict[str, str] = {}

    def walk(node, prefix=""):
        for k, v in (node.get("properties") or {}).items():
            path = f"{prefix}{k}"
            if v.get("description"):
                out[path] = v["description"]
            if v.get("type") == "object" or v.get("properties"):
                walk(v, path + ".")

    walk(schema)
    return out


def load_fixture_meta(vectors_root: Path) -> dict[str, dict]:
    """Walk vectors/.../manifest.yaml → {id and rel-path: {title, spec_refs,
    expects, notes}}. Keyed by both the bare id and the 'stage/id' rel path so
    results.json fixture ids (which are paths) resolve."""
    out: dict[str, dict] = {}
    for m_path in vectors_root.rglob("manifest.yaml"):
        try:
            m = yaml.safe_load(m_path.read_text())
        except Exception:
            continue
        meta = {
            "title": (m.get("title") or "").strip(),
            "spec_refs": m.get("spec_refs") or [],
            "expects": m.get("expects") or {},
            "notes": (m.get("notes") or "").strip(),
            "fixture_kind": m.get("fixture_kind", ""),
        }
        rel = str(m_path.parent.relative_to(vectors_root))
        for key in {m.get("id") or m_path.parent.name, rel}:
            out[key] = meta
    return out


def _fix_meta_for(fix_meta: dict, fixture_id: str) -> dict | None:
    """Resolve a results.json fixture id (may carry ::public_api and a stage
    prefix) to its manifest meta."""
    base = fixture_id.split("::", 1)[0]
    return (fix_meta.get(base)
            or fix_meta.get(base.rsplit("/", 1)[-1]))


# ---- stage grouping for capability rows ---------------------------------
def _stage_of(cap: str) -> str:
    if cap.startswith("sigstore"):
        return "sigstore"
    if cap.startswith("attestation_sev"):
        return "attestation-sev"
    if cap.startswith("attestation_tdx"):
        return "attestation-tdx"
    if cap.startswith("measurement"):
        return "measurement"
    return "global"


def _stage_of_fixture(fid: str) -> str:
    return fid.split("/", 1)[0]


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True)


# ---- gap leaderboard ----------------------------------------------------
def build_leaderboard(report: dict) -> list[dict]:
    """For each divergent capability, classify the divergence type.

    A flag declared by only a subset of SDKs (others show "—") means the
    capability itself isn't universally exposed — usually a feature only some
    SDKs implement. We label those 'partial-coverage' and rank them below the
    genuine quorum-wide divergences so they don't masquerade as quick wins.
    """
    sdks = report["sdks"]
    n_total = len(sdks)
    rows = []
    for cap, by_sdk in report["capability_divergences"].items():
        # Only count SDKs that actually declare the flag (skip "—"/absent).
        declared = {s: v for s, v in by_sdk.items() if v is not None}
        if len(declared) < 2:
            continue
        counts = Counter(_canon(v) for v in declared.values())
        consensus_canon, consensus_n = counts.most_common(1)[0]
        deviators = [s for s, v in declared.items() if _canon(v) != consensus_canon]
        n = len(declared)
        n_dev = len(deviators)
        full_quorum = n == n_total
        if not full_quorum:
            kind = "partial-coverage"       # flag not exposed by all SDKs
        elif n_dev == 1:
            kind = "lone-deviator"          # quick win: fix the 1 outlier
        elif len(counts) == 2 and n_dev < n / 2:
            kind = "minority"               # bring the minority into line
        elif len(counts) == 2:
            kind = "even-split"             # needs a SPEC decision
        else:
            kind = "multi-way"              # genuine lib differences / SPEC
        consensus_val = json.loads(consensus_canon)
        rows.append({
            "capability": cap,
            "stage": _stage_of(cap),
            "kind": kind,
            "n_declared": n,
            "n_total": n_total,
            "n_deviating": n_dev,
            "consensus": consensus_val,
            "deviators": {s: declared[s] for s in deviators},
            "by_sdk": by_sdk,
        })
    # Rank: genuine quick wins first, partial-coverage near the end.
    order = {"lone-deviator": 0, "minority": 1, "even-split": 2,
             "multi-way": 3, "partial-coverage": 4}
    rows.sort(key=lambda r: (order[r["kind"]], r["n_deviating"], r["stage"], r["capability"]))
    return rows


# ---- per-test behavior matrix -------------------------------------------
def behavior_cell(res: dict | None) -> tuple[str, str, str]:
    """Return (label, css-class, kind) describing what the SDK actually DID.

    kind ∈ {accept, reject, error, skip, absent, other} — the *outcome family*,
    used to tell a substantive behavior split (accept-vs-reject) apart from a
    mere rejection-code taxonomy split (all reject, different codes)."""
    if res is None:
        return "—", "absent", "absent"
    st = res.get("status")
    body = res.get("body") or {}
    if st == "skip":
        return "skip", "skip", "skip"
    if st == "error":
        return "ERROR", "error", "error"
    rej = (body.get("rejection") or {}).get("code")
    accepted = body.get("accepted")
    if rej:
        label, kind = rej, "reject"
    elif accepted is True:
        label, kind = "accept", "accept"
    else:
        label, kind = (st or "?"), "other"
    cls = "pass" if st == "pass" else ("fail" if st == "fail" else "other")
    return label, cls, kind


def build_matrix(results: dict) -> list[dict]:
    sdks = [s["name"] for s in results["sdks"]]
    out = []
    for fx in results["fixtures"]:
        cells = {}
        kinds = set()
        reject_codes = set()
        for s in sdks:
            label, cls, kind = behavior_cell(fx["results"].get(s))
            cells[s] = (label, cls, (fx["results"].get(s) or {}).get("reason", ""))
            if kind in ("accept", "reject", "error"):
                kinds.add(kind)
                if kind == "reject":
                    reject_codes.add(label)
        # Classify the divergence among SDKs that actually ran:
        #   "behavior" — outcome families differ (accept vs reject vs error)
        #   "code"     — all rejected, but emitted ≥2 different taxonomy codes
        if len(kinds) > 1:
            divergence = "behavior"
        elif kinds == {"reject"} and len(reject_codes) > 1:
            divergence = "code"
        else:
            divergence = ""
        out.append({
            "fixture": fx["id"],
            "stage": _stage_of_fixture(fx["id"]),
            "cells": cells,
            "divergence": divergence,
        })
    return out


# ---- renderers ----------------------------------------------------------
CSS = """
body{font:13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#111}
h1{font-size:22px} h2{margin-top:32px;border-bottom:2px solid #eee;padding-bottom:4px}
table{border-collapse:collapse;margin:8px 0 24px;font-size:12px}
th,td{border:1px solid #ddd;padding:3px 7px;text-align:center;white-space:nowrap}
th.row,td.row{text-align:left;font-family:ui-monospace,Menlo,monospace;max-width:520px;white-space:normal}
td.yes{background:#d7f5d7} td.no{background:#fbd2d2;font-weight:600}
td.skip{background:#fff3cd;color:#7a5b00} td.absent{background:#f3f3f3;color:#aaa}
td.pass{background:#eaf7ea} td.fail{background:#fbd2d2;font-weight:600}
td.error{background:#e88;color:#400;font-weight:600} td.other{background:#eee}
tr.div-behavior td.row{border-left:4px solid #d48806}
tr.div-code td.row{border-left:4px dashed #1890ff}
tr.div-code td.pass{background:#e6f2ff}
td.codediv{outline:2px solid #1890ff;outline-offset:-2px}
.kind-lone-deviator{background:#d7f5d7} .kind-minority{background:#fff3cd}
.kind-even-split{background:#ffe0b2} .kind-multi-way{background:#f0f0f0}
.kind-partial-coverage{background:#e3e8f0}
.legend span{display:inline-block;padding:2px 8px;margin:2px;border:1px solid #ccc;border-radius:3px}
.sub{color:#888;font-size:11px} .stage{background:#222;color:#fff;font-weight:600;text-align:left}
code{background:#f4f4f4;padding:1px 4px;border-radius:3px}
details{margin:0} details>summary{cursor:pointer;list-style:none;font-family:ui-monospace,Menlo,monospace}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"\\25b8 ";color:#888}
details[open]>summary::before{content:"\\25be ";color:#888}
.desc{font-family:-apple-system,Segoe UI,sans-serif;white-space:normal;color:#333;
  background:#fafafa;border-left:3px solid #ccc;padding:6px 10px;margin:6px 0;max-width:760px;font-size:12px}
.desc .meta{color:#888;font-size:11px;margin-bottom:4px}
.desc pre{white-space:pre-wrap;font-size:11px;color:#555;margin:6px 0 0}
"""


def _details(summary_html: str, body_html: str) -> str:
    return f"<details><summary>{summary_html}</summary><div class=desc>{body_html}</div></details>"


def render_html(results, report, leaderboard, matrix, cap_desc, fix_meta, out_path: Path):
    sdks = report["sdks"]

    def cap_label(cap):
        d = cap_desc.get(cap)
        code = f"<code>{html.escape(cap)}</code>"
        if not d:
            return code
        return _details(code, html.escape(d))

    def fix_label(fid):
        m = _fix_meta_for(fix_meta, fid)
        code = html.escape(fid)
        if not m:
            return code
        parts = []
        if m["title"]:
            parts.append(f"<b>{html.escape(m['title'])}</b>")
        meta_bits = []
        if m["spec_refs"]:
            meta_bits.append("SPEC §" + ", §".join(str(s) for s in m["spec_refs"]))
        exp = m["expects"]
        if exp.get("exit_code") is not None:
            meta_bits.append(f"expect exit {exp['exit_code']}")
        if exp.get("rejection_code"):
            rc = exp["rejection_code"]
            meta_bits.append("allowed: " + ", ".join(rc if isinstance(rc, list) else [rc]))
        if m["fixture_kind"]:
            meta_bits.append(m["fixture_kind"])
        if meta_bits:
            parts.append(f"<div class=meta>{html.escape(' · '.join(meta_bits))}</div>")
        if m["notes"]:
            parts.append(f"<pre>{html.escape(m['notes'])}</pre>")
        return _details(code, "".join(parts))
    L = []
    A = L.append
    A(f"<!doctype html><meta charset=utf-8><title>Conformance homogenization report</title><style>{CSS}</style>")
    A("<h1>Cross-SDK conformance — homogenization targets</h1>")

    # summary
    A("<h2>Summary</h2><table><tr><th class=row>SDK</th><th>pass</th><th>fail</th><th>skip</th><th>error</th></tr>")
    for s in sdks:
        t = report["summary"][s]
        A(f"<tr><td class=row>{s}</td><td>{t.get('pass',0)}</td><td>{t.get('fail',0)}</td>"
          f"<td>{t.get('skip',0)}</td><td>{t.get('error',0)}</td></tr>")
    A("</table>")

    # leaderboard
    A("<h2>Gap leaderboard — pick targets here</h2>")
    A("<div class=legend><span class=kind-lone-deviator>lone-deviator = quick win (fix 1 SDK)</span>"
      "<span class=kind-minority>minority = bring few into line</span>"
      "<span class=kind-even-split>even-split = needs SPEC decision</span>"
      "<span class=kind-multi-way>multi-way = lib differences</span>"
      "<span class=kind-partial-coverage>partial-coverage = flag only exposed by some SDKs (feature gap)</span></div>")
    A("<table><tr><th class=row>Capability</th><th>stage</th><th>type</th><th>deviating</th><th>consensus</th><th>off-consensus SDK(s)</th></tr>")
    for r in leaderboard:
        devs = ", ".join(f"{s}={_fmt(v)}" for s, v in r["deviators"].items())
        A(f"<tr class=kind-{r['kind']}><td class=row>{cap_label(r['capability'])}</td>"
          f"<td>{r['stage']}</td><td>{r['kind']}</td><td>{r['n_deviating']}/{r['n_declared']}</td>"
          f"<td>{_fmt(r['consensus'])}</td><td class=row>{html.escape(devs)}</td></tr>")
    A("</table>")

    # capability heatmap grouped by stage
    A("<h2>Capability matrix (heatmap)</h2>")
    A("<p class=sub>Green = on cross-SDK consensus, red = off-consensus gap, grey = not declared.</p>")
    A("<table><tr><th class=row>Capability</th>" + "".join(f"<th>{s}</th>" for s in sdks) + "</tr>")
    _, cap_rows = _capability_matrix(results["sdks"])
    by_stage = defaultdict(list)
    for cap in cap_rows:
        by_stage[_stage_of(cap)].append(cap)
    consensus = {r["capability"]: _canon(r["consensus"]) for r in leaderboard}
    for stage in ["sigstore", "attestation-sev", "attestation-tdx", "measurement", "global"]:
        caps = sorted(by_stage.get(stage, []))
        if not caps:
            continue
        A(f"<tr><td class=stage colspan={len(sdks)+1}>{stage}</td></tr>")
        for cap in caps:
            row = cap_rows[cap]
            cons = consensus.get(cap)
            tds = []
            for s in sdks:
                v = row.get(s)
                if v is None:
                    tds.append("<td class=absent>—</td>")
                elif cap not in consensus:
                    tds.append(f"<td class=yes>{_fmt(v)}</td>")  # uniform
                elif _canon(v) == cons:
                    tds.append(f"<td class=yes>{_fmt(v)}</td>")
                else:
                    tds.append(f"<td class=no>{_fmt(v)}</td>")
            A(f"<tr><td class=row>{cap_label(cap)}</td>" + "".join(tds) + "</tr>")
    A("</table>")

    # per-test behavior matrix
    n_beh = sum(1 for m in matrix if m["divergence"] == "behavior")
    n_code = sum(1 for m in matrix if m["divergence"] == "code")
    A(f"<h2>Per-test behavior matrix <span class=sub>"
      f"({n_beh} behavior · {n_code} rejection-code divergences)</span></h2>")
    A("<p class=sub>What each SDK actually did. "
      "<b style='border-left:4px solid #d48806;padding-left:6px'>Orange (solid)</b> = behavior split "
      "(some accept, some reject/error — substantive). "
      "<b style='border-left:4px dashed #1890ff;padding-left:6px'>Blue (dashed)</b> = rejection-code split "
      "(all reject, but with different taxonomy codes); the blue-outlined cell is the odd one out. "
      "Both can happen even when all 'pass'. Hover a skip for its reason.</p>")
    A("<table><tr><th class=row>Fixture</th>" + "".join(f"<th>{s}</th>" for s in sdks) + "</tr>")
    cur = None
    for m in matrix:
        if m["stage"] != cur:
            cur = m["stage"]
            A(f"<tr><td class=stage colspan={len(sdks)+1}>{cur}</td></tr>")
        rowcls = f" class=div-{m['divergence']}" if m["divergence"] else ""
        # For code-divergence rows, outline the minority-code cell(s) so the
        # odd-one-out SDK pops without over-marking the whole row.
        minority = set()
        if m["divergence"] == "code":
            ran = [lbl for (lbl, cls, _) in m["cells"].values() if cls not in ("absent", "skip")]
            top = Counter(ran).most_common(1)[0][0] if ran else None
            minority = {lbl for lbl in ran if lbl != top}
        tds = []
        for s in sdks:
            label, cls, reason = m["cells"][s]
            extra = " codediv" if label in minority and cls not in ("absent", "skip") else ""
            title = f' title="{html.escape(reason)}"' if reason else ""
            tds.append(f'<td class="{cls}{extra}"{title}>{html.escape(label)}</td>')
        A(f"<tr{rowcls}><td class=row>{fix_label(m['fixture'])}</td>" + "".join(tds) + "</tr>")
    A("</table>")
    out_path.write_text("".join(L))


def _fmt(v):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, dict)):
        return html.escape(json.dumps(v))
    return html.escape(str(v))


def render_markdown(results, report, leaderboard, cap_desc, out_path: Path):
    sdks = report["sdks"]
    L = ["# Cross-SDK conformance — homogenization report", ""]
    L += ["## Summary", "", "| SDK | pass | fail | skip | error |", "|---|--:|--:|--:|--:|"]
    for s in sdks:
        t = report["summary"][s]
        L.append(f"| `{s}` | {t.get('pass',0)} | {t.get('fail',0)} | {t.get('skip',0)} | {t.get('error',0)} |")
    L += ["", "## Gap leaderboard (pick targets here)", "",
          "Ranked easiest-first. **lone-deviator** = one SDK off consensus (quick win); "
          "**minority** = a few off; **even-split** = needs a SPEC decision; **multi-way** = lib differences.", "",
          "| # | Capability | stage | type | deviating | consensus | off-consensus |",
          "|--:|---|---|---|:--:|---|---|"]
    for i, r in enumerate(leaderboard, 1):
        devs = ", ".join(f"`{s}`={_md(v)}" for s, v in r["deviators"].items())
        L.append(f"| {i} | `{r['capability']}` | {r['stage']} | {r['kind']} | "
                 f"{r['n_deviating']}/{r['n_declared']} | {_md(r['consensus'])} | {devs} |")
    # rejection-code splits
    L += ["", "## Rejection-code divergences (taxonomy splits — SPEC clarification targets)", ""]
    rd = report["rejection_code_divergences"]
    if rd:
        L += ["| Fixture | allowed | " + " | ".join(f"`{s}`" for s in sdks) + " |",
              "|---|---|" + "|".join(["---"] * len(sdks)) + "|"]
        for d in rd:
            allowed = ", ".join(d.get("allowed") or []) or "—"
            cells = " | ".join(d["emitted"].get(s, "—") for s in sdks)
            L.append(f"| `{d['fixture']}` | {allowed} | {cells} |")
    else:
        L.append("_None._")
    # skip causes (condensed: counts not full fixture lists)
    L += ["", "## Skip causes (capability gaps, fixture counts)", "",
          "| Gate | " + " | ".join(f"`{s}`" for s in sdks) + " |",
          "|---|" + "|".join(["--:"] * len(sdks)) + "|"]
    for c in report["skip_causes"]:
        cells = " | ".join(str(len(c["by_sdk"].get(s, []))) or "" for s in sdks)
        L.append(f"| `{c['cap']}` | {cells} |")
    # glossary — what each divergent capability (and its enum values) means.
    # Uses GitHub-flavored <details> so it stays collapsed until clicked.
    L += ["", "## Glossary — what each divergent capability means", ""]
    for r in leaderboard:
        cap = r["capability"]
        d = cap_desc.get(cap)
        if not d:
            continue
        L.append(f"<details><summary><code>{cap}</code></summary>\n\n{d}\n\n</details>")
    out_path.write_text("\n".join(L) + "\n")


def _md(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    return str(v)


def write_matrix_csv(matrix, sdks, fix_meta, out_path: Path):
    with out_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["fixture", "title", "stage", "divergence"] + sdks)
        for m in matrix:
            meta = _fix_meta_for(fix_meta, m["fixture"]) or {}
            title = " ".join((meta.get("title") or "").split())
            row = [m["fixture"], title, m["stage"], m["divergence"]]
            for s in sdks:
                label, cls, reason = m["cells"][s]
                row.append(f"{label}" + (f" ({reason})" if cls == "skip" and reason else ""))
            w.writerow(row)


def write_gaps_csv(leaderboard, out_path: Path):
    with out_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["capability", "stage", "kind", "n_deviating", "n_declared", "consensus", "deviators"])
        for r in leaderboard:
            w.writerow([r["capability"], r["stage"], r["kind"], r["n_deviating"], r["n_declared"],
                        _md(r["consensus"]), "; ".join(f"{s}={_md(v)}" for s, v in r["deviators"].items())])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results/latest/results.json", type=Path)
    ap.add_argument("--vectors", default="vectors", type=Path)
    ap.add_argument("--schema", default="schemas/capabilities.schema.json", type=Path)
    ap.add_argument("--out", default="results/latest/report", type=Path)
    a = ap.parse_args()

    results = json.loads(a.results.read_text())
    report = analyze(a.results, a.vectors)
    leaderboard = build_leaderboard(report)
    matrix = build_matrix(results)
    sdks = report["sdks"]
    cap_desc = load_cap_descriptions(a.schema)
    fix_meta = load_fixture_meta(a.vectors)

    a.out.mkdir(parents=True, exist_ok=True)
    render_html(results, report, leaderboard, matrix, cap_desc, fix_meta, a.out / "report.html")
    render_markdown(results, report, leaderboard, cap_desc, a.out / "report.md")
    write_matrix_csv(matrix, sdks, fix_meta, a.out / "matrix.csv")
    write_gaps_csv(leaderboard, a.out / "gaps.csv")
    (a.out / "gaps.json").write_text(json.dumps(leaderboard, indent=2))
    (a.out / "report.json").write_text(json.dumps(report, indent=2))

    n_lone = sum(1 for r in leaderboard if r["kind"] == "lone-deviator")
    n_beh = sum(1 for m in matrix if m["divergence"] == "behavior")
    n_code = sum(1 for m in matrix if m["divergence"] == "code")
    print(f"Wrote artifacts to {a.out}/")
    for f in ["report.html", "report.md", "matrix.csv", "gaps.csv", "gaps.json", "report.json"]:
        print(f"  {a.out / f}")
    print(f"\n{len(leaderboard)} divergent capabilities — {n_lone} are lone-deviator quick wins.")
    print(f"Per-test: {n_beh} behavior divergences, {n_code} rejection-code divergences.")


if __name__ == "__main__":
    main()
