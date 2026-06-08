"""Cross-SDK divergence analysis.

Reads a results.json (produced by `tinfoil-conformance run`) and surfaces the
three classes of cross-SDK divergence the suite is designed to expose:

  1. Rejection-code divergences — fixtures whose `rejection.code` is a list
     (in manifest.yaml) and where the SDKs emit different (but all-allowed)
     codes from that list. Each divergent fixture is a documented taxonomy
     split worth knowing about.

  2. Capability divergences — capability flags where at least one SDK
     declares a different value from the others. Maps to "real SPEC-
     compliance gap" candidates (flag=false on one SDK only) and "lib
     design choices" (multiple SDKs split).

  3. Skip matrix — per-fixture × per-SDK skip reasons, so the gating
     pattern is visible at a glance.

The output is markdown by default (paste into a PR or release note) or
JSON with --json. No SDK invocation, no fixture running — pure transform on
results.json + sdks[].capabilities.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


def _flatten(cap: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested capability tree into dotted-path leaves.

    Lists and primitive values are leaves. We don't dive into dict-of-dict
    further than the keys themselves — capability bags are 1-2 levels deep
    in practice."""
    out: dict[str, Any] = {}
    if isinstance(cap, dict):
        for k, v in cap.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(_flatten(v, path))
            else:
                out[path] = v
    return out


def _capability_matrix(
    sdks: list[dict[str, Any]],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """Returns (sdk_names, {capability_path: {sdk_name: value}}).
    Skips the bookkeeping fields (schema_version, sdk, sdk_version, known_quirks)
    that aren't actually capability declarations."""
    skip_top_keys = {"schema_version", "sdk", "sdk_version", "known_quirks"}
    names = [s["name"] for s in sdks]
    rows: dict[str, dict[str, Any]] = defaultdict(dict)
    for s in sdks:
        flat = _flatten(
            {k: v for k, v in (s.get("capabilities") or {}).items() if k not in skip_top_keys}
        )
        for k, v in flat.items():
            rows[k][s["name"]] = v
    return names, rows


def _fixture_codes_from_manifests(
    vectors_root: Path,
) -> dict[str, list[str] | str | None]:
    """Walk vectors/.../manifest.yaml and return {fixture_id: rejection_code}
    where rejection_code may be a list (taxonomy-split fixture) or a single
    string or None (accept-path fixture)."""
    out: dict[str, list[str] | str | None] = {}
    for m_path in vectors_root.rglob("manifest.yaml"):
        try:
            m = yaml.safe_load(m_path.read_text())
        except Exception:
            continue
        fid = m.get("id") or m_path.parent.name
        rel = str(m_path.parent.relative_to(vectors_root))
        code = (m.get("expects") or {}).get("rejection_code")
        out[fid] = code
        out[rel] = code
    return out


def _base_fixture_id(fid: str) -> str:
    return fid.split("::", 1)[0]


def analyze(
    results_path: Path, vectors_root: Path | None = None
) -> dict[str, Any]:
    """Returns the structured divergence report."""
    r = json.loads(results_path.read_text())
    sdk_names = [s["name"] for s in r["sdks"]]

    # --- Summary tally ----------------------------------------------------
    tally: dict[str, Counter] = {n: Counter() for n in sdk_names}
    for fx in r["fixtures"]:
        for n in sdk_names:
            res = fx["results"].get(n)
            if res:
                tally[n][res["status"]] += 1

    # --- Capability divergences ------------------------------------------
    _, cap_rows = _capability_matrix(r["sdks"])
    cap_divergent: dict[str, dict[str, Any]] = {}
    for k, by_sdk in sorted(cap_rows.items()):
        vals = list(by_sdk.values())
        # serialize non-hashable values (dict/list) for set comparison
        canon = {json.dumps(v, sort_keys=True) for v in vals}
        if len(canon) > 1:
            cap_divergent[k] = by_sdk

    # --- Rejection-code divergences --------------------------------------
    # For each fixture whose manifest accepts a LIST of rejection codes,
    # collect the code each SDK emitted (parse SDK's stdout body to extract).
    # If at least two SDKs emit different codes, it's a documented divergence.
    fix_codes = (
        _fixture_codes_from_manifests(vectors_root)
        if vectors_root is not None
        else {}
    )

    rejection_div: list[dict[str, Any]] = []
    for fx in r["fixtures"]:
        fid = fx["id"]
        per_sdk: dict[str, str] = {}
        for n in sdk_names:
            res = fx["results"].get(n) or {}
            body = res.get("body") or {}
            code = (body.get("rejection") or {}).get("code")
            if code:
                per_sdk[n] = code
        if len(set(per_sdk.values())) > 1:
            base_fid = _base_fixture_id(fid)
            # fixture-ids stored in results.json are paths
            # ("sigstore/021-..."); manifest lookup keys on the basename too.
            allowed = (
                fix_codes.get(base_fid)
                or fix_codes.get(base_fid.rsplit("/", 1)[-1])
            )
            rejection_div.append({
                "fixture": fid,
                "allowed": allowed,
                "emitted": per_sdk,
            })

    # --- Skip matrix -----------------------------------------------------
    skip_rows: list[dict[str, Any]] = []
    for fx in r["fixtures"]:
        per_sdk: dict[str, str] = {}
        any_skip = False
        for n in sdk_names:
            res = fx["results"].get(n) or {}
            if res.get("status") == "skip":
                any_skip = True
                per_sdk[n] = res.get("reason") or "(no reason given)"
            else:
                per_sdk[n] = ""
        if any_skip:
            skip_rows.append({"fixture": fx["id"], "by_sdk": per_sdk})

    # --- Skip-cause aggregation -----------------------------------------
    # Group skip reasons by their root cause (capability path) so the
    # "why does X skip" question has a 1-line answer per capability.
    cap_to_fixtures: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for row in skip_rows:
        for sdk, reason in row["by_sdk"].items():
            if not reason:
                continue
            # Reasons formatted by runner as:
            #   "capability 'X' = Y, fixture wants Z"
            #   "stage 'X' not in SDK capabilities.stages_supported"
            if reason.startswith("capability '"):
                path = reason.split("'")[1]
            elif reason.startswith("stage '"):
                path = "stages_supported(" + reason.split("'")[1] + ")"
            else:
                path = reason.split(":")[0]
            cap_to_fixtures[(path, sdk)].append((row["fixture"], reason))

    skip_causes: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for (path, sdk), lst in sorted(cap_to_fixtures.items()):
        if path not in seen_paths:
            skip_causes.append({"cap": path, "by_sdk": {}})
            seen_paths.add(path)
    for cause in skip_causes:
        for sdk in sdk_names:
            ff = [f for (f, _) in cap_to_fixtures.get((cause["cap"], sdk), [])]
            cause["by_sdk"][sdk] = ff

    return {
        "sdks": sdk_names,
        "summary": {n: dict(c) for n, c in tally.items()},
        "capability_divergences": cap_divergent,
        "rejection_code_divergences": rejection_div,
        "skip_matrix": skip_rows,
        "skip_causes": skip_causes,
    }


def _fmt_cell(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "`true`" if v else "`false`"
    if isinstance(v, (list, dict)):
        return f"`{json.dumps(v, separators=(',', ':'))}`"
    return f"`{v}`"


def render_markdown(report: dict[str, Any]) -> str:
    sdks = report["sdks"]
    lines: list[str] = []
    lines.append("# Cross-SDK divergence report")
    lines.append("")
    lines.append("Auto-generated from `results.json` by `tinfoil-conformance divergence`.")
    lines.append("")

    # --- Summary --------------------------------------------------------
    lines.append("## Summary")
    lines.append("")
    lines.append("| SDK | pass | fail | skip | error |")
    lines.append("|" + "|".join(["---", "---:", "---:", "---:", "---:"]) + "|")
    for n in sdks:
        t = report["summary"].get(n, {})
        lines.append(
            f"| `{n}` | {t.get('pass', 0)} | {t.get('fail', 0)} | "
            f"{t.get('skip', 0)} | {t.get('error', 0)} |"
        )
    lines.append("")

    # --- Capability divergences ----------------------------------------
    cap = report["capability_divergences"]
    lines.append(f"## Capability divergences ({len(cap)})")
    lines.append("")
    lines.append(
        "Capability flags where at least one SDK declares a value different "
        "from the others. False on a single SDK = candidate real gap; multi-way "
        "splits often indicate honest lib-design differences."
    )
    lines.append("")
    if cap:
        lines.append("| Capability | " + " | ".join(f"`{n}`" for n in sdks) + " |")
        lines.append("|" + "|".join(["---"] * (1 + len(sdks))) + "|")
        for k in sorted(cap):
            row = cap[k]
            lines.append(
                f"| `{k}` | "
                + " | ".join(_fmt_cell(row.get(n)) for n in sdks)
                + " |"
            )
    else:
        lines.append("_All SDKs agree on every capability flag._")
    lines.append("")

    # --- Rejection-code divergences ------------------------------------
    rdiv = report["rejection_code_divergences"]
    lines.append(f"## Rejection-code divergences ({len(rdiv)})")
    lines.append("")
    lines.append(
        "Fixtures where the SDKs emit different (but each individually allowed) "
        "rejection codes. The manifest's `rejection_code` list documents which "
        "codes are accepted; the per-SDK column shows which one each actually emitted. "
        "Pure taxonomy ambiguity in the SPEC — not bugs."
    )
    lines.append("")
    if rdiv:
        lines.append("| Fixture | Allowed (manifest) | " + " | ".join(f"`{n}`" for n in sdks) + " |")
        lines.append("|" + "|".join(["---"] * (2 + len(sdks))) + "|")
        for row in rdiv:
            allowed = row.get("allowed")
            allowed_str = (
                ", ".join(f"`{c}`" for c in allowed)
                if isinstance(allowed, list)
                else (f"`{allowed}`" if allowed else "—")
            )
            cells = []
            for n in sdks:
                code = row["emitted"].get(n)
                cells.append(f"`{code}`" if code else "—")
            lines.append(f"| `{row['fixture']}` | {allowed_str} | " + " | ".join(cells) + " |")
    else:
        lines.append("_No rejection-code divergences in this run._")
    lines.append("")

    # --- Skip causes ---------------------------------------------------
    causes = report["skip_causes"]
    lines.append(f"## Skip causes ({len(causes)})")
    lines.append("")
    lines.append(
        "Each row is a capability (or stage) that gates fixtures; cells list the "
        "fixtures that skipped because that capability was unsupported. Empty = "
        "the SDK declares it supported (no skip)."
    )
    lines.append("")
    if causes:
        lines.append("| Gate | " + " | ".join(f"`{n}`" for n in sdks) + " |")
        lines.append("|" + "|".join(["---"] * (1 + len(sdks))) + "|")
        for c in causes:
            cells = []
            for n in sdks:
                ff = c["by_sdk"].get(n) or []
                cells.append(
                    ("<br>".join(f"`{f}`" for f in ff)) if ff else "—"
                )
            lines.append(f"| `{c['cap']}` | " + " | ".join(cells) + " |")
    else:
        lines.append("_No skips in this run._")
    lines.append("")

    # --- TL;DR ---------------------------------------------------------
    lines.append("## TL;DR")
    lines.append("")
    lines.append(f"- **{len(cap)}** capability flags where SDKs disagree")
    lines.append(f"- **{len(rdiv)}** fixtures with rejection-code taxonomy splits")
    sum_fail = sum(t.get('fail', 0) for t in report['summary'].values())
    sum_skip = sum(t.get('skip', 0) for t in report['summary'].values())
    sum_pass = sum(t.get('pass', 0) for t in report['summary'].values())
    cells_total = sum_pass + sum_fail + sum_skip
    lines.append(
        f"- **{cells_total}** total cells: **{sum_pass} pass** / "
        f"**{sum_skip} skip** / **{sum_fail} fail**"
    )
    lines.append("")
    return "\n".join(lines)
