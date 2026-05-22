"""Emit results.json (machine-readable) and results.md (human dashboard)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from .runner import FixtureResult, SdkRegistration


# All rejection codes across every verify-*.output.schema.json. The
# coverage table lists each one and which fixtures exercise it.
_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def _all_rejection_codes() -> list[str]:
    codes: list[str] = []
    for schema_path in sorted(_SCHEMAS_DIR.glob("verify-*.output.schema.json")):
        try:
            schema = json.loads(schema_path.read_text())
            codes.extend(
                schema["properties"]["rejection"]["properties"]["code"]["enum"]
            )
        except Exception:
            continue
    # Preserve first-seen order while de-duplicating.
    seen: set[str] = set()
    out: list[str] = []
    for c in codes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _fixture_code_mapping(vectors_root: Path) -> dict[str, list[str]]:
    """Walk fixture manifests and return {fixture_id: [rejection_codes]} for
    rejection fixtures (empty list for accepting fixtures)."""
    out: dict[str, list[str]] = {}
    for manifest_path in vectors_root.rglob("manifest.yaml"):
        try:
            m = yaml.safe_load(manifest_path.read_text())
        except Exception:
            continue
        fid = m.get("id") or manifest_path.parent.name
        expects = m.get("expects", {}) or {}
        code = expects.get("rejection_code")
        if code is None:
            out[fid] = []
        elif isinstance(code, str):
            out[fid] = [code]
        else:
            out[fid] = list(code)
    return out


def write_results_json(
    path: Path,
    sdks: list[SdkRegistration],
    results: dict[str, dict[str, FixtureResult]],
) -> None:
    payload: dict[str, Any] = {
        "schema": "tinfoil-conformance-results/v1",
        "sdks": [
            {"name": s.name, "capabilities": s.capabilities} for s in sdks
        ],
        "fixtures": [
            {
                "id": fix_id,
                "results": {
                    name: {
                        "status": r.status,
                        "got_exit": r.got_exit,
                        "reason": r.reason,
                    }
                    for name, r in per_sdk.items()
                },
            }
            for fix_id, per_sdk in results.items()
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def write_markdown(
    path: Path,
    sdks: list[SdkRegistration],
    results: dict[str, dict[str, FixtureResult]],
    vectors_root: Path | None = None,
) -> None:
    lines: list[str] = []
    lines.append("# Tinfoil conformance results\n")

    lines.append("## Summary\n")
    lines.append("| SDK | pass | fail | skip | error |")
    lines.append("|---|---:|---:|---:|---:|")
    for sdk in sdks:
        c: Counter[str] = Counter()
        for per_sdk in results.values():
            c[per_sdk[sdk.name].status] += 1
        lines.append(
            f"| `{sdk.name}` | {c['pass']} | {c['fail']} | {c['skip']} | {c['error']} |"
        )
    lines.append("")

    # Rejection-code coverage — shows how much of the SPEC error taxonomy is
    # exercised by at least one fixture. Codes with no fixture are visible at
    # a glance, which guides where to add tests next.
    if vectors_root is not None:
        lines.extend(_render_coverage_section(vectors_root, results, sdks))

    lines.append("## Detail\n")
    header = "| Fixture | " + " | ".join(f"`{s.name}`" for s in sdks) + " |"
    sep = "|---|" + "|".join("---" for _ in sdks) + "|"
    lines.append(header)
    lines.append(sep)
    sym = {"pass": "✓", "fail": "✗", "skip": "·", "error": "!"}
    for fix_id, per_sdk in results.items():
        cells = []
        for s in sdks:
            r = per_sdk[s.name]
            cell = sym[r.status]
            if r.status != "pass" and r.reason:
                cell += f" <sub>{r.reason}</sub>"
            cells.append(cell)
        lines.append(f"| `{fix_id}` | " + " | ".join(cells) + " |")
    lines.append("")

    path.write_text("\n".join(lines))


def _render_coverage_section(
    vectors_root: Path,
    results: dict[str, dict[str, FixtureResult]],
    sdks: list[SdkRegistration],
) -> list[str]:
    """Coverage table: for every code in the schema, which fixtures pin it
    and did each SDK emit a passing result for at least one of them."""
    lines: list[str] = []
    codes = _all_rejection_codes()
    if not codes:
        return lines
    fixture_codes = _fixture_code_mapping(vectors_root)

    # code -> list of (fixture_id, per-sdk status dict)
    by_code: dict[str, list[tuple[str, dict[str, str]]]] = defaultdict(list)
    for fid, codes_for_fix in fixture_codes.items():
        if not codes_for_fix:
            continue
        per_sdk_status = {
            sdk.name: results.get(fid, {}).get(sdk.name, FixtureResult(status="")).status
            for sdk in sdks
        }
        for c in codes_for_fix:
            by_code[c].append((fid, per_sdk_status))

    lines.append("## Rejection-code coverage\n")
    lines.append(
        "One row per code in `schemas/verify-sigstore.output.schema.json`. "
        "Codes without any fixture are listed last as gaps to fill — most "
        "require a synthetic-bundle generator (fixturegen).\n"
    )
    lines.append(
        "| Code | Fixtures pinning this code | "
        + " | ".join(f"`{s.name}`" for s in sdks)
        + " |"
    )
    lines.append("|---|---|" + "|".join("---" for _ in sdks) + "|")

    sym = {"pass": "✓", "fail": "✗", "skip": "·", "error": "!", "": " "}
    for code in codes:
        fixs = by_code.get(code, [])
        if not fixs:
            cells = ["—"] * len(sdks)
            lines.append(f"| `{code}` | _no fixture_ | " + " | ".join(cells) + " |")
            continue
        fixture_label = "<br>".join(f"`{fid}`" for fid, _ in fixs)
        # Per-SDK column: ✓ if at least one fixture passed; otherwise the
        # worst observed status.
        sdk_cells = []
        for sdk in sdks:
            statuses = [s.get(sdk.name, "") for _, s in fixs]
            if "pass" in statuses:
                sdk_cells.append(sym["pass"])
            elif "fail" in statuses:
                sdk_cells.append(sym["fail"])
            elif "error" in statuses:
                sdk_cells.append(sym["error"])
            elif "skip" in statuses:
                sdk_cells.append(sym["skip"])
            else:
                sdk_cells.append(" ")
        lines.append(
            f"| `{code}` | {fixture_label} | " + " | ".join(sdk_cells) + " |"
        )
    lines.append("")
    return lines
