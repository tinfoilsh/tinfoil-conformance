"""Emit results.json (machine-readable) and results.md (human dashboard)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .runner import FixtureResult, SdkRegistration


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
