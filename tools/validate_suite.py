#!/usr/bin/env python3
"""Validate the v3 conformance suite and report coverage — the CI gate.

Two jobs, both fail-closed (non-zero exit):
  1. Structurally validate every fixture in vectors/v3/ against the fixture
     contract (schemas/v3/fixture.schema.json), without an external jsonschema
     dependency: allowed stages, Input shape, and the accept/reject + code
     invariants (code present and in the closed taxonomy iff accepted=false).
  2. Parse the coverage matrix (docs/SPEC_COVERAGE_V3.md) and assert every rule
     is accounted for — fixtured `[x]` or documented-by-design `[~]`, zero open
     `[ ]` — then print the per-layer tally.

Run: python3 tools/validate_suite.py  (from the repo root)
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors" / "v3"
MATRIX = ROOT / "docs" / "SPEC_COVERAGE_V3.md"
SCHEMAS = ROOT / "schemas" / "v3"

# The JSON Schemas are the single source of truth for the contract; load the
# enums from them so this gate can never drift from the published schema.
_FIXTURE = json.loads((SCHEMAS / "fixture.schema.json").read_text())
_INPUT = json.loads((SCHEMAS / "input.schema.json").read_text())
STAGES = set(_FIXTURE["properties"]["stage"]["enum"])
CODES = set(_FIXTURE["properties"]["expected"]["properties"]["code"]["enum"])
INPUT_KEYS = set(_INPUT["properties"])


def validate_fixture(path):
    errs = []
    try:
        f = json.loads(path.read_text())
    except Exception as e:  # noqa: BLE001
        return [f"invalid JSON: {e}"]
    if set(f) != {"id", "stage", "input", "expected"}:
        errs.append(f"top-level keys {sorted(f)} != id/stage/input/expected")
        return errs
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", str(f["id"])):
        errs.append(f"id {f['id']!r} is not filesystem-safe")
    if f["stage"] not in STAGES:
        errs.append(f"unknown stage {f['stage']!r}")
    inp = f["input"]
    if not isinstance(inp, dict) or not set(inp) <= INPUT_KEYS:
        errs.append(f"input has unknown keys {sorted(set(inp) - INPUT_KEYS)}")
    if inp.get("schema_version") != "1":
        errs.append("input.schema_version != \"1\"")
    if not isinstance(inp.get("document_b64"), str):
        errs.append("input.document_b64 missing/not a string")
    exp = f["expected"]
    exp_keys = {"accepted", "code", "tls_public_key_fp", "hpke_public_key"}
    if not isinstance(exp, dict) or not set(exp) <= exp_keys:
        errs.append(f"expected has unknown keys {sorted(set(exp) - exp_keys)}")
    if not isinstance(exp.get("accepted"), bool):
        errs.append("expected.accepted missing/not a bool")
    elif exp["accepted"] and "code" in exp:
        errs.append("accept fixture must not carry a code")
    elif not exp["accepted"] and (exp.get("tls_public_key_fp") or exp.get("hpke_public_key")):
        errs.append("reject fixture must not carry endorsed keys")
    elif not exp["accepted"]:
        if exp.get("code") not in CODES:
            errs.append(f"reject fixture code {exp.get('code')!r} not in the taxonomy")
    return errs


def check_fixtures():
    files = sorted(VECTORS.glob("*/*.json"))
    if not files:
        return ["no fixtures found under vectors/v3/"], 0
    problems = []
    for p in files:
        for e in validate_fixture(p):
            problems.append(f"{p.relative_to(ROOT)}: {e}")
    return problems, len(files)


def check_matrix():
    text = MATRIX.read_text()
    layers = re.findall(
        r"\*\*([A-Z][A-Z /-]*?)\*\* \([^)]*\) — (\d+) rules[^\n]*\n\n((?:  `\[[ x~]\][A-Z0-9]+`[^\n]*\n)+)", text)
    rows, tot_x, tot_acc, tot_open = [], 0, 0, 0
    for name, total, block in layers:
        x = len(re.findall(r"\[x\]", block))
        acc = len(re.findall(r"\[~\]", block))
        opn = len(re.findall(r"\[ \]", block))
        tot_x += x; tot_acc += acc; tot_open += opn
        rows.append((name.strip().split(" /")[0], int(total), x, acc, opn))
    return rows, tot_x, tot_acc, tot_open


def main():
    ok = True
    problems, n = check_fixtures()
    print(f"fixtures: validated {n} against schemas/v3/fixture.schema.json")
    for p in problems:
        print(f"  FAIL {p}")
    if problems:
        ok = False

    rows, x, acc, opn = check_matrix()
    print(f"\n{'layer':<13}{'rules':>6}{'[x]':>5}{'[~]':>5}{'[ ]':>5}")
    print("-" * 39)
    for name, total, cx, ca, co in rows:
        print(f"{name:<13}{total:>6}{cx:>5}{ca:>5}{co:>5}")
    print("-" * 39)
    print(f"{'TOTAL':<13}{x + acc + opn:>6}{x:>5}{acc:>5}{opn:>5}")
    print(f"\nfixtured {x} + accounted-by-design {acc} = {x + acc}; open {opn}")
    if opn != 0:
        print(f"  FAIL: {opn} rule(s) still open ([ ])")
        ok = False

    print("\n" + ("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
