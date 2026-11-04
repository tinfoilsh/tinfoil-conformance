#!/usr/bin/env python3
"""Validate the v3 conformance suite and report coverage — the CI gate.

Two jobs, both fail-closed (non-zero exit):
  1. Structurally validate every fixture in vectors/v3/ against the fixture
     contract (schemas/v3/fixture.schema.json + input.schema.json), without an
     external jsonschema dependency: allowed stages, Input shape (the members
     each stage requires, read from the fixture schema's per-stage if/then
     rules, plus each member's type/pattern/encoding), and the accept/reject +
     code invariants (code present and in the closed taxonomy iff
     accepted=false; accept facts only on accepts).
  2. Parse the coverage matrix (docs/SPEC_COVERAGE_V3.md) and assert every rule
     is accounted for — fixtured `[x]` or documented-by-design `[~]`, zero open
     `[ ]` — then print the per-layer tally.

Run: python3 tools/validate_suite.py  (from the repo root)
"""

import base64
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors" / "v3"
MATRIX = ROOT / "docs" / "SPEC_COVERAGE_V3.md"
SCHEMAS = ROOT / "schemas" / "v3"

# The JSON Schemas are the single source of truth for the contract; load the
# enums, member specs and per-stage requirements from them so this gate can
# never drift from the published schema.
_FIXTURE = json.loads((SCHEMAS / "fixture.schema.json").read_text())
_INPUT = json.loads((SCHEMAS / "input.schema.json").read_text())
STAGES = set(_FIXTURE["properties"]["stage"]["enum"])
CODES = set(_FIXTURE["properties"]["expected"]["properties"]["code"]["enum"])
INPUT_PROPS = _INPUT["properties"]
EXPECTED_PROPS = _FIXTURE["properties"]["expected"]["properties"]
ACCEPT_FACTS = set(EXPECTED_PROPS) - {"accepted", "code"}


def _stage_input_rules():
    """{stage: (required input members, per-member spec overrides)} from the
    fixture schema's `allOf` if/then rules keyed on `stage`."""
    rules = {}
    for rule in _FIXTURE.get("allOf", []):
        cond = rule.get("if", {}).get("properties", {}).get("stage", {})
        stages = [cond["const"]] if "const" in cond else cond.get("enum", [])
        inp = rule.get("then", {}).get("properties", {}).get("input", {})
        for s in stages:
            req, over = rules.get(s, ([], {}))
            rules[s] = (req + inp.get("required", []), {**over, **inp.get("properties", {})})
    return rules


STAGE_INPUT = _stage_input_rules()


def _check_value(name, value, spec, errs):
    """Check one member against its (small, flat) JSON Schema spec."""
    if "const" in spec:
        if value != spec["const"]:
            errs.append(f"{name} != {spec['const']!r}")
        return
    t = spec.get("type")
    if t == "string":
        if not isinstance(value, str):
            errs.append(f"{name} is not a string")
            return
        if spec.get("contentEncoding") == "base64":
            try:
                base64.b64decode(value, validate=True)
            except Exception:  # noqa: BLE001
                errs.append(f"{name} is not valid base64")
        if "pattern" in spec and not re.match(spec["pattern"], value):
            errs.append(f"{name} does not match {spec['pattern']}")
    elif t == "boolean":
        if not isinstance(value, bool):
            errs.append(f"{name} is not a bool")
    elif t == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            errs.append(f"{name} is not an integer")
        elif value < spec.get("minimum", value):
            errs.append(f"{name} < {spec['minimum']}")
    elif t == "array":
        if not isinstance(value, list) or len(value) < spec.get("minItems", 0):
            errs.append(f"{name} is not an array of >= {spec.get('minItems', 0)} items")
            return
        for i, item in enumerate(value):
            _check_value(f"{name}[{i}]", item, spec.get("items", {}), errs)
    elif t == "object":
        if not isinstance(value, dict):
            errs.append(f"{name} is not an object")
        elif not spec.get("additionalProperties", True) and not set(value) <= set(spec.get("properties", {})):
            errs.append(f"{name} has unknown keys {sorted(set(value) - set(spec['properties']))}")


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
    stage = f["stage"]
    if stage not in STAGES:
        errs.append(f"unknown stage {stage!r}")
    elif stage not in STAGE_INPUT:
        errs.append(f"stage {stage!r} has no input requirement rule in fixture.schema.json")
    inp = f["input"]
    if not isinstance(inp, dict):
        errs.append("input is not an object")
        return errs
    if not set(inp) <= set(INPUT_PROPS):
        errs.append(f"input has unknown keys {sorted(set(inp) - set(INPUT_PROPS))}")
    required, overrides = STAGE_INPUT.get(stage, ([], {}))
    for key in _INPUT.get("required", []) + required:
        if key not in inp:
            errs.append(f"input.{key} missing (required for {stage})")
    for key, v in inp.items():
        if key in INPUT_PROPS:
            _check_value(f"input.{key}", v, {**INPUT_PROPS[key], **overrides.get(key, {})}, errs)
    exp = f["expected"]
    if not isinstance(exp, dict) or not set(exp) <= set(EXPECTED_PROPS):
        errs.append(f"expected has unknown keys {sorted(set(exp) - set(EXPECTED_PROPS))}")
        return errs
    for key, v in exp.items():
        _check_value(f"expected.{key}", v, EXPECTED_PROPS[key], errs)
    if not isinstance(exp.get("accepted"), bool):
        errs.append("expected.accepted missing/not a bool")
    elif exp["accepted"] and "code" in exp:
        errs.append("accept fixture must not carry a code")
    elif not exp["accepted"]:
        if ACCEPT_FACTS & set(exp):
            errs.append(f"reject fixture must not carry accept facts {sorted(ACCEPT_FACTS & set(exp))}")
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
