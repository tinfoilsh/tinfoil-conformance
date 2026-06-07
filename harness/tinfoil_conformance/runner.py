"""Vector runner: spawns SDK binaries, compares stdout JSON + exit code."""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


EXIT_ACCEPT = 0
EXIT_REJECT = 10
EXIT_UNSUPPORTED = 20
EXIT_BAD_INPUT = 30


@dataclass
class SdkRegistration:
    name: str
    binary: list[str]   # argv prefix; e.g. ["/path/to/bin"] or ["node", "/path/to/cli.js"]
    capabilities: dict[str, Any] = field(default_factory=dict)


@dataclass
class FixtureResult:
    status: str          # "pass" | "fail" | "skip" | "error"
    got_exit: int | None = None
    got_output: dict[str, Any] | None = None
    stderr_excerpt: str = ""
    reason: str = ""


def load_sdk_capabilities(sdk: SdkRegistration, timeout_s: float = 10.0) -> dict[str, Any]:
    """Invoke `<binary> capabilities` and parse JSON."""
    proc = subprocess.run(
        sdk.binary + ["capabilities"],
        capture_output=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{sdk.name}: capabilities returned exit {proc.returncode}\n"
            f"stderr: {proc.stderr.decode(errors='replace')[:400]}"
        )
    return json.loads(proc.stdout)


def required_capabilities_satisfied(
    required: dict[str, Any], have: dict[str, Any]
) -> tuple[bool, str]:
    """Each key in `required` is a dotted path into `have`.

    Scalar SDK capabilities must exactly match. List-valued SDK capabilities
    are treated as supported sets, so a scalar fixture requirement means
    membership. If the fixture requirement is itself a list, any matching value
    is sufficient.
    """
    for path, expected in required.items():
        cur: Any = have
        for segment in path.split("."):
            if not isinstance(cur, dict) or segment not in cur:
                return False, f"capability path '{path}' not declared"
            cur = cur[segment]
        if isinstance(cur, list):
            acceptable = expected if isinstance(expected, list) else [expected]
            if not any(item in cur for item in acceptable):
                return False, (
                    f"capability '{path}' = {cur!r}, fixture wants any of {acceptable!r}"
                )
        elif isinstance(expected, list):
            if cur not in expected:
                return False, (
                    f"capability '{path}' = {cur!r}, fixture wants one of {expected!r}"
                )
        elif cur != expected:
            return False, f"capability '{path}' = {cur!r}, fixture wants {expected!r}"
    return True, ""


def run_fixture(
    fixture_dir: Path, sdk: SdkRegistration, timeout_s: float = 30.0
) -> FixtureResult:
    """Run one fixture against one SDK and return the verdict."""
    manifest = yaml.safe_load((fixture_dir / "manifest.yaml").read_text())
    stage = manifest["stage"]
    expects = manifest["expects"]
    required_caps: dict[str, Any] = manifest.get("required_capabilities") or {}

    stages_supported = sdk.capabilities.get("stages_supported", []) or []
    if stage not in stages_supported:
        return FixtureResult(
            status="skip",
            reason=f"stage {stage!r} not in SDK capabilities.stages_supported",
        )

    ok, reason = required_capabilities_satisfied(required_caps, sdk.capabilities)
    if not ok:
        return FixtureResult(status="skip", reason=reason)

    stdin_bytes = (fixture_dir / "input.json").read_bytes()
    try:
        proc = subprocess.run(
            sdk.binary + [stage],
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return FixtureResult(status="error", reason=f"timeout after {timeout_s}s")

    got_exit = proc.returncode
    stderr_excerpt = proc.stderr.decode(errors="replace")[:400]
    try:
        got_output = json.loads(proc.stdout) if proc.stdout else None
    except json.JSONDecodeError as e:
        return FixtureResult(
            status="error",
            got_exit=got_exit,
            stderr_excerpt=stderr_excerpt,
            reason=f"stdout not JSON: {e}",
        )

    want_exit = int(expects["exit_code"])
    if got_exit != want_exit:
        return FixtureResult(
            status="fail",
            got_exit=got_exit,
            got_output=got_output,
            stderr_excerpt=stderr_excerpt,
            reason=f"exit {got_exit}, want {want_exit}",
        )

    if got_exit == EXIT_REJECT:
        want_code = expects.get("rejection_code")
        got_rejection = (got_output or {}).get("rejection", {})
        got_code = got_rejection.get("code")
        if want_code is not None:
            # `rejection_code` may be a single string OR a list of acceptable
            # codes. The list form is for fixtures where the underlying
            # taxonomy is genuinely ambiguous across implementations (e.g.
            # @freedomofpress/sigstore-browser can't distinguish
            # REKOR_KEY_NOT_TRUSTED from REKOR_INCLUSION_INVALID at its public
            # surface). Each list use MUST be justified in manifest.notes.
            acceptable = (
                [want_code] if isinstance(want_code, str) else list(want_code)
            )
            if got_code not in acceptable:
                return FixtureResult(
                    status="fail",
                    got_exit=got_exit,
                    got_output=got_output,
                    stderr_excerpt=stderr_excerpt,
                    reason=f"rejection.code={got_code!r}, want one of {acceptable!r}",
                )
        want_stage = expects.get("rejection_stage")
        if want_stage is not None and got_rejection.get("stage") != want_stage:
            return FixtureResult(
                status="fail",
                got_exit=got_exit,
                got_output=got_output,
                stderr_excerpt=stderr_excerpt,
                reason=(
                    f"rejection.stage={got_rejection.get('stage')!r}, "
                    f"want {want_stage!r}"
                ),
            )
        return FixtureResult(status="pass", got_exit=got_exit, got_output=got_output)

    if got_exit == EXIT_ACCEPT:
        expected_path = fixture_dir / "expected.json"
        if expected_path.exists():
            expected = json.loads(expected_path.read_text())
            diff = diff_outputs(expected.get("outputs", {}), (got_output or {}).get("outputs", {}))
            if diff:
                return FixtureResult(
                    status="fail",
                    got_exit=got_exit,
                    got_output=got_output,
                    stderr_excerpt=stderr_excerpt,
                    reason=f"outputs differ: {diff}",
                )
        return FixtureResult(status="pass", got_exit=got_exit, got_output=got_output)

    return FixtureResult(status="pass", got_exit=got_exit, got_output=got_output)


def diff_outputs(expected: dict[str, Any], got: dict[str, Any]) -> str:
    """Structural diff on whitelisted output keys. Returns '' if ok, else a description."""
    problems: list[str] = []
    for key, want in expected.items():
        if key not in got:
            problems.append(f"missing {key}")
            continue
        have = got[key]
        if isinstance(want, str) and isinstance(have, str):
            if want.lower() != have.lower():  # hex fields are case-insensitive per SPEC §7.3
                problems.append(f"{key}: {have!r} != {want!r}")
        elif want != have:
            problems.append(f"{key}: {have!r} != {want!r}")
    return "; ".join(problems)


def discover_fixtures(vectors_root: Path) -> list[Path]:
    """All directories under vectors_root that contain a manifest.yaml."""
    return sorted(
        p.parent for p in vectors_root.rglob("manifest.yaml") if p.is_file()
    )


def parse_sdk_spec(spec: str) -> SdkRegistration:
    """Parse 'name=cmd...' into an SdkRegistration. The command may have spaces."""
    if "=" not in spec:
        raise ValueError(f"--sdk expects name=command, got {spec!r}")
    name, _, cmd = spec.partition("=")
    return SdkRegistration(name=name, binary=shlex.split(cmd))
