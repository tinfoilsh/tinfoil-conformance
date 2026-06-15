"""tinfoil-conformance CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import runner
from .divergence import analyze, render_markdown
from .report import write_markdown, write_results_json


def cmd_run(args: argparse.Namespace) -> int:
    sdks = [runner.parse_sdk_spec(s) for s in args.sdk]
    for sdk in sdks:
        try:
            sdk.capabilities = runner.load_sdk_capabilities(sdk)
        except Exception as e:
            print(f"ERROR: {sdk.name}: cannot load capabilities: {e}", file=sys.stderr)
            return 2

    fixtures = runner.discover_fixture_cases(
        Path(args.vectors),
        public_api_variants=args.public_api_variants,
    )
    if not fixtures:
        print(f"No fixtures found under {args.vectors}", file=sys.stderr)
        return 2

    print(f"Running {len(fixtures)} fixture(s) against {len(sdks)} SDK(s)...",
          file=sys.stderr)

    results: dict[str, dict[str, runner.FixtureResult]] = {}
    for fix in fixtures:
        key = fix.id
        results[key] = {}
        for sdk in sdks:
            r = runner.run_fixture(
                fix.fixture_dir,
                sdk,
                execution_mode=fix.execution_mode,
            )
            results[key][sdk.name] = r
            sym = {"pass": "✓", "fail": "✗", "skip": "·", "error": "!"}[r.status]
            print(f"  [{sdk.name:14s}] {sym} {key}", file=sys.stderr)

    out_dir = Path(args.output_dir) / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    write_results_json(out_dir / "results.json", sdks, results)
    write_markdown(out_dir / "results.md", sdks, results, vectors_root=args.vectors)
    latest = Path(args.output_dir) / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(out_dir.name)
    print(f"\nWrote {out_dir}/results.{{json,md}}", file=sys.stderr)

    any_fail = any(
        r.status in ("fail", "error")
        for per_sdk in results.values()
        for r in per_sdk.values()
    )
    return 1 if any_fail else 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    """Convenience: invoke an SDK binary's capabilities subcommand and pretty-print."""
    sdk = runner.parse_sdk_spec(args.sdk)
    caps = runner.load_sdk_capabilities(sdk)
    json.dump(caps, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def cmd_divergence(args: argparse.Namespace) -> int:
    """Analyze a results.json and surface cross-SDK divergences.

    Pure transform — no SDK invocation, no fixture running. Reads
    `results/latest/results.json` by default; pass `--results` to point at a
    specific run. Output is markdown (default, paste-into-PR friendly) or
    machine-readable JSON with `--json`."""
    results_path = args.results or (Path("results") / "latest" / "results.json")
    if not results_path.exists():
        print(f"results.json not found at {results_path}", file=sys.stderr)
        return 2
    vectors_root = args.vectors  # may be None — rejection-code allowed-list lookup is best-effort
    report = analyze(results_path, vectors_root=vectors_root)
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True, default=str)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tinfoil-conformance",
                                description="Cross-SDK conformance test runner")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="Run vectors against one or more SDK binaries")
    pr.add_argument("--sdk", action="append", required=True, metavar="NAME=CMD",
                    help="Repeat per SDK. CMD may include spaces (quote it).")
    pr.add_argument("--vectors", required=True, type=Path,
                    help="Path to vectors directory (recursive).")
    pr.add_argument("--output-dir", default="results", type=Path)
    pr.add_argument(
        "--public-api-variants",
        "--tdx-public-api-variants",  # back-compat alias (was TDX-only)
        dest="public_api_variants",
        action="store_true",
        help=(
            "For attestation adapter fixtures (verify-attestation-tdx and "
            "verify-attestation-sev), also run a '::public_api' variant with "
            "execution_mode=public_api. This keeps lower-level adapter coverage "
            "while exercising compatible pre-policy fixtures through the whole "
            "verifier entrypoint with only external dependencies hooked."
        ),
    )
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("capabilities", help="Dump one SDK's capabilities JSON")
    pc.add_argument("--sdk", required=True, metavar="NAME=CMD")
    pc.set_defaults(func=cmd_capabilities)

    pd = sub.add_parser(
        "divergence",
        help="Analyze a results.json and surface cross-SDK divergences "
             "(capability flags, rejection codes, skip causes).",
    )
    pd.add_argument(
        "--results", type=Path, default=None,
        help="Path to results.json (default: results/latest/results.json).",
    )
    pd.add_argument(
        "--vectors", type=Path, default=Path("vectors"),
        help="Path to vectors directory — used to look up each fixture's "
             "allowed rejection_code list. Best-effort; omit if vectors aren't local.",
    )
    pd.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of markdown.",
    )
    pd.set_defaults(func=cmd_divergence)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
