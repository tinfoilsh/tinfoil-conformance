"""tinfoil-conformance CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import runner
from .report import write_markdown, write_results_json


def cmd_run(args: argparse.Namespace) -> int:
    sdks = [runner.parse_sdk_spec(s) for s in args.sdk]
    for sdk in sdks:
        try:
            sdk.capabilities = runner.load_sdk_capabilities(sdk)
        except Exception as e:
            print(f"ERROR: {sdk.name}: cannot load capabilities: {e}", file=sys.stderr)
            return 2

    fixtures = runner.discover_fixtures(Path(args.vectors))
    if not fixtures:
        print(f"No fixtures found under {args.vectors}", file=sys.stderr)
        return 2

    print(f"Running {len(fixtures)} fixture(s) against {len(sdks)} SDK(s)...",
          file=sys.stderr)

    results: dict[str, dict[str, runner.FixtureResult]] = {}
    for fix in fixtures:
        key = str(fix.relative_to(args.vectors))
        results[key] = {}
        for sdk in sdks:
            r = runner.run_fixture(fix, sdk)
            results[key][sdk.name] = r
            sym = {"pass": "✓", "fail": "✗", "skip": "·", "error": "!"}[r.status]
            print(f"  [{sdk.name:14s}] {sym} {key}", file=sys.stderr)

    out_dir = Path(args.output_dir) / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    write_results_json(out_dir / "results.json", sdks, results)
    write_markdown(out_dir / "results.md", sdks, results)
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
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("capabilities", help="Dump one SDK's capabilities JSON")
    pc.add_argument("--sdk", required=True, metavar="NAME=CMD")
    pc.set_defaults(func=cmd_capabilities)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
