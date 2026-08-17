#!/usr/bin/env python3
"""Run v3 fixtures against any conformance adapter CLI.

Usage: run_adapter.py --adapter "cmd args..." [--dirs d1,d2 | fixture.json ...]

For every fixture: pipe input JSON to `cmd <stage>`, then assert the verdict
(exit code + accepted), the declared reject code, and any declared accept facts
(code_digest, measurements, channel keys). Exit nonzero on any mismatch.
"""

import argparse
import glob
import json
import os
import subprocess
import sys

EXIT_ACCEPTED, EXIT_REJECTED, EXIT_UNSUPPORTED, EXIT_MALFORMED = 0, 10, 20, 30
FACTS = ("code_digest", "code_measurement", "enclave_measurement",
         "tls_public_key_fp", "hpke_public_key")


def run_fixture(adapter, path):
    f = json.load(open(path))
    exp = f["expected"]
    proc = subprocess.run(adapter + [f["stage"]], input=json.dumps(f["input"]).encode(),
                          capture_output=True)
    if proc.returncode == EXIT_UNSUPPORTED:
        return "SKIP", "stage unsupported"
    try:
        out = json.loads(proc.stdout)
    except (ValueError, json.JSONDecodeError):
        return "FAIL", f"no JSON output (exit {proc.returncode}); stderr: {proc.stderr[:300].decode(errors='replace')}"

    errs = []
    if exp["accepted"]:
        if proc.returncode != EXIT_ACCEPTED or not out.get("accepted"):
            errs.append(f"rejected (exit {proc.returncode}, {out.get('rejection')})")
        else:
            got = out.get("outputs") or {}
            for k in FACTS:
                if k in exp and got.get(k) != exp[k]:
                    errs.append(f"{k}: got {json.dumps(got.get(k))[:80]}, want {json.dumps(exp[k])[:80]}")
    else:
        if proc.returncode not in (EXIT_REJECTED, EXIT_MALFORMED) or out.get("accepted"):
            errs.append(f"accepted (exit {proc.returncode}), want reject {exp.get('code')}")
        elif exp.get("code") and (out.get("rejection") or {}).get("code") != exp["code"]:
            errs.append(f"code: got {(out.get('rejection') or {}).get('code')}, want {exp['code']}")
    return ("FAIL", "; ".join(errs)) if errs else ("PASS", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, help="adapter command, e.g. 'node dist/cli.js'")
    ap.add_argument("--dirs", help="comma-separated fixture dirs (default: all of vectors/v3)")
    ap.add_argument("files", nargs="*", help="individual fixture files")
    args = ap.parse_args()
    adapter = args.adapter.split()

    root = os.path.join(os.path.dirname(__file__), "..", "vectors", "v3")
    if args.files:
        groups = {"(files)": args.files}
    else:
        dirs = args.dirs.split(",") if args.dirs else sorted(os.listdir(root))
        groups = {d: sorted(glob.glob(os.path.join(root, d, "*.json"))) for d in dirs}

    total = failed = skipped = 0
    for name, files in groups.items():
        results = [(f, *run_fixture(adapter, f)) for f in files]
        npass = sum(1 for _, s, _ in results if s == "PASS")
        nskip = sum(1 for _, s, _ in results if s == "SKIP")
        nfail = len(results) - npass - nskip
        total += len(results); failed += nfail; skipped += nskip
        print(f"{name:18} {npass}/{len(results)} pass" + (f", {nskip} skip" if nskip else "") + (f", {nfail} FAIL" if nfail else ""))
        for f, s, msg in results:
            if s == "FAIL":
                print(f"  FAIL {os.path.basename(f)}: {msg}")
    print(f"\nTOTAL {total - failed - skipped}/{total} pass, {skipped} skip, {failed} fail")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
