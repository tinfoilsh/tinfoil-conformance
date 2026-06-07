# tinfoil-conformance

Cross-SDK conformance test suite for [Tinfoil](https://tinfoil.sh) attestation verification.

This repo is the **executable form** of the Tinfoil Attestation Verification Specification (see [`sdk-flywheel/SPEC.md`](https://github.com/tinfoilsh/sdk-flywheel) v1.2, Section 5 for the Sigstore stage covered first). Each verification stage in the SPEC corresponds to a subcommand in a small CLI contract; each requirement (`MUST` / `SHOULD`) corresponds to one or more test vectors that pass or fail on a per-SDK basis.

The goal is to make cross-SDK compliance **measurable** rather than judged by code review.

## Status

Work in progress. v0.1 covers the Sigstore stage.

## Design

* **One contract, many SDKs.** Each SDK ships a `tinfoil-conformance` binary that speaks the JSON-in / JSON-out protocol defined in `schemas/`. The harness in this repo spawns those binaries.
* **Hermetic.** Bundles, trust roots and verification time are all supplied as inputs.
* **Capability-aware.** SDKs declare missing features via `capabilities`; the harness skips fixtures that require unimplemented knobs and records the skip.
* **Spec-anchored.** Every fixture cites a SPEC section; every rejection code maps to a SPEC clause.

## Repository layout

```
schemas/                JSON Schemas (draft 2020-12) for each subcommand's I/O
vectors/                Test fixtures, grouped by stage
  sigstore/             Sigstore stage (SPEC §5)
  …                     attestation-sev, attestation-tdx, measurement,
                        tls-pinning, cert-binding, ehbp (planned)
harness/                Python test runner: spawns SDK binaries, diffs JSON
fixturegen/             (Planned) Synthetic-bundle generator for crafted fixtures
.github/workflows/      Reusable workflows each SDK repo can call
```

## The CLI contract (v0.1)

Each SDK's binary implements:

```
tinfoil-conformance capabilities                       # no stdin
tinfoil-conformance verify-sigstore < input.json       # stdin = JSON, stdout = JSON
```

Exit codes:

| Code | Meaning |
|---|---|
| `0`  | Verification accepted; `outputs` populated |
| `10` | Verification rejected; `rejection.code` from the taxonomy |
| `20` | Stage or required capability not supported by this SDK |
| `30` | Malformed input (schema violation, decode failure) |
| `1`  | Internal / unexpected error |

The full per-subcommand schemas live in `schemas/`. `stderr` is free-form human diagnostics — never parsed by the harness.

## Running the harness locally

### 1) Build each SDK's `tinfoil-conformance` binary

Each SDK ships the conformance CLI under its native ecosystem's build
tool. Run the one(s) you have checked out:

```bash
# Rust (tinfoil-rs)
cd /path/to/tinfoil-rs
cargo build --release --bin tinfoil-conformance
# → target/release/tinfoil-conformance

# JavaScript (tinfoil-js)
cd /path/to/tinfoil-js
npm ci && npm run build -w @tinfoilsh/verifier && npm run build -w @tinfoilsh/conformance
# → packages/conformance/dist/cli.js  (invoke via `node …`)

# Python (tinfoil-python)
cd /path/to/tinfoil-python
uv sync          # or: python -m venv .venv && pip install -e .
# → .venv/bin/tinfoil-conformance  (or: `uv run tinfoil-conformance`)

# Go (tinfoil-go)
cd /path/to/tinfoil-go
go build -o bin/tinfoil-conformance ./cmd/tinfoil-conformance/
# → bin/tinfoil-conformance
```

### 2) Install the harness and run

```bash
pip install ./harness

tinfoil-conformance run \
  --sdk tinfoil-rs=/path/to/tinfoil-rs/target/release/tinfoil-conformance \
  --sdk "tinfoil-js=node /path/to/tinfoil-js/packages/conformance/dist/cli.js" \
  --sdk tinfoil-py=/path/to/tinfoil-python/.venv/bin/tinfoil-conformance \
  --sdk tinfoil-go=/path/to/tinfoil-go/bin/tinfoil-conformance \
  --vectors vectors/sigstore/
```

For TDX, add `--tdx-public-api-variants` to keep the adapter/lower-level
fixture and also run a `::public_api` variant through the SDK's whole verifier
entrypoint with only external dependencies hooked. The harness only auto-adds
public variants for fixtures whose expected failure is valid before production
policy/collateral gates. Deeper collateral and policy-pin cases stay adapter
fixtures unless the manifest opts in with `public_api_variant: true` or the
fixture is already authored for `execution_mode: public_api`.

You can register any subset of SDKs. Each `--sdk name=cmd` registers
one binary; `cmd` is split on whitespace, so commands with arguments
(like `node script.js` or `uv run --no-sync tinfoil-conformance`) work
when quoted as a single string.

### 3) Inspect results

```bash
cat results/latest/results.md
```

### 4) Surface cross-SDK divergences

```bash
tinfoil-conformance divergence            # markdown, paste-into-PR friendly
tinfoil-conformance divergence --json     # machine-readable
```

Auto-generated digest of the three things this suite is designed to
expose:

* **Capability divergences** — flags where SDKs disagree (false on a
  single SDK = candidate real gap; multi-way splits = honest lib
  differences).
* **Rejection-code divergences** — fixtures where SDKs emit different
  but each-allowed codes from the manifest's `rejection_code` list.
  Pure SPEC taxonomy ambiguity.
* **Skip causes** — per-capability matrix of which SDK skipped which
  fixture, so the gating pattern is visible at a glance.

Pure transform on `results/latest/results.json` — no SDK invocation, no
fixture re-running.

## Adding a new fixture

Each fixture is a directory under `vectors/<stage>/`:

```
NNN-short-description/
├── manifest.yaml      Title, spec_refs, expected exit + rejection code, capabilities required
├── input.json         Piped to the SDK binary on stdin (matches the input schema)
├── expected.json      Canonical output for the harness to diff against
├── files/             Optional binary inputs referenced by input.json
└── README.md          (Optional) human-readable rationale
```

See `vectors/sigstore/001-happy-path-snp-tdx-multiplatform/` for a template.

## Adding a new SDK

1. Create a `tinfoil-conformance` binary in your SDK that implements the subcommands in `schemas/`.
2. Add a CI workflow (see [CI wiring](#ci-wiring) below).
3. Open a PR to this repo registering your SDK in `harness/sdks.toml` (planned).

## CI wiring

Each SDK ships its own self-contained workflow that builds the SDK's
`tinfoil-conformance` binary, checks out this repo, and runs the harness.
There is intentionally **no** cross-repo reusable workflow — the build step is
SDK-specific (cargo vs npm vs pip), and inline workflows are easier to debug
and don't require artifact passing between jobs.

See the canonical implementations:

* [`tinfoil-rs/.github/workflows/tinfoil-conformance.yml`](https://github.com/tinfoilsh/tinfoil-rs/blob/main/.github/workflows/tinfoil-conformance.yml)
* [`tinfoil-js/.github/workflows/tinfoil-conformance.yml`](https://github.com/tinfoilsh/tinfoil-js/blob/main/.github/workflows/tinfoil-conformance.yml)

The pattern, in steps:

1. Checkout your SDK (`actions/checkout`).
2. Set up the SDK's toolchain (rustup / setup-node / setup-python).
3. Build the SDK's `tinfoil-conformance` binary.
4. Checkout this repo into a subdirectory: `repository: lsd-cat/tinfoil-conformance`.
5. Set up Python 3.12, install the harness: `pip install ./tinfoil-conformance/harness`.
6. Run `tinfoil-conformance run --sdk <name>=<binary-path> --vectors tinfoil-conformance/vectors/sigstore`.
7. Upload `results/` as an artifact (`if: always()`) and append `results/latest/results.md` to `$GITHUB_STEP_SUMMARY`.

The exit code of `tinfoil-conformance run` is non-zero if any fixture failed
or errored, so the job will fail naturally. Skips (capability-gated fixtures)
do not fail the job.

## Relationship to upstream sigstore-conformance

The [upstream sigstore-conformance](https://github.com/sigstore/sigstore-conformance) suite tests generic Sigstore-spec compliance (a `verify-bundle` / `sign-bundle` CLI). Some Tinfoil SDKs (currently tinfoil-rs) ship a binary for that suite separately. **This repo is distinct**: it tests the Tinfoil-specific policy layer that sits on top of Sigstore — GitHub Actions OIDC identity pinning, in-toto subject-digest binding to the release artifact, predicate-type allowlists, plus the SEV/TDX/TLS/EHBP stages that aren't part of Sigstore at all.

A fully conformant Tinfoil SDK passes both suites.
