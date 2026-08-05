# V3 Conformance Roadmap — to 100% coverage, full spec, reusable interface

> The plan from the current state (envelope done, provenance happy-path proven) to
> three end states: **(1) 100% of the 121-rule matrix fixtured and green**,
> **(2) full v3 spec coverage** (every normative rule reachable + testable,
> ambiguities tracked as spec-questions), and **(3) a consolidated conformance
> interface**, frozen as a versioned spec every SDK reuses.
> Companions: [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) (the matrix),
> [V3_CONFORMANCE_HARNESS_SPEC.md](V3_CONFORMANCE_HARNESS_SPEC.md) (wire protocol),
> [V3_CONFORMANCE_TEST_PLAN.md](V3_CONFORMANCE_TEST_PLAN.md) (per-fixture plan).

## 0. Definition of done

- **Coverage:** every non-ambiguous rule has ≥1 fixture (accept + reject where both
  are meaningful); the 5 ambiguous rules are logged as open spec-questions, not gaps.
- **Reachability:** every rule is exercised by `verify-attestation-v3`; block stages
  add localization. One fully-valid "golden" document proves the end-to-end accept.
- **Interface:** the wire protocol, stage catalog, Input/Output/Capabilities schemas,
  rejection taxonomy, fixture manifest, and report format are frozen in a versioned
  `CONFORMANCE_ADAPTER_SPEC.md` and implemented identically by all 5 SDKs.

## 1. Current state

| Layer | Rules | Generator | Stage | Status |
|---|---|---|---|---|
| ENVELOPE (B1) | 17 | `gen_envelope.py` | `v3-check-envelope` | **done, green** |
| PROVENANCE (B2) | 16 | `sigstore_synth.py` | `v3-authenticate-provenance` | happy-path green; stage + mutations pending |
| QUOTE-SEV (B3) | 26 | `gen_sev.py` | `v3-authenticate-quote` / `v3-validate-quote` | not started |
| QUOTE-TDX (B3) | 25 | `gen_tdx.py` | `v3-authenticate-quote` / `v3-validate-quote` | not started |
| IDENTITY (B4a) | 7 | `gen_identity.py` | `v3-assemble-policy` | not started |
| POLICY (B4b) | 12 | `gen_policy.py` | `v3-assemble-policy` / `v3-validate-quote` | not started |
| STRUCTURAL (B4a) | 4 | `gen_policy.py` | `v3-assemble-policy` | not started |
| FRESHNESS | 3 | `gen_freshness.py` | capability-gated | not started |
| UNCHECKED | 6 | `gen_unchecked.py` | `verify-attestation-v3` | not started |
| AMBIGUOUS | 5 | — | — | tracked as spec-questions |

Foundation (anchor injection, harness skeleton, CLI, capabilities, docs) is landed on
tinfoil-go `feat/v3` (PR #104) behind the `tinfoil_conformance` build tag. Nothing is
pushed on the conformance repo yet (holding per "before pushing").

## 2. Workstream A — generators to 100% coverage

Each slice: build/extend the generator → emit shared fixtures to `vectors/v3/<layer>/`
→ green through the Go block stage → tick the matrix. Block stages keep layers testable
in isolation so generators don't serialize on each other.

### A1. Finish provenance (B2)
- Add `v3-authenticate-provenance` stage: extract the sigstore-code collateral from the
  document, call `AuthenticateCodeWithRoot(bundle, repo, digest, root)`.
- `gen_provenance.py` (wraps `sigstore_synth`): happy v3 document + **P1–P16** single-field
  mutations — wrong repo/SAN (P11/P14/P15), broken DSSE sig / non-in-toto (P9), legacy
  multi-cert bundle (P3), 0 / 2 DSSE signatures (P4), untrusted Fulcio root (P5), absent /
  bad SCT (P6), dup-SCT-log (P12), no Rekor entry (P7), timestamp outside cert window (P8),
  subject[0] mismatch (P10), wrong predicate type / missing `vm_shape` (P13), missing
  sigstore-code|platform entry (P1/P2/P16).
- **Reuse:** the platform bundle (P2/sigstore-platform) uses the *same* `sigstore_synth`
  machinery with the platform identity + a `policy.Artifact` predicate — so IDENTITY/POLICY
  slices inherit provenance for free.

### A2. SEV quote (B3, S1–S26) — largest remaining crypto lift
- Synthetic AMD root: ARK → ASK → VCEK/VLEK chain; a SEV-SNP attestation-report signer.
- Stages `v3-authenticate-quote` (chain/structural) and `v3-validate-quote` (Table-23 policy).
- **Coupling:** the report's `REPORT_DATA` must equal the envelope ladder
  `SHA256(LABEL‖nonce‖cmh‖deh)`, and `MEASUREMENT` must equal the code measurement — so
  `gen_sev` builds the envelope sections + report together. Mutations cover TCB floors,
  guest_policy/platform_info exact bits, signer, vmpl, host/image/family, mitigation,
  MEASUREMENT mismatch, VCEK vs VLEK, CRL.

### A3. TDX quote (B3, T1–T25)
- Synthetic Intel PCK CA + captured-shape PCS collateral (QE identity, TCB info); a TDX
  quote (v4/v5) signer with QE report. Same envelope/report_data coupling as SEV.
- Mutations: RTMR1/RTMR2 vs code, MRTD/RTMR0 policy, TcbStatus terminal-vs-not (capability
  gate for SDKs that reject non-terminal), QE report bind, collateral floor.

### A4. Identity + Policy + Structural (B4)
- `gen_identity.py` (I1–I7): platform-endorsements machines map — identity key, lookup-fatal,
  platform-match; accept + absent/mismatch rejects. Built on the A1 platform bundle.
- `gen_policy.py` (PL1–PL12, ST1–ST4): every-member-required, unknown-field fail-closed,
  unmappable-block, author/id-must-be-false; shape filtering / exactly-one-measurement
  (0 or >1 → reject). Stages `v3-assemble-policy` + `v3-validate-quote`.

### A5. Unchecked + Freshness (+ Ambiguous)
- `gen_unchecked.py` (U1–U6): **negative assertions** — mutate an explicitly-unchecked field
  on the golden document, assert it *still accepts* (legacy dcode SAN, cert-embedded hashes,
  well-known paths, DNS binding).
- `gen_freshness.py` (FR1–FR3): capability-gated probes (`freshness_enforced=false`); assert
  nonce-freshness enforced, collateral-expiry not enforced today.
- Ambiguous (AM1–AM5): no fixture; each filed as a spec-question issue and linked in the matrix.

### A6. Golden document + end-to-end
- Assemble ONE fully-valid v3 document (envelope + sigstore-code + sigstore-platform + a SEV
  and a TDX variant) that `verify-attestation-v3` accepts.
- Regression: feed every layer's reject fixture through `verify-attestation-v3` and confirm it
  rejects there too (reachability), and through its block stage (localization).

## 3. Workstream B — consolidate + freeze the interface

Produce `CONFORMANCE_ADAPTER_SPEC.md` v1 (promoting today's harness spec to a normative,
versioned contract), plus machine-checkable schemas under `schemas/`:

1. **Wire protocol** — `tinfoil-conformance <stage>` (stdin Input → stdout Output, exit-code
   verdict) + `capabilities`. Frozen exit codes (0/10/20/30/1).
2. **JSON Schemas** — `input.schema.json`, `output.schema.json`, `capabilities.schema.json`,
   `fixture.schema.json` (id, stage, input, expected, `rule_ids[]`). `schema_version` on every
   message; adapters reject unknown majors.
3. **Stage catalog** — canonical names + semantics for the 7 stages; a stage an SDK lacks is a
   capability skip, never a failure.
4. **Rejection taxonomy** — layer-tagged codes (`ENVELOPE_REJECTED`, `PROVENANCE_REJECTED`,
   `QUOTE_REJECTED`, `POLICY_REJECTED`, `MALFORMED_INPUT`), verdict via exit code.
5. **Capability model** — declared support (stages, synthetic roots, TDX, freshness) drives
   which fixtures run; documents legitimate divergence as skips.
6. **Report format** — `report.schema.json`: per-rule pass/skip/fail per SDK, plus a coverage
   roll-up cross-checked against the matrix (100% = every non-ambiguous rule ≥1 fixture green).
7. **Fixture layout** — `vectors/v3/<layer>/*.json` shared byte-for-byte across SDKs; a
   `manifest.json` linking fixtures ↔ rule ids for the coverage report.

## 4. Workstream C — cross-SDK rollout

For each of python / rs / js / swift: implement the adapter binary against the frozen spec
(same Input/Output/exit codes), wire in the injectable synthetic roots (per-language schema:
Go/Rust two-stage flag+forwarder, Python `_underscore`, JS internal export), run the **shared**
fixtures, and record results in the report format. Behavioral differences (e.g. non-terminal
TDX TcbStatus, no-TDX, freshness) surface as capability skips, feeding the divergence trackers
(see the SDK homogenization + SEV/Sigstore remediation notes). This is the payoff — the same
bytes verified everywhere is what makes the comparison meaningful.

## 5. Workstream D — CI + close-out

- Coverage gate: CI runs the harness over all fixtures per SDK and fails if any non-ambiguous
  rule lacks a green fixture, or the matrix and manifest disagree.
- A "real-frozen" lane: a handful of production-captured documents (empty synthetic roots →
  embedded roots) verified to accept, guarding against synthetic-only drift.
- Commit + push: tinfoil-go `feat/v3-conformance-harness`, tinfoil-conformance
  `feat/v3-conformance`; coordinate with PR #104 (force-push dismisses jdrean's approval).

## 6. Ordering, dependencies, risk

```
A1 provenance ──┬─> A4 identity/policy ──┐
                │   (reuses A1 bundle)    ├─> A6 golden doc ─> D CI/close-out
A2 SEV ─────────┤                         │
A3 TDX ─────────┘   (envelope+report_data coupling) 
B interface spec  ── can start now, frozen after A1 stabilizes the shapes
C cross-SDK       ── starts once B is frozen + A mostly green
```

- **Critical path:** A2/A3 (vendor-quote crypto) are the long poles; A2 first (AMD is the
  primary platform). A1/A4 share the Sigstore machinery and are cheaper.
- **Freeze B after A1**, not before — provenance is the richest Input; locking schemas
  earlier risks churn. Everything after B keys off the frozen contract.
- **Risks:** vendor-quote signing fidelity (mitigate with the same iterate-against-Go loop
  that cracked provenance); fixture non-determinism (generate each layer in one run, commit
  together); cross-SDK Sigstore/quote-lib quirks (express as capability skips + divergence
  entries, never silent fixture failures).

## 7. Milestones

- **M1** — provenance closed (A1): 33/121 rules, `v3-authenticate-provenance` green.
- **M2** — SEV closed (A2): ~59/121.
- **M3** — TDX + identity/policy/structural (A3, A4): ~107/121.
- **M4** — unchecked/freshness + golden doc (A5, A6): 116/116 layer-mapped, ambiguities filed
  → **100% matrix**; `CONFORMANCE_ADAPTER_SPEC.md` frozen (B).
- **M5** — cross-SDK adapters green on shared fixtures (C) + CI gate (D) → **full spec,
  reusable interface**.
