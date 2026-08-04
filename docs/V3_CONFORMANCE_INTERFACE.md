# V3 Conformance Interface (DRAFT)

> Branch `feat/v3-conformance`. The cross-SDK contract the v3 conformance suite drives.
> Companion to [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) (the rule burn-down).

## Principle: the stages *are* the architecture blocks

`VERIFICATION_ARCHITECTURE.md` decomposes verification into six blocks (B1–B6) and is
explicit that **each block's trust anchor is a parameter, not part of its definition**.
The existing v2 suite already stumbled into this shape (`verify-sigstore`≈B2,
`verify-attestation-sev/tdx`≈B3, `verify-ehbp-key-binding`≈B6, `verify-full`≈B1–B6). v3
makes it clean and total: one conformance **stage per block**, each with its trust
anchors as first-class JSON inputs, plus the intermediate *verified facts* as typed I/O
so the policy phases can be exercised in isolation.

The payoff is homogenization by construction: **porting a new SDK = implementing the
same block adapters against the same vectors.** `CONFORMANCE.md §5` already sketches the
SDK-side shapes (R1 `AssembledPolicy`, R2 `QuoteVerifier`, R3 `QuoteValidator`,
R4 `EndorsementVerifier`, R5 shared strict-JSON); this document turns them into the
harness wire contract.

## Transport (unchanged from the v2 harness)

JSON on stdin → JSON on stdout, one subcommand per stage. Exit codes:
`0` accept · `10` reject (`rejection.code` set) · `20` stage/capability unsupported ·
`30` malformed input · `1` internal error. Every input carries `"schema_version": "1"`.
Output envelope is the existing `oneOf`: `{stage, accepted:true, outputs:{…}}` **or**
`{stage, accepted:false, rejection:{code, spec_ref}}`.

## Stages

Reference verbs are the exported `tinfoil-go feat/v3` functions each stage wraps.

### B1 · `v3-check-envelope` — local consistency (authenticates nothing)
Wraps `envelope.Check`. **No trust anchor.**
```
in : { schema_version, document_b64, expected_nonce_hex }
out: { outputs: { report_data_hex, crypto_material_hash_hex, device_evidence_hash_hex,
                  cpu_evidence_format, collateral_ids: [ … ] } }
rej: ENVELOPE_*  (strict-parse: unknown/duplicate member, non-canonical base64,
                  bad hex/length, invalid UTF-8, trailing data; nonce mismatch;
                  hash/ladder mismatch)
```

### B2 · `v3-authenticate-provenance` — transparency-log endorsement
Wraps `provenance.NewClientFromJSON(...).AuthenticateCode|AuthenticateEndorsements`.
**Anchor: Sigstore trusted root — injectable today (zero prod change).**
```
in : { schema_version, kind: "code"|"platform", bundle_json_b64, pinned_repo,
       expected_digest_hex,
       sigstore_trusted_root_json_b64?   # omitted → embedded production root }
out(code)    : { outputs: { measurement:{type,registers}, vm_shape } }
out(platform): { outputs: { policy_artifact_json } }
rej: PROVENANCE_*  (identity/SAN/issuer/runner mismatch, legacy bundle shape,
                    non-single DSSE sig, missing SCT/tlog/observer-ts, duplicate SCT
                    log-id, subject[0] digest mismatch, predicate-type mismatch)
```

### B3 · `v3-authenticate-quote` — CPU quote authenticity (no policy comparison)
Wraps `quote.Authenticate` → `sev.Authenticate`/`tdx.Authenticate`.
**Anchors: AMD product root + Intel SGX root.** Injectable only after the additive
`WithTrustedRoot` option lands on `sev`/`tdx` `Authenticate` (see *Anchor injection*).
Until then this stage runs against the **embedded real roots** — sufficient for accept
(real frozen docs) and signature/structural rejects (mutated real quote), not for
validly-signed-but-wrong-policy rejects.
```
in : { schema_version, document_b64,
       amd_root_ca_pem?, ask_pem?, intel_sgx_root_pem?,   # synthetic anchors
       verification_time_unix? }
out: { outputs: <AuthenticatedQuote> }        # see Verified-fact wire formats
rej: QUOTE_*  (chain-to-root failure, revocation, unsupported format/version,
               reserved/trailing bytes non-zero, report_data binding)
```

### B4a · `v3-assemble-policy` — assemble the complete expected state (pure)
Wraps `quote.Assemble` (`policy.PolicyFor` + shape-filtered `ResolvePlatformMeasurement`).
**No anchor** — consumes verified facts only.
```
in : { schema_version, policy_artifact_json, authenticated_quote: <AuthenticatedQuote>,
       code_measurement:{type,registers}, vm_shape, report_data_hex }
out: { outputs: <AssembledPolicy> }
rej: IDENTITY_*   (machine absent from map, platform≠evidence kind)
     STRUCTURAL_* (no shape-satisfying candidate, >1 or 0 measurement resolution)
     POLICY_*     (missing required member, unknown member, unmappable block)
```

### B4b · `v3-validate-quote` — total strict-equality comparison (pure)
Wraps `(*AssembledPolicy).Validate`. **No anchor.**
```
in : { schema_version, authenticated_quote: <AuthenticatedQuote>,
       assembled_policy: <AssembledPolicy> }
out: { outputs: { ok: true } }
rej: QUOTE_POLICY_*  (guest_policy/platform_info bit mismatch, TCB floor, measurement,
                      report_data, td_attributes/xfam, mr_seam, signer state, vmpl, …)
```

### B6 · `v3-bind-channel` — key endorsement + channel binding
Wraps the `client.VerifyV3` binding section. **No anchor.**
```
in : { schema_version, crypto_material_json,
       channel: { kind:"tls", spki_der_b64 } | { kind:"hpke", hpke_pub_hex } }
out: { outputs: { bound_id: "tls"|"hpke" } }
rej: BINDING_*  (key not endorsed, id/format mismatch, fingerprint mismatch)
```

### full · `v3-verify` — end-to-end composition (B1→B6)
Wraps `client.VerifyDocumentV3`. Optional synthetic anchors as in B2/B3.
```
in : { schema_version, document_b64, expected_nonce_hex, pinned_repo,
       sigstore_trusted_root_json_b64?, amd_root_ca_pem?, ask_pem?, intel_sgx_root_pem?,
       verification_time_unix? }
out: { outputs: { code_digest, code_measurement:{type,registers},
                  enclave_measurement:{type,registers}, crypto_material:[{id,format,data}] } }
rej: { code, spec_ref, failed_stage }   # first failing block
```

## Enforcement-class → stage (coverage is total against `POLICY_VALIDATION §1`)

`POLICY_VALIDATION.md` assigns every quote field exactly one of 8 enforcement classes
("a field without a row is a conformance bug"). Each class has a stage that exercises it,
so every field is testable and no class is orphaned:

| Class | What it means | Stage that exercises it |
|---|---|---|
| policy | strict-equality vs the assembled policy | `v3-validate-quote` |
| code | measurement from verified provenance | `v3-authenticate-provenance` (emit) → `v3-validate-quote` (compare) |
| envelope | recomputed REPORT_DATA ladder | `v3-check-envelope` (compute) → `v3-validate-quote` (compare) |
| identity | machines-map lookup key | `v3-assemble-policy` |
| vendor | vendor library vs vendor-signed collateral | `v3-authenticate-quote` |
| structural | implied by signature / strict parse | `v3-authenticate-quote` · `v3-check-envelope` |
| sdk | hardcoded invariant (pinned-zero, no author key) | `v3-validate-quote` |
| unchecked | no expected value — assert it is *not* enforced | negative-assertion fixtures on `v3-verify` |

Ambiguous/underspecified rules (`SPEC_COVERAGE_V3` `AM*`) get no fixture until resolved
as Phase-3 spec-questions.

## Verified-fact wire formats

The typed facts blocks pass to each other, serialized so B4a/B4b are testable without
valid signatures. Every SDK must be able to **emit** them (from B3/B4a) and **consume**
them (into B4a/B4b) — this is the homogenization forcing function; an SDK that can't is
gated by `v3.intermediate_facts=false` and only runs the composed stages.

```
<AuthenticatedQuote> = {
  platform: "sev-snp"|"tdx",
  identity_hex,                       # SEV 64-byte CHIP_ID | TDX 16-byte PPID
  launch_measurement: {type, registers},
  report_data_hex,                    # 64 bytes
  config: { … platform-specific authenticated fields … }   # guest_policy/platform_info/tcb (SEV); mrtd/rtmrs/td_attributes/xfam/mr_seam/tcb (TDX)
}

<AssembledPolicy> = {
  platform, identity_hex, expected_report_data_hex,
  expected_launch_measurement: {type, registers},
  fields: { … one expected value per policy-relevant field … },
  floors: { … TCB floors — the one sanctioned non-equality comparison … }
}
```

## Anchor injection

| Anchor | Stage | Status | Mechanism |
|---|---|---|---|
| Sigstore trusted root | B2, full | ✅ injectable now | `provenance.NewClientFromJSON(json)` |
| AMD product root (+ASK) | B3, full | ⏳ needs option | additive `sev.WithTrustedRoot(...)` (~20 LOC) |
| Intel SGX root | B3, full | ⏳ needs option | additive `tdx.WithTrustedRoot(...)` (~20 LOC) |

The AMD/Intel options are **additive, non-breaking, and spec-aligning**: `VERIFICATION_
ARCHITECTURE §1` mandates anchors-as-parameters and `provenance` already complies. This
is the same seam **every** SDK needs, so it belongs in the interface, not as a go hack.
Zero-change coverage (real frozen docs + mutated-quote signature rejects + Sigstore-
injected provenance rejects) proceeds without it; the option unlocks the validly-signed-
but-wrong-policy reject matrix (the highest-value SEV/TDX exact-equality rows). Gated by
capability `v3.synthetic_vendor_roots`.

## Rejection taxonomy

Layer-prefixed, one code + `spec_ref` per reject fixture:
`ENVELOPE_* · PROVENANCE_* · QUOTE_* · QUOTE_POLICY_* · IDENTITY_* · POLICY_* ·
STRUCTURAL_* · BINDING_* · FRESHNESS_*`. The prefix names the block that must fire, so a
single full-`v3-verify` fixture localizes its failure the same way an isolated block
fixture does. Codes are enumerated per-rule in `SPEC_COVERAGE_V3.md`.

## Capabilities (declared by `tinfoil-conformance capabilities`)

```
v3: {
  supported: bool,
  stages_supported: [ "v3-check-envelope", "v3-authenticate-provenance",
                      "v3-authenticate-quote", "v3-assemble-policy",
                      "v3-validate-quote", "v3-bind-channel", "v3-verify" ],
  synthetic_sigstore_root: bool,     # can inject a test Fulcio/Rekor root (go: yes)
  synthetic_vendor_roots:  bool,     # can inject test AMD/Intel roots (go: after option)
  intermediate_facts:      bool,     # can emit/consume AuthenticatedQuote/AssembledPolicy
  freshness_enforced:      bool,     # false today everywhere (pilot deferred)
  device_appraisal:        bool,     # false today everywhere (B5 unimplemented)
  accepts_non_terminal_tcb_statuses: bool   # go(tdx): true — over-strict divergence
}
```

Fixtures declare `required_capabilities` (dotted paths) so an SDK cleanly skips
(exit `20`) what it can't run. Known divergences are expressed as capability gates, never
as failing fixtures.

## Porting a new SDK (Phase C, later)

1. Implement the seven `v3-*` subcommands mapping to the SDK's block verbs.
2. Expose the two anchor-injection seams (Sigstore + vendor roots) — the same additive
   shape as go.
3. Emit/consume the verified-fact wire formats (or declare `intermediate_facts=false`).
4. Declare capabilities; run the shared vectors. Any unmappable field blocks the port
   (fail-closed homogenization rule).

## Assumptions (override if wrong)

- **Reference = `feat/v3`**, pinned. If `pr/assembled-policy` (options-only) lands, the
  SEV `QUOTE_POLICY_*` rows correctly flag its exact-equality regression.
- **Coexist with v2**; retire each SDK's v2 fixtures only when it lands v3.
- **Extend `tinfoil-conformance`** (this harness); fold the spec's `v3/testdata`
  per-rule intent into these stages rather than forking a parallel corpus.
