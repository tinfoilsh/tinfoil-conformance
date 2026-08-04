# V3 Conformance Harness Spec

> The language-neutral contract every SDK's v3 conformance adapter implements,
> and the 1:1 map from v3 spec rules to the harness stages that reach them.
> Companions: [V3_CONFORMANCE_INTERFACE.md](V3_CONFORMANCE_INTERFACE.md) (block
> design), [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) (the authoritative
> 117-rule matrix). Reference implementation: `tinfoil-go`
> `cmd/tinfoil-conformance` + `verifier/conformance` (built `-tags
> tinfoil_conformance`).

## 1. Goal

Every normative rule in the v3 spec (SPEC_V3, POLICY_VALIDATION,
PLATFORM_ENDORSEMENTS) must be **reachable** (some harness stage exercises it)
and **testable** (a fixture asserts accept or reject for it). This document
pins the wire protocol so all SDKs are driven identically, then maps each spec
part to the stage that reaches it, so coverage is auditable and shared fixtures
verify the same bytes in every language.

## 2. Wire protocol

The suite invokes a per-SDK binary named `tinfoil-conformance`:

```
tinfoil-conformance <stage>      # Input JSON on stdin → Output JSON on stdout, exit code = verdict
tinfoil-conformance capabilities # self-description JSON on stdout, exit 0
```

**Exit codes** (the verdict; stdout is diagnostic only):

| code | meaning |
|---|---|
| 0  | accepted (Output.outputs populated) |
| 10 | rejected (Output.rejection populated) |
| 20 | stage/capability unsupported by this SDK |
| 30 | input did not parse |
| 1  | internal adapter error |

**Input** (one v3 document + the roots it was produced under; empty root fields
select the embedded production roots, so real-frozen fixtures supply none):

```json
{
  "schema_version": "1",
  "document_b64": "<base64 attestation/v3 document>",
  "nonce_hex": "<32-byte verifier nonce, lowercase hex>",
  "repo": "<pinned sigstore-code repo>",
  "amd_root_ca_pem": "<ARK PEM, optional>",
  "ask_pem": "<ASK PEM, optional; paired with amd_root_ca_pem>",
  "intel_sgx_root_pem": "<Intel SGX root PEM, optional>",
  "sigstore_trusted_root_json_b64": "<base64 Sigstore trusted-root JSON, optional>"
}
```

**Output** (exactly one of `outputs` / `rejection`):

```json
{ "stage": "verify-attestation-v3", "accepted": true,
  "outputs": { "code_digest": "…",
               "code_measurement":    { "type": "…", "registers": ["…"] },
               "enclave_measurement": { "type": "…", "registers": ["…"] } } }
```
```json
{ "stage": "verify-attestation-v3", "accepted": false,
  "rejection": { "code": "ENVELOPE_REJECTED" } }
```

**Rejection codes** are coarse and layer-tagged (`ENVELOPE_REJECTED`,
`PROVENANCE_REJECTED`, `QUOTE_REJECTED`, `MALFORMED_INPUT`). v1 of the suite
asserts pass/reject via the **exit code**; the code aids diagnosis and is stable
across SDKs at layer granularity. Per-rule codes are not required (see §5).

**Capabilities** gate which fixtures an SDK runs:

```json
{ "schema_version": "1", "sdk": "tinfoil-go",
  "v3": { "supported": true,
          "stages_supported": ["verify-attestation-v3", "v3-check-envelope"],
          "synthetic_roots": { "amd": true, "intel": true, "sigstore": true },
          "freshness_enforced": false } }
```

## 3. Stages

`verify-attestation-v3` is the **primary** stage: it runs the full flow
(envelope → provenance → quote authenticate → policy assemble/validate → bind)
and therefore **reaches every rule** — a fixture violating any rule rejects
somewhere in this flow. The block stages are optional and add *localization*
(which layer fired), not reach; an SDK advertises the ones it implements.

| stage | flow | block it isolates |
|---|---|---|
| `verify-attestation-v3` | full end-to-end | — (reaches all) |
| `v3-check-envelope` | strict parse + nonce/hash/report-data binding | B1 |
| `v3-authenticate-provenance` | sigstore-code / sigstore-platform bundles | B2 |
| `v3-authenticate-quote` | CPU quote signature chain | B3 |
| `v3-assemble-policy` | machine lookup + shape resolution | B4a |
| `v3-validate-quote` | strict-equality policy comparison | B4b |
| `v3-bind-channel` | crypto_material key binding | B6 |

## 4. Rule → stage map (1:1 with the v3 spec)

Every rule group in [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) maps to a stage;
`verify-attestation-v3` reaches all of them, the block stage localizes. Fixtures
are **accept/reject pairs with single-field mutation** (a valid base document,
one field changed to violate the rule under test).

| v3 spec part | rules | reached by (block stage) | fixture kind |
|---|---|---|---|
| SPEC_V3 §2.1 strict parsing; §4 REPORT_DATA ladder; crypto_material / device_evidence | `E1–E13` | `v3-check-envelope` | reject (one violation) + accept (well-formed base) |
| SPEC_V3 §5 + POLICY_VALIDATION provenance: identity pin, DSSE-single, SCT/tlog/observer, legacy/dup-SCT, subject[0], predicate | `P1–P16` | `v3-authenticate-provenance` | reject + accept (synthetic Sigstore root) |
| POLICY_VALIDATION §2 (AMD Table 23) + §2.1/§2.2 bits: TCB floors, guest_policy/platform_info exact, signer, vmpl, host/image/family, mitigation | `S1–S26` | `v3-authenticate-quote` (structural/vendor) · `v3-validate-quote` (policy) | reject + accept (synthetic AMD root, re-signed report) |
| POLICY_VALIDATION §3 (Intel §3.1/§3.2) + §3.3/§3.4 bits + §3.2a QE report + collateral floor | `T1–T25` | `v3-authenticate-quote` · `v3-validate-quote` | reject + accept (synthetic Intel root + collateral) |
| PLATFORM_ENDORSEMENTS machines-map: identity key, lookup-fatal, platform-match | `I1–I7` | `v3-assemble-policy` | reject (absent/mismatch) + accept |
| PLATFORM_ENDORSEMENTS policies: every-member-required, unknown-field fail-closed, unmappable block, author/id-block-must-be-false | `PL1–PL12` | `v3-assemble-policy` · `v3-validate-quote` | reject + accept |
| Shape filtering / exactly-one measurement resolution | `ST1–ST4` | `v3-assemble-policy` | reject (0 or >1) + accept |
| Channel binding (crypto_material) | (B6) | `v3-bind-channel` | reject + accept |
| Freshness (deferred; not enforced) | `FR1–FR3` | `v3-authenticate-provenance`, capability-gated `freshness_enforced=false` | probe (expected behavior once implemented) |
| Explicitly-unchecked fields | `U1–U6` | `verify-attestation-v3` | negative assertion (mutate → still accepts) |
| Ambiguous / underspecified | `AM1–AM5` | — | no fixture until resolved as a spec-question |

## 5. Fixture ↔ rule linkage and the reachability guarantee

- Each fixture declares the `RULE_ID`(s) it exercises (in its manifest) and its
  expected verdict. Because fixtures use single-field mutation from a valid
  base, a reject is attributable to the rule under test even with coarse
  rejection codes.
- A coverage report cross-checks the fixture set against
  [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md): **every non-ambiguous rule must
  have ≥1 fixture** (accept and reject where both are meaningful). 100% = the
  matrix is fully covered. Ambiguous rules are tracked as open spec-questions,
  not gaps.
- **Reachability guarantee:** every rule is reachable through
  `verify-attestation-v3`; the block stages and rejection codes only refine
  *where* a rejection occurs. An SDK that implements only `verify-attestation-v3`
  can still be driven to 100% rule coverage.

## 6. Cross-language

The protocol (§2), stages (§3), and map (§4) are identical across SDKs; only the
adapter implementation differs. Fixtures are **shared** — the same document
bytes are verified by every SDK, which is the point of the suite. Behavioral
divergences (e.g. an SDK that rejects a non-terminal TDX TcbStatus, or one
without TDX support) are expressed as **capability gates**, never as failing
fixtures, so the same fixture set runs everywhere and differences surface as
skips in the report.
