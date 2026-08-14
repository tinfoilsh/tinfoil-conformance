# V3 Conformance Harness Spec

> The language-neutral contract every SDK's v3 conformance adapter implements,
> and the 1:1 map from v3 spec rules to the harness stages that reach them.
> Companions: [V3_CONFORMANCE_INTERFACE.md](V3_CONFORMANCE_INTERFACE.md) (block
> design), [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) (the authoritative
> 121-rule matrix). Reference implementation: `tinfoil-go`
> `cmd/tinfoil-conformance` + `verifier/conformance` (built `-tags
> tinfoil_conformance`).
>
> Machine-checkable contract: [`schemas/v3/`](../schemas/v3/) (JSON Schema for
> Input / Output / capabilities / fixture — the enums here are authoritative).
> [`tools/validate_suite.py`](../tools/validate_suite.py) validates every fixture
> against those schemas and asserts the matrix is 121/121 accounted-for; it and
> the go harness run on every push via `.github/workflows/v3-conformance.yml`.

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
tinfoil-conformance capture -host <enclave> -repo <owner/name> [-out f.json]
                                 # fetch a live v3 attestation and freeze it as a real-frozen fixture
```

The **`capture`** subcommand is the real-frozen lane, the one path synthetic
fixtures cannot reach: it fetches a live enclave's v3 attestation, verifies it
against the **embedded production roots** (empty anchors), and — only if it
accepts — writes a fixture pinned to that capture time via
`verification_time_unix`, so it replays offline forever. The result is the
cross-SDK accept oracle: every SDK must accept the same real bytes. The first is
`vectors/v3/real-frozen/real-sev-inference-tinfoil.json`, from the live SEV-SNP
enclave `inference.tinfoil.sh` (repo `tinfoilsh/confidential-model-router`).

Each SDK SHOULD also ship an opt-in live check that fetches and verifies a real
enclave directly (skipped by default, so runs stay offline). The Go harness's is
`TestLiveVerification` (`TINFOIL_LIVE_HOST` / `TINFOIL_LIVE_REPO`), which also
replays the fetched document at a pinned time — the same contract, on live
collateral.

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
  "sigstore_trusted_root_json_b64": "<base64 Sigstore trusted-root JSON, optional>",
  "verification_time_unix": 0
}
```

`verification_time_unix` (optional, seconds since the epoch) pins the **quote-layer
clock** used for CRL and certificate validity windows, so a **frozen real
document** replays at its capture time deterministically forever; absent/0 means
verify at the current time. Sigstore verification is unaffected — it uses the
bundle's own observer timestamps. Every SDK that runs real-frozen fixtures must
honour this pin: verifying such a document at wall-clock time would spuriously
reject it once its collateral windows lapse.

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

**Rejection codes** are a **closed, layer-tagged taxonomy** and are **asserted**
(not merely diagnostic): a reject fixture declares the code it expects and the
suite checks both the verdict *and* the code. This is what makes SDK clients fail
the *same way* — they must agree not just on accept/reject but on *which layer*
rejected.

| code | layer | meaning |
|---|---|---|
| `ENVELOPE_REJECTED` | B1 | document parse/shape, nonce equality, endorsed-section hashes, REPORT_DATA ladder |
| `PROVENANCE_REJECTED` | B2 | a Sigstore reference-values bundle (code or platform) failed to authenticate — signature chain, SCT, tlog, observer timestamp, pinned identity, subject[0] digest |
| `QUOTE_REJECTED` | B3 | the hardware quote failed **authentication** — signature/chain/collateral/vendor-structure; the quote is **not authentic** |
| `POLICY_REJECTED` | B4 | the quote is authentic but fails the endorsed **policy/identity/shape**, or the platform-endorsements artifact fails to parse (machines map, named policies, shape resolution, SEV/TDX field comparison) |
| `MALFORMED_INPUT` | — | the input did not parse (exit 30) |

Two rules make this implementation-independent:

1. **`expected.code` is the target rule's spec layer**, assigned by the fixture
   author from the matrix (SPEC_COVERAGE_V3.md block column) — **never** recorded
   from an implementation's output. Otherwise the suite would standardize one
   verifier's quirks (e.g. its check ordering) rather than the spec.
2. **Adapters emit the code by attributing the rejection to the failing
   verification *step*** — envelope-check → authenticate-provenance →
   authenticate-quote → assemble/validate — not by parsing error strings. The
   `QUOTE` vs `POLICY` boundary (quote-not-authentic vs authentic-but-noncompliant)
   is the security-relevant distinction and falls out of *which step* returned the
   error. This obliges every SDK's verifier to attribute rejections to these
   layers — the price, and the point, of consistent client error behavior.

Per-stage: a block stage emits the code for its block; `verify-attestation-v3`
attributes by the failing step. A fixture whose *actual* rejection layer differs
from its *spec-assigned* code is a real signal — a mistagged fixture or a genuine
divergence — and fails the suite.

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
| SPEC_V3 §2.1 strict parsing (E1–E13); §4 REPORT_DATA ladder + nonce/section-hash binding (E14–E17); crypto_material / device_evidence | `E1–E17` | `v3-check-envelope` | reject (one violation) + accept (well-formed base) |
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
