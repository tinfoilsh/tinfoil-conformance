# Conformance Adapter Specification — v1.1.0

The normative contract a tinfoil SDK implements to be driven by the shared v3
conformance suite. An SDK that passes the suite under this contract rejects
under the same conditions, for the same reasons, and yields the same verified
facts as every other conforming SDK.

Keywords MUST / MUST NOT / SHOULD are RFC 2119. The JSON Schemas in
[`schemas/v3/`](../schemas/v3/) are authoritative for all wire shapes and
enums; this document defines the semantics. Reference implementation:
`tinfoil-go` `cmd/tinfoil-conformance` (built with `-tags tinfoil_conformance`).
Companion normative spec: [SDK_SURFACE_SPEC.md](SDK_SURFACE_SPEC.md) — the
public API surface an SDK exposes and the rule that the full-verify stage and
`live-verify` consume it. Informative companions:
[V3_CONFORMANCE_HARNESS_SPEC.md](V3_CONFORMANCE_HARNESS_SPEC.md)
(rule→stage map), [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) (coverage matrix).

Versioning: this contract is frozen at **1.0.0**. Additive, backward-compatible
changes (new optional Input/expected fields, new stages) bump the minor;
anything an existing adapter would break on bumps the major. `Input.schema_version`
stays `"1"` for all 1.x.

## 1. Invocation

Each SDK ships an executable (any language) invoked as:

```
tinfoil-conformance <stage>        # Input JSON on stdin → Output JSON on stdout
tinfoil-conformance capabilities   # capabilities JSON on stdout, exit 0
```

**Exit codes are the verdict** (stdout is diagnostic/derived data):

| code | meaning |
|---|---|
| 0  | accepted; `outputs` populated |
| 10 | rejected; `rejection` populated |
| 20 | stage or capability not supported by this SDK |
| 30 | input did not parse (bad JSON / base64 / hex / pairing) |
| 1  | internal adapter error |

## 2. Stages

An adapter MUST implement `verify-attestation-v3`; the block stages are
RECOMMENDED (they localize failures but add no reach):

| stage | semantics |
|---|---|
| `verify-attestation-v3` | full flow: envelope check → code + platform provenance **with their freshness proofs** → quote authenticate → policy assemble + validate |
| `v3-check-envelope` | strict parse + nonce equality + endorsed-section hashes + report_data ladder only |
| `v3-authenticate-provenance` | sigstore-code bundle: identity, digest, predicate → code measurement |
| `v3-assemble-policy` | sigstore-platform bundle → endorsements artifact (fail-closed parse) |
| `v3-authenticate-quote` | CPU quote signature chain to the vendor root (no policy comparison) |

Unimplemented stages MUST exit 20 (never 1 or a wrong verdict).

## 3. Input semantics

Shape: [`input.schema.json`](../schemas/v3/input.schema.json). Beyond the shape:

- **Trust-root injection.** `amd_root_ca_pem`+`ask_pem` (both or neither),
  `intel_sgx_root_pem`, `sigstore_trusted_root_json_b64` replace the SDK's
  embedded production anchors for this run only. An **absent/empty field
  selects the embedded production root** — that is how embedded-root and
  real-frozen fixtures exercise the true production path. Root injection MUST
  NOT be reachable through the SDK's public production API (gate it: build
  tag, adapter-only parameter, or equivalent).
- **`verification_time_unix`** pins the verification clock — collateral
  validity windows (CRL `thisUpdate`/`nextUpdate`, certificate validity at the
  quote layer) **and** the freshness appraisal time. `0`/absent = current
  time. Sigstore bundle verification itself is unaffected (it uses the
  bundle's own observer timestamps).
- `nonce_hex` is the *verifier's* nonce. The adapter MUST use it — never the
  document's echoed nonce — as the expected value.
- `schema_version` MUST equal `"1"`; anything else is malformed (exit 30).
- When a document carries more than one reference-values entry of the same
  format (distinct ids — duplicate ids already reject at parse), the **first**
  entry in collateral order is used.

## 4. Output semantics

Shape: [`output.schema.json`](../schemas/v3/output.schema.json). Exactly one of
`outputs` / `rejection`.

**On accept**, `outputs` MUST carry the verified facts: `code_digest`,
`code_measurement` and `enclave_measurement` (each `{type, registers}` with
registers in canonical order, lowercase hex), and the endorsed channel keys
`tls_public_key_fp` / `hpke_public_key`. On `verify-attestation-v3` both keys
are REQUIRED: a document that verifies but endorses no usable `tls` (spki-fp)
and `hpke` (x25519) crypto-material entry MUST reject with `ENVELOPE_REJECTED` —
every real client would fail such a document at channel binding. When a
fixture's `expected` declares any of these, the suite asserts byte-exact
equality — an adapter that accepts but yields a different digest, a
mis-ordered/mis-typed register set, or the wrong channel key is
**non-conformant**.

**On reject**, `rejection.code` MUST be one of the closed taxonomy, attributed
to the *verification step that failed* (never derived by matching error
strings):

| code | layer |
|---|---|
| `ENVELOPE_REJECTED` | document parse/shape, nonce equality, endorsed-section hashes, report_data ladder |
| `PROVENANCE_REJECTED` | a Sigstore artifact (code, platform, or **freshness witness**) failed authentication: chain, SCT, tlog, observer timestamp, identity, subject digest, predicate parse, tag/commit extraction, freshness window |
| `QUOTE_REJECTED` | the hardware quote is not authentic: signature/chain/collateral/vendor structure |
| `POLICY_REJECTED` | the quote is authentic but fails the endorsed policy/identity/shape comparison |
| `MALFORMED_INPUT` | the adapter input itself did not parse (exit 30) |

The QUOTE/POLICY boundary is normative: not-authentic vs
authentic-but-noncompliant. Fixture `expected.code` values are assigned from
the spec matrix, never recorded from an implementation.

## 5. Freshness

Since v3 requires per-artifact freshness (#109), a conforming adapter MUST
verify, inside `verify-attestation-v3`: the `code-freshness` and
`platform-freshness` reference-values entries exist, each is a DSSE bundle
signed under the freshness-witness identity, endorses exactly the
authenticated artifact (repo/tag/commit/subject/digest), and its earliest
transparency-log timestamp is within **MaxFreshnessAge = 7 days** (future skew
≤ 5 minutes) of the appraisal time (§3). All freshness failures are
`PROVENANCE_REJECTED`.

## 6. Capabilities

Shape: [`capabilities.schema.json`](../schemas/v3/capabilities.schema.json).
Declares `stages_supported`, `synthetic_roots` (which vendor roots the adapter
can inject), `freshness_enforced` (true for any SDK on the current v3
verifier). The suite uses capabilities to gate fixtures; behavioral divergence
is expressed as a capability, never as a tolerated failing fixture.

## 7. Integration lane (v1.1)

The fixture stages prove the *verifier*; the integration lane proves the SDK
**as applications consume it** — the public production entry point, embedded
roots, current time, no injection seams.

- **`live-verify`** (SHOULD): `tinfoil-conformance live-verify` reads
  `{"host": "...", "repo": "..."}` on stdin, fetches a fresh attestation with a
  fresh random nonce, verifies it through the SDK's **public API** (never the
  adapter's composed flow or injected seams), and emits the standard Output
  (all accept facts) plus, when the platform can inspect the transport,
  `outputs.channel_binding: "tls-spki"` after asserting the live connection's
  SPKI SHA-256 fingerprint equals the endorsed `tls_public_key_fp`. Platforms
  that bind via EHBP/HPKE instead declare `channel_binding: "hpke"` semantics
  in capabilities. Exit codes as §1.
- The runner's `--live host,repo` mode drives every adapter's `live-verify`
  and **deep-compares the emitted facts across SDKs** — the live analogue of
  the fixture-level output-equivalence oracle.
- Capabilities declare `"live_verify": true|false` and
  `"channel_binding": "tls-spki"|"hpke"|"none"`.
- **capture** (SHOULD): a subcommand that fetches a live enclave's v3
  attestation, verifies it against the embedded production roots, and — only
  if accepted — freezes it as a fixture pinned to its capture time
  (`verification_time_unix`).

## 8. Running the suite

```
python3 tools/validate_suite.py                                  # fixtures + matrix gate
python3 tools/run_adapter.py --adapter "<cmd>" [--dirs a,b,...]  # drive any adapter
```

`run_adapter.py` asserts, per fixture: the verdict (exit code + `accepted`),
the declared `expected.code`, and every declared accept fact. An adapter is
conforming at a given suite revision when it passes all fixtures its
capabilities cover.
