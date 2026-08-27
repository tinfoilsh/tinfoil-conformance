# SDK Surface Specification — v1.0.0

The normative **public API surface** a v3 SDK exposes. The adapter spec
([CONFORMANCE_ADAPTER_SPEC.md](CONFORMANCE_ADAPTER_SPEC.md)) pins *behavior*;
this document pins the *surface* applications program against, so SDKs stay
mutually predictable and the conformance adapter cannot test anything other
than what ships. Reference: `tinfoil-go` `verifier/` on `feat/v3`.

Keywords MUST/SHOULD are RFC 2119. Naming is language-idiomatic (Go
`VerifyDocumentV3` ⇔ JS `verifyDocumentV3` ⇔ Python `verify_document_v3`);
semantics, parameters, and error behavior are identical.

## 1. Consumption rule (what makes this conformance-relevant)

- The adapter's `verify-attestation-v3` stage and its `live-verify` command
  MUST consume the SDK **through this public surface** (plus the
  tag/build-gated injection seams for fixture roots and clocks). Deep imports
  of internal modules there are non-conformant: they let the suite pass
  against code applications cannot reach. Block stages (`v3-check-envelope`,
  …) MAY reach internal modules — isolating internal layers is their purpose.
- Each SDK MUST carry a surface test asserting these names are importable from
  the package's public entry point (compile-time in Go; an
  import-from-package-root test in dynamic languages).

## 2. Tier 1 — core verification surface (MUST)

| surface (Go form) | semantics |
|---|---|
| `VerifyDocumentV3(docBytes, nonce, repo) → VerifiedDocumentV3` | full offline verification of a v3 document: envelope check → code+platform provenance each with its freshness proof → quote authenticate → policy assemble/validate. Embedded production roots, current time. Throws/returns layer-attributable errors |
| `VerifiedDocumentV3` | carries `CodeDigest`, `CodeMeasurement`, `EnclaveMeasurement` (type + canonical registers), and the endorsed crypto material |
| `TLSPublicKeyFP(v)` / `HPKEPublicKey(v)` | recover the endorsed channel keys (`tls` spki-fp-sha256 / `hpke` x25519) from the verified document; error when absent or format-mismatched |
| `Fetch(host, nonce) → docBytes` | GET `https://<host>/.well-known/tinfoil-attestation?nonce=<hex>`; host may carry a port |
| `RandomNonce() → bytes` / `NonceSize = 32` | fresh 32-byte verifier nonce |
| the verification error type | rejections expose the layer (`ENVELOPE/PROVENANCE/QUOTE/POLICY_REJECTED`) without string matching |

## 3. Tier 2 — product client surface (SHOULD; MUST before an SDK release claims v3)

| surface (Go form) | semantics |
|---|---|
| `SecureClient.Verify()` / `VerifyV3()` | fetch + verify a live enclave and retain the ground truth |
| channel binding | every subsequent connection is bound to the endorsed key: TLS SPKI pinning where the platform can inspect the transport, EHBP/HPKE key binding otherwise (declared via `channel_binding` capability) |
| verification-document accessor | expose the verified facts to applications in the SDK's established document shape |

## 4. Change control

Surface additions bump this spec's minor version; renames/removals bump the
major and require a coordinated release across SDKs. An SDK's conformance
claim states the surface-spec version it implements.
