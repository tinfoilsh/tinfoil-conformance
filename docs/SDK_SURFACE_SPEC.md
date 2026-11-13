# SDK Surface Specification — v0.3.0

The normative **public API surface** a v3 SDK exposes. The adapter spec
([CONFORMANCE_ADAPTER_SPEC.md](CONFORMANCE_ADAPTER_SPEC.md)) pins *behavior*;
this document pins the *surface* applications program against, so SDKs stay
mutually predictable and the conformance adapter cannot test anything other
than what ships. Reference: `tinfoil-go` `main` — package `verify` (and its
`document` and `measurement` subpackages) for Tier 1, the root `tinfoil`
package for Tier 2.

Keywords MUST/SHOULD/MAY are RFC 2119. Naming is language-idiomatic (Go
`VerifyV3` ⇔ JS `verifyV3` ⇔ Python `verify_v3`; Go `ok bool` results ⇔ an
optional/undefined/None result; Go functional options ⇔ an options object or
keyword arguments); semantics, parameters, and error behavior are identical.
Go-only mechanics (contexts, `*http.Client` embedding) map to the language's
native equivalent (abort signals, the native fetch/HTTP client type).

## 1. Consumption rule (what makes this conformance-relevant)

- The adapter's `verify-attestation-v3` stage and its `live-verify` command
  MUST verify **through this public surface** — a `Verifier` built by the
  public constructor and its `VerifyV3`/`VerifyV3At` — plus the
  tag/build-gated injection seams for fixture roots. Deep imports of internal
  verification modules there are non-conformant: they let the suite pass
  against code applications cannot reach. Block stages (`v3-check-envelope`,
  …) MAY reach internal modules — isolating internal layers is their purpose.
- Fetching the attestation document is transport, not verification:
  `live-verify` MAY fetch it with an internal helper, provided the request
  matches §2.5.
- Each SDK MUST carry a surface test asserting the Tier 1 names are importable
  from the package's public entry point (compile-time in Go; an
  import-from-package-root test in dynamic languages).

## 2. Tier 1 — verification surface (MUST)

The verifier is the functional core: it opens no connections and keeps no
state between calls. Fetching documents, caching a verification and enforcing
its expiry belong to the caller (Tier 2).

### 2.1 Verifier

| surface (Go form) | semantics |
|---|---|
| `NewVerifier(opts...) → Verifier` | immutable, concurrency-safe policy. Defaults: embedded production trust roots, Tinfoil's public config and artifact signing keys, 7-day freshness bound. An option that fails is a `UsageError` |
| `Verifier.VerifyV3(docBytes, nonce, repo) → Verification` | full offline appraisal of a nonce-bound v3 document: envelope → code/config + platform provenance each with its freshness proof → quote authenticate → policy assemble/validate. `repo` pins `org/project[@revision][@sha256:digest]`. Samples the clock once; that instant judges every time-bound check |
| `Verifier.VerifyV3At(docBytes, nonce, repo, verificationTime)` | `VerifyV3` with the caller's instant replacing the clock in every time-bound check (freshness witnesses/approvals, vendor cert and CRL windows). A zero time is a `UsageError`. This is the entry the fixture stage uses |
| `Verifier.CheckRepoVerifiability(repo)` | rejects (`UsageError`) a repo pin this verifier could never accept, without a document or I/O |
| `Verifier.CallerAuthorizesConfig()` / `PinnedRegisters()` / `FreshnessMaxAge()` | read back the policy |
| `ParseReference(ref) → (repo, tag, digest)` | validates `owner/name[@tag][@sha256:digest]` |

### 2.2 Verifier options

| option (Go form) | level | semantics |
|---|---|---|
| `WithPinnedRegisters(expected)` | MUST | each set register must match the enclave: fills a register the release leaves open, must equal one it fixes; pins for one platform reject every enclave on the other |
| `WithFreshnessMaxAge(d)` | MUST | bounds witness age; zero keeps the default, negative is invalid |
| `WithConfigSigningKeys(keys)` | SHOULD | replaces public config trust; requires `attestation-collaterals/v3` |
| `WithFreshnessSigningKeys(keys)` | SHOULD | pins platform/runtime approval keys; requires `attestation-collaterals/v3` |
| `WithConfigAuthorizer(fn)` | SHOULD | caller callback replaces config endorsement verification; requires an empty repo |
| `WithEmbeddedReferences({Config, Runtime, Platform})` | SHOULD | caller-trusted reference values replace endorsement and renewal checks for the supplied components only |

### 2.3 Verification

Read-only; accessors return copies.

| accessor (Go form) | semantics |
|---|---|
| `CodeDigest()` / `CodeTag()` / `ConfigRepo()` | the verified code or runtime artifact and its repository (no version pins) |
| `CodeMeasurement() → Expected` | registers the release fixes, in the enclave platform's layout; unset for a register left to the platform |
| `EnclaveMeasurement() → Measurement` | the quote's authenticated registers |
| `TLSPublicKeyFP()` / `HPKEPublicKey()` | the endorsed channel keys (`tls` in `spki-fp-sha256/v1`, `hpke` in `x25519-hpke/v1`); absent when not endorsed in exactly that format |
| `CryptoMaterial()` / `CryptoMaterialData(id, format)` | all endorsed key items / exact id+format lookup (also a free function over an item list) |
| `FreshnessExpiresAt()` | earliest witness/approval deadline; a cached verification MUST NOT authorize new requests at or after it. Zero when every component is embedded |
| `Config()` / `Runtime()` / `Platform()` | config-based verification only: `ConfigVerification` / `ArtifactVerification` describing what was accepted and its `ReferenceSource` (`endorsement`/`embedded`/`policy`) |
| `Metadata() → {Verifier: {Name, Version}, VerifiedAt}` | unattested facts about the verification itself |

### 2.4 Measurements (`measurement`)

Closed sets, one type per platform, distinguished by type switch / tag:
`Measurement` = `SEVSNP{Launch}` | `TDX{MRTD, RTMR0..3}`; `Expected` =
`ExpectedSEVSNP` | `ExpectedTDX` with each register optional.
`Register` is 48 bytes (`RegisterSize`), text form lowercase hex.
`ParseRegister`, `ParseExpectedSEVSNP(launch)`,
`ParseExpectedTDX(mrtd, rtmr0, rtmr1, rtmr2, rtmr3)` accept hex in either
case; an empty string leaves an expected register unconstrained.

### 2.5 Document (`document`)

| surface (Go form) | semantics |
|---|---|
| `RandomNonce() → bytes` / `NonceSize = 32` | fresh 32-byte verifier nonce |
| `CryptoMaterialIDTLS = "tls"`, `CryptoMaterialIDHPKE = "hpke"`, the format-registry constants | identifiers for crypto-material lookup |
| `CryptoMaterialItem{ID, Format, Data}` | one endorsed key; `Data` is lowercase hex |

Attestation fetch (wire, not API): `GET
https://<host>/.well-known/tinfoil-attestation?nonce=<lowercase hex>`; host
may carry a port.

### 2.6 Errors

| surface (Go form) | semantics |
|---|---|
| `UsageError` | verifier built or called with invalid inputs; retrying won't help |
| `VerificationError{Layer}` | document must not be trusted; `Layer` ∈ `envelope`/`provenance`/`quote`/`policy` (open set — tolerate unknown values), mapping to `ENVELOPE/PROVENANCE/QUOTE/POLICY_REJECTED` without string matching |
| `Error` | common supertype of both |

### 2.7 TLS helper (MUST)

`CertPubkeyFP(cert)` (SPKI SHA-256 of a certificate, the `TLSPublicKeyFP`
form). Pure: the verifier takes no socket or connection objects. Building the
connection check from its facts is the transport's job (§3.4).

## 3. Tier 2 — product client surface (SHOULD; MUST before an SDK release claims v3)

This section pins names and the behavior applications rely on. Every client verifies before its constructor returns, checks options
before any network I/O, re-verifies by itself when the verification expires
(§2.3) or is rejected, and refuses requests to any origin other than the one
it is bound to.

### 3.1 Routes

| route | HTTP client | OpenAI client | level |
|---|---|---|---|
| recommended | — | `NewClient(openaiOpts) → Client` with `BaseURL()`, `HTTPClient()` | MUST |
| explicit enclave | `NewEnclaveHTTPClient(host, repo, EnclaveOptions)` | `NewEnclaveOpenAIClient(host, repo, EnclaveOptions, openaiOpts)` | MUST |
| discovered router | `NewRouterHTTPClient(RouterOptions)` | `NewRouterOpenAIClient(RouterOptions, openaiOpts)` | MUST |
| gateway (experimental) | `NewGatewayHTTPClient(GatewayOptions)` | `NewGatewayOpenAIClient(GatewayOptions, openaiOpts)` | MAY |

An OpenAI client applies the caller's options first, then sets its HTTP
client and base URL so they cannot be replaced; it exposes its HTTP client via
`HTTPClient()`.

### 3.2 Enclave and router HTTP clients

| method (Go form) | semantics |
|---|---|
| `BaseURL()` | where requests go: the `BaseURL` option, else the enclave's origin |
| `Enclave()` | the verified enclave's host, even behind a proxy |
| `Repo()` | the repo pin, empty when the verifier authorizes the config |
| `Current() → Verification` | last successful verification, unchecked |
| `EnsureVerified() → Verification` | a verification valid now, verifying only if needed; success means requests can be sent |
| `Reverify() → Verification` | verify again unconditionally |

`EnclaveOptions` / `RouterOptions`: `TransportMode` (default `tls`),
`BaseURL` (a proxy; requires `ehbp`; HTTPS, or `http://` only to loopback;
requests carry `X-Tinfoil-Enclave-Url`), `Verifier` (nil = defaults; for the
router, a config-authorizing verifier is a `ConfigurationError`),
`VerificationCheck(v)` (caller veto after policy; rejection is a
non-retried `AttestationError`, or for the router, moves discovery on),
`UserCacheSecret` (router: empty resolves from `TINFOIL_USER_CACHE_SECRET`
then `~/.tinfoil/user_cache_secret`; a non-empty body `user_cache_secret`
overrides it).

### 3.3 Gateway client (MAY)

Methods `BaseURL()`, `Current() → [ReplicaVerification]`,
`EnsureVerified(model)`, `Models()`. `GatewayOptions`: `ModelPins` (model →
`ModelPin{Repo, Verifier}`), `PinnedModelsOnly`, `Verifier`,
`VerificationCheck`, `UserCacheSecret`, `URL`, `Catalog`. Also
`FetchCatalog(host) → Catalog` (model → `CatalogEntry{Repo, Hosts}`,
untrusted). Every request is sealed as with `ehbp`.

### 3.4 Transport and channel binding

`TransportMode` ∈ `tls` | `ehbp`. `tls` pins every connection to the endorsed
`TLSPublicKeyFP`; `ehbp` seals bodies to the endorsed `HPKEPublicKey` and
refuses protocol upgrades and CONNECT. A platform that cannot inspect the
transport (browsers) supports only `ehbp` and MUST reject `tls` with a
`ConfigurationError`. `capabilities.channel_binding` declares the **product
client's** default mechanism, not the adapter's test-time check.

The pin is internal to the client; the SDK exposes no public connection
helper. A caller who brings their own transport pins it by comparing
`CertPubkeyFP` (§2.7) of the peer's leaf certificate with `TLSPublicKeyFP`
after the handshake and before sending anything, in addition to, never
instead of, the normal certificate checks.

### 3.5 Errors and version

`Error` supertype with `ConfigurationError` (invalid arguments or
configuration), `NetworkError` (couldn't reach attestation material or the
enclave: network failure, timeout, HTTP error status), and `AttestationError`
(rejected evidence, policy, or channel binding; wraps the Tier 1 error).
Errors from the OpenAI API keep their own types. `Version()` reports the SDK
version.

## 4. Out of scope

Enclave-side and publisher plumbing in the reference is not client surface:
`document.Build`/`ComputeReportData`/`BuildInput`/`QuoteGenerator`, the
`collaterals` service types, `endorsement/config` and `endorsement/freshness`
statement construction, `verify/document/collateral` entry types, and the Go
`mobile` FFI package.

## 5. Change control

The surface is not yet stable. While the version is 0.x, any change —
including renames and removals — bumps the minor version. From 1.0.0,
surface additions bump the minor version; renames/removals bump the major
and require a coordinated release across SDKs. An SDK's conformance claim
states the surface-spec version it implements.

v0.3.0: `ConnectionCertFP` and `PinTLSKey` removed from the surface (§2.7),
so that the verifier takes no connection objects; nothing outside the SDKs
used them. The clients keep the pin internal, and §3.4 says how a caller who
brings their own transport pins it with `CertPubkeyFP`. `CertPubkeyFP` and
`TLSPublicKeyFP` stay in Tier 1, and `CertPubkeyFP`, which needs no transport
access, is now a plain MUST.

v0.2.0 (from 1.0.0, renumbered as pre-stable): reference moved to `tinfoil-go` `main`.
`VerifyDocumentV3` → `Verifier.VerifyV3`/`VerifyV3At`; `VerifiedDocumentV3`
→ `Verification`; free `TLSPublicKeyFP(v)`/`HPKEPublicKey(v)` → accessors;
public `Fetch(host, nonce)` removed (wire contract kept, §2.5); verifier
options, measurement types and TLS helpers added; Tier 2 now names the
recommended, enclave, router and gateway client routes and the SDK error
categories.
