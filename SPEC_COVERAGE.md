# SPEC Coverage Matrix

This document tracks which parts of `sdk-flywheel/SPEC.md` are covered by the
conformance vectors, and which function-level gaps should be closed before the
suite moves on to production-path hooks or end-to-end SDK flows.

The goal is practical coverage: every verifier primitive that can reject should
have at least one hermetic vector, or an explicit reason why it is out of scope.

## Current Inventory

| Stage | Vector Count | SPEC Area | Status |
|---|---:|---|---|
| `verify-sigstore` | 48 | §5, with some §7.3 normalization | Strong |
| `verify-hardware-measurements` | 11 | §6.3, §7.3 normalization | Strong |
| `verify-measurement` | 17 | §7.1-§7.3 | Strong |
| `verify-attestation-sev` | 26 | §3, selected §8 bindings | Broad, gaps remain |
| `verify-attestation-tdx` | 51 | §4, selected §8 bindings | Broad, gaps remain |
| `verify-full` | 7 | §11 composition | Partial, checks sub-stage propagation and envelope presence |

## Coverage By SPEC Section

| SPEC Section | Covered Behaviors | Representative Vectors | Coverage |
|---|---|---|---|
| §2 Attestation document protocol | Not directly covered as a separate stage. Some document body/hash assumptions are covered by attestation stages. | N/A | Gap |
| §2.3 Predicate type URIs | Unknown/unsupported measurement types, known Sigstore predicate extraction. | `measurement/150-compare-tdx-direct-to-sev-unsupported`, `sigstore/013-predicate-type-not-allowed` | Partial |
| §2.4 Document hash | Used indirectly by certificate/report binding checks. | `attestation-sev/420-report-data-pin-mismatch`, `attestation-tdx/460-report-data-pinned-mismatch` | Partial |
| §2.5 Decompression safety | No gzip bomb / decompressed size-limit fixture. | N/A | Gap |
| §2.6 UTF-8/text encoding | Hex lowercase normalization is covered; generic UTF-8 conversion failures are not. | `measurement/103-fingerprint-uppercase-normalized`, `sigstore/017-subject-digest-uppercase-accepted` | Partial |
| §3.1 SEV report layout | Happy path, bad version, truncation. | `attestation-sev/200-real-sev-snp-happy`, `210-wrong-report-version`, `211-truncated-report` | Partial |
| §3.2 SEV bitfields | Synthetic policy/reserved-bit cases: debug, reserved MBO/MBZ, migration agent, baseline accept. | `attestation-sev/600-synth-debug-bit-set`, `601-synth-reserved-mbo-cleared`, `602-synth-reserved-mbz-set`, `603-synth-migrate-ma-set`, `604-synth-baseline-accept` | Broad |
| §3.3 SEV certificate chain | Happy path, corrupted VCEK, expired VCEK, VCEK signature tamper. | `attestation-sev/230-vcek-first-byte-flipped`, `231-vcek-signature-tampered`, `240-vcek-expired` | Partial |
| §3.4 SEV VCEK extensions | VCEK TCB mismatch, HWID mismatch, missing HWID extension. | `attestation-sev/700-vcek-hwid-mismatch`, `701-vcek-bl-spl-mismatch`, `702-vcek-ucode-spl-mismatch`, `703-vcek-missing-hwid-extension` | Partial |
| §3.5 SEV VCEK fetching/cache | Not covered; conformance vectors supply cert material hermetically. | N/A | Out of current scope |
| §3.6 SEV report signature | Signature byte flip, signed-region tamper. | `attestation-sev/220-signature-byte-flipped`, `221-signed-region-measurement-tampered` | Strong |
| §3.7 SEV policy validation | Measurement, host/report data, ID/author key digest pins, selected TCB minimums, selected policy bits. | `attestation-sev/400-measurement-pin-mismatch`, `410-host-data-pin-mismatch`, `420-report-data-pin-mismatch`, `430-id-key-digest-pin-mismatch`, `440-author-key-digest-pin-mismatch`, `450-tcb-bl-spl-below-min`, `451-tcb-ucode-spl-below-min` | Broad |
| §3.8 SEV measurement/key extraction | Measurement pin match/mismatch and all-pins positive. | `attestation-sev/400-measurement-pin-mismatch`, `460-measurement-pin-match`, `461-all-pins-match` | Partial |
| §4.1 TDX quote layout | Happy path, wrong quote version, wrong TEE type, unsupported attestation key type, wrong QE vendor, truncation, signed-data size. | `attestation-tdx/300-tdx-v4-happy`, `310-wrong-quote-version`, `311-wrong-tee-type-sgx`, `312-akt-p384-unsupported`, `313-wrong-qe-vendor`, `314-truncated-quote`, `315-wrong-signed-data-size` | Broad |
| §4.2 TDX PCK certificate chain | Leaf/intermediate/root/chain mutation, leaf expiry. | `attestation-tdx/320-pck-leaf-sig-broken`, `321-pck-intermediate-sig-broken`, `322-pck-root-byte-changed`, `323-pck-chain-byte-changed`, `324-pck-leaf-expired` | Partial |
| §4.3 TDX quote signature | Header and body signature breakage. | `attestation-tdx/330-quote-sig-broken-via-header`, `331-quote-sig-broken-via-body` | Strong |
| §4.4 TDX QE report signature | Covered indirectly through quote/collateral verification; no clearly isolated QE report signature-only vector. | N/A | Partial |
| §4.5 TDX QE report data binding | Not isolated; quote/collateral vectors exercise the path indirectly. | N/A | Gap |
| §4.6 TDX PCK SGX extensions | FMSPC mismatch. | `attestation-tdx/325-pck-fmspc-mismatch` | Partial |
| §4.7 TDX collateral validation | CRL signature breakage, TCB Info/QE Identity signature and expiry, FMSPC/MRSIGNER tamper, TCB eval data number. | `attestation-tdx/326-pck-crl-sig-broken`, `327-root-crl-sig-broken`, `340-tcb-info-sig-broken`, `341-tcb-info-expired`, `342-qe-identity-sig-broken`, `343-qe-identity-expired`, `344-tcb-info-fmspc-tampered`, `345-qe-identity-mrsigner-tampered`, `346-tcb-eval-data-number-too-low` | Broad |
| §4.7.7 TDX TCB statuses | UpToDate, non-terminal accepted statuses, terminal rejected statuses. | `attestation-tdx/350-tcb-uptodate`, `360-tcb-swhardening-needed`, `361-tcb-configuration-needed`, `362-tcb-config-and-sw-hardening-needed`, `363-tcb-out-of-date`, `364-tcb-out-of-date-config-needed`, `368-tcb-revoked` | Strong |
| §4.8 TDX policy validation | TD attributes, XFAM, MR_SIGNER_SEAM, SEAM attributes, MR_SEAM allowlist, MRTD, RTMR3, report data, owner/config IDs, TEE TCB SVN, QE vendor. | `attestation-tdx/400-*` through `490-qe-vendor-id-mismatch` | Strong |
| §4.9 TDX orchestration | Covered implicitly by `verify-attestation-tdx` happy/negative vectors. | `attestation-tdx/300-tdx-v4-happy` | Partial |
| §4.10 TDX measurement/key extraction | MRTD and RTMR3 pin mismatch. | `attestation-tdx/440-mrtd-pinned-mismatch`, `450-rtmr3-pinned-mismatch` | Partial |
| §5.1 Sigstore trust root | Invalid JSON, missing Rekor keys, missing Fulcio CAs, missing CT log keys. | `sigstore/020-trust-root-invalid-json`, `021-trust-root-no-rekor-keys`, `022-trust-root-no-fulcio-cas`, `023-trust-root-no-ct-log-keys` | Strong |
| §5.2 DSSE bundle verification | Missing DSSE, tlog count, signature tamper/count, Rekor root/hash, SCT missing/duplicate, cert validity, legacy cert layout. | `sigstore/030-*` through `079-bundle-cert-in-x509-chain-format` | Strong |
| §5.3 Certificate identity policy | Issuer/repo/ref mismatch, ref prefix, trojan ref strings, ref vs BuildSignerURI split, missing extensions, V1/V2 issuer behavior. | `sigstore/010-*`, `011-*`, `012-*`, `050-*`, `060-*`, `060b-*`, `068-*`, `069-*`, `070-*`, `071-*`, `075-*`, `076-*` | Strong |
| §5.4 Artifact digest verification | Payload type, in-toto statement type, subject digest mismatch/case, subject missing, subject[0] only, extra fields, exact case. | `sigstore/014-*`, `015-*`, `016-*`, `017-*`, `063-*`, `073-*`, `074-*`, `078-*` | Strong |
| §5.5 Predicate extraction | Predicate allowlists, null/empty allowlists, missing SNP/TDX registers, trailing slash exactness. | `sigstore/013-*`, `018-*`, `051-*`, `062-*`, `077-*`, `080-*`, `081-*` | Strong |
| §6.3 Hardware measurement matching | Single/second/duplicate first match, no match, partial field mismatch, wrong enclave type/count, case normalization. | `hardware-measurements/200-*` through `230-hardware-case-normalization` | Strong |
| §7.1 Measurement layouts | Register count validation for known types. | `measurement/123-compare-multiplatform-to-tdx-bad-target-count`, `hardware-measurements/221-*`, `222-*` | Partial |
| §7.2 Measurement fingerprint | SEV, TDX, multiplatform, uppercase normalization. | `measurement/100-*`, `101-*`, `102-*`, `103-*` | Strong |
| §7.3 Cross-platform comparison | Same-type, MP to TDX, MP to SEV, reverse comparison, unsupported direct TDX to SEV, RTMR3 nonzero. | `measurement/110-*` through `150-*` | Strong |
| §8 Report data / nonce binding | SEV host/report data pins and TDX report data pin. HPKE layout is not fully isolated. | `attestation-sev/410-host-data-pin-mismatch`, `420-report-data-pin-mismatch`, `461-all-pins-match`, `attestation-tdx/460-report-data-pinned-mismatch` | Partial |
| §9 Enclave certificate verification | Not a first-class conformance stage yet. | N/A | Gap |
| §10 Attestation bundle format | Some `verify-full` fixtures use bundle envelopes; schema edge cases are minimal. | `verify-full/500-standard-flow-sev-happy`, `510-pinned-flow-sev-happy` | Partial |
| §11 End-to-end verification flows | Standard SEV happy path, Sigstore rejection propagation, SEV attestation rejection propagation, missing standard-flow blocks, pinned happy path, pinned mismatch. | `verify-full/500-standard-flow-sev-happy`, `501-standard-flow-sigstore-digest-mismatch`, `502-standard-flow-sev-attestation-pin-mismatch`, `503-standard-flow-missing-sigstore-block`, `504-standard-flow-missing-attestation-block`, `510-pinned-flow-sev-happy`, `520-pinned-flow-measurement-mismatch` | Partial |
| §12 Infrastructure | Proxy/discovery/GitHub/cache behavior not covered by hermetic core suite. | N/A | Out of current scope |
| §13 Constants | Exercised indirectly by SEV/TDX/Sigstore vectors. No constant-audit stage. | N/A | Partial |
| §14 SDK client architecture | Not covered by core conformance suite. | N/A | Out of current scope |
| §15 Error handling | Rejection-code mapping is covered per stage schemas; SDK exception hierarchy is not. | All rejection fixtures | Partial |
| §16 Retry and recovery | Not covered by core conformance suite. | N/A | Out of current scope |

## Priority Gap Backlog

Close these before investing in production-path hooks or a real end-to-end
suite. Each item is function-level and should be implementable as a hermetic
fixture.

### P0: Composition And Truthfulness

1. Add `verify-full` negative vectors for sub-stage failures:
   - Done: Sigstore rejects and `rejection.stage` is `verify-sigstore`.
   - Done: SEV attestation rejects and `rejection.stage` is `verify-attestation-sev`.
   - Done in pinned mode: measurement mismatch and `rejection.stage` is `verify-measurement`.
   - Remaining: standard-flow measurement mismatch and `rejection.stage` is `verify-measurement`.
   - Done: missing `sigstore` block and missing attestation block reject at `verify-full`.

2. Add `verify-full` TDX coverage or declare it unsupported by capability:
   - TDX standard happy path.
   - TDX attestation rejection propagation.
   - MP to TDX measurement mismatch propagation.

### P1: SEV Function-Level Gaps

1. Report parser and signed-body checks:
   - `signature_algo != 1`.
   - unsupported signing key type / VLEK-like signer.
   - report length with trailing bytes accepted, if that is required by the SPEC.

2. Policy validation:
   - VMPL out of range.
   - VMPL pin mismatch.
   - ABI version below expected.
   - platform-info pin mismatches.
   - provisional firmware allowed vs rejected behavior.

3. TCB policy:
   - `current_tcb` below minimum.
   - `committed_tcb` below minimum.
   - `launch_tcb` below minimum.
   - non-BL/non-UCODE components below minimum.

4. VCEK certificate format:
   - product name not `Genoa`.
   - `CSP_ID` extension present.
   - HWID wrong length.
   - VCEK public key curve not P-384.
   - VCEK not-yet-valid.
   - ASK/ARK not-yet-valid or expired, if fixture generation can synthesize this.

5. Chip identity binding:
   - `mask_chip_key` set and `chip_id` nonzero.
   - `mask_chip_key` unset and HWID mismatch, already partially covered by `700`.

### P1: TDX Function-Level Gaps

1. Quote/certification parsing:
   - certification data wrong `cert_type`.
   - certification data size mismatch.
   - quote auth data size mismatch.
   - PCK cert chain with null bytes accepted.

2. PCK certificate chain:
   - chain not exactly 3 certs.
   - intermediate missing `CA=true`.
   - PCK leaf not-yet-valid.
   - root public key mismatch distinct from root byte mutation.

3. QE report and binding:
   - QE report signature-only failure.
   - QE report data binding failure, isolated from quote signature failure.

4. SGX extension parsing:
   - missing FMSPC.
   - missing PCEID.
   - wrong TCB element count.
   - malformed SGX extension sequence.

5. Collateral:
   - malformed issuer-chain header.
   - issuer-chain URL decoding positive/negative.
   - cached collateral signature re-verification is out of hermetic scope unless cache fixtures are introduced.

### P2: Sigstore Precision Gaps

1. DSSE payload parse:
   - payload is not base64.
   - payload is base64 but not JSON.
   - payload JSON has `predicate` missing entirely.

2. Subject digest shape:
   - `subject[0].digest` present but no `sha256`.
   - `subject[0].digest.sha256` non-string.

3. Rekor/certificate binding:
   - Rekor body certificate differs from bundle certificate, if fixturegen can synthesize this cleanly.
   - Rekor body signature differs from DSSE signature.

4. Bundle observables:
   - Legacy `x509CertificateChain` accepted SDKs should emit complete cert/SCT observables, not blanks or sentinel values.

### P2: Attestation Document And Certificate Stages

1. Add a first-class `verify-cert-binding` or `verify-enclave-certificate` stage for §9:
   - dcode label parsing.
   - HPKE key binding.
   - attestation hash binding.
   - certificate subject/SAN malformed cases.

2. Add a first-class attestation document stage or extend full-flow fixtures for §2/§10:
   - malformed JSON/envelope.
   - invalid base64 body.
   - gzip decompression limit.
   - document hash computation.

## Out Of Scope Until Production Hooks

These are important, but they should wait until the SDK public paths can be
driven with injected fetchers/trust roots/clocks:

- Real attestation endpoint behavior and timeout handling (§2.1, §10.2).
- GitHub latest release / artifact fetching (§12.4).
- Runtime TUF/PCS/KDS fetching and cache behavior (§3.5, §4.7, §12.5).
- Router discovery and retry/recovery (§12.2, §16).
- Client architecture and user-facing error wrapping (§14, §15 beyond rejection codes).
