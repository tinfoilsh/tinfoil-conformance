# `verify-attestation-tdx` Conformance Plan

Cross-SDK conformance plan for the Intel TDX DCAP quote verification surface.
Anchored to two sources:

* **Intel® TDX DCAP Quote Generation Library and Quote Verification Library**,
  rev 0.9 (2025-May) — the canonical Intel doc defining the quote format
  (§A.3 v4, §A.4 v5), the QVL verification steps (§2.3), the verification
  result codes (§B.1), and the extended-TD-checks the caller must do (§2.3.2).
* **Tinfoil SPEC §4** (Intel TDX Verification) and §7/§6/§8 (cross-platform
  comparison, hardware-measurement binding, report-data binding).

This document is the planning artifact. Fixtures, schemas, and SDK code land
in their respective directories.

## Cross-SDK divergence risk

| SDK             | TDX support       | Underlying lib                  | Risk                                                  |
|-----------------|-------------------|---------------------------------|-------------------------------------------------------|
| `tinfoil-go`    | Yes               | likely `google/go-tdx-guest`    | Lowest                                                |
| `tinfoil-python`| Yes               | Intel DCAP QVL via pyca         | Medium (Intel returns 11 result codes; lib may collapse) |
| `tinfoil-rs`    | Probably partial  | own impl, unclear depth         | Medium-high                                           |
| `tinfoil-js`    | **No** (per audit — `PredicateType.TdxGuestV2` not in enum) | n/a | All TDX fixtures skip; gated by capability         |

JS skips the whole stage via `platforms_supported` not including `"tdx"`.
Same pattern as `measurement.compare_multiplatform_to_tdx_supported` for §7.

## Phase 1 — Contract, Schema, Happy Path (~5 fixtures, 1-2 days)

**Goal:** lock the CLI contract and have one real-bundle fixture passing on
at least Go + Python.

* Add stage `verify-attestation-tdx` to capability schema.
* Input: `{ quote_b64, collateral: {tcb_info_json, tcb_info_sig,
  qe_identity_json, qe_identity_sig, pck_crl, root_ca_crl, root_ca_cert,
  intermediate_ca_cert}, expiration_check_date_unix, policy: {...} }`.
* Output (accept): `{measurement: TdxGuestV2 with 5 registers, qv_result,
  tcb_status, td_attributes_decoded, xfam_decoded, report_data_hex,
  mrseam, mrsignerseam, mrtd, mrconfigid, mrowner, mrownerconfig, rtmr0..3}`.
* Output (reject): one of ~30 SPEC-anchored codes (Phase 2 enumerates).
* Happy-path fixtures (5):
  * `300-tdx-v4-happy` (TDX 1.0 v4 quote)
  * `301-tdx-v5-happy` (TDX 1.5 v5 quote — A.4 layout)
  * `302-qv-result-sw-hardening-needed` (non-terminal, accept under permissive policy)
  * `303-qv-result-config-needed` (non-terminal)
  * `304-qv-result-out-of-date-within-grace` (custom policy)

## Phase 2 — Cryptographic Verification (~25 fixtures, 1 week)

Tests §4.1–4.7 — cert chain + signatures + collateral. Highest value-per-effort.

### Quote structure parsing (~5)
* 310 — wrong magic / version → `QUOTE_FORMAT_UNSUPPORTED`
* 311 — header.tee_type=0x00 (SGX) → `WRONG_TEE_TYPE`
* 312 — header.attestation_key_type=3 (P-384, not supported) → `ATTESTATION_KEY_TYPE_UNSUPPORTED`
* 313 — header.qe_vendor_id != Intel UUID → `QE_VENDOR_UNKNOWN`
* 314 — truncated quote → `QUOTE_TRUNCATED`

### PCK cert chain (~7)
* 320 — PCK chain signature broken at leaf → `PCK_CHAIN_INVALID`
* 321 — chain missing intermediate → `PCK_CHAIN_INCOMPLETE`
* 322 — PCK leaf SAN doesn't match expected FMSPC → `PCK_FMSPC_MISMATCH`
* 323 — chain root not Intel SGX Root CA → `ROOT_CA_UNTRUSTED`
* 324 — PCK leaf expired vs `expiration_check_date` → `PCK_EXPIRED`
* 325 — PCK leaf on PCK CRL → `PCK_REVOKED`
* 326 — intermediate (Platform CA) on Root CRL → `INTERMEDIATE_REVOKED`

### Quote signature ↔ AK ↔ QE Report binding (~6)
* 330 — quote signature byte-flipped → `QUOTE_SIGNATURE_INVALID`
* 331 — QE report signature byte-flipped → `QE_REPORT_SIGNATURE_INVALID`
* 332 — AK hash in QE.ReportData != AK pubkey → `AK_BINDING_INVALID`
* 333 — quote signed by different AK than the cert data references → `AK_MISMATCH`
* 334 — QE auth data tampered → caught as `QE_REPORT_SIGNATURE_INVALID`
* 335 — signature encoding (DER vs raw) corner case

### TCB Info / QE Identity collateral (~7)
* 340 — TCB Info signature byte-flipped → `TCB_INFO_SIGNATURE_INVALID`
* 341 — TCB Info expired — test both strict and permissive policy
* 342 — QE Identity signature byte-flipped → `QE_IDENTITY_SIGNATURE_INVALID`
* 343 — QE Identity expired
* 344 — TCB Info chain doesn't anchor at Intel SGX Root CA → `TCB_INFO_CHAIN_INVALID`
* 345 — QE Identity MRSIGNER != QE Report MRSIGNER → `QE_IDENTITY_MRSIGNER_MISMATCH`
* 346 — QE Identity ISVPRODID/MISCSELECT/ATTRIBUTES mismatch → `QE_IDENTITY_FIELD_MISMATCH`

## Phase 3 — TCB Evaluation (~15 fixtures, 3-5 days)

Tests §A.3.3 TEE_TCB_SVN[16] vs `TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[0..15]`,
plus all 11 verification result codes per §B.1.

### TCB comparison (~6)
* 350 — TEE_TCB_SVN[0..15] all equal to `Up-To-Date` level → qv_result=OK
* 351 — TEE_TCB_SVN[0] < TCBLevel.svn[0] → qv_result=OUT_OF_DATE
* 352 — Quote TCB matches `Revoked` level → qv_result=REVOKED
* 353 — Quote TCB matches `ConfigurationNeeded` level → qv_result=CONFIG_NEEDED
* 354 — TCB fan-through: matches first level marked `OutOfDate`
* 355 — Quote PCESVN < TCBLevel.tcb.pcesvn → qv_result=OUT_OF_DATE

### Verification result code matrix (~9, one per non-OK result per §B.1)
* 360 — SW_HARDENING_NEEDED
* 361 — CONFIG_NEEDED
* 362 — CONFIG_AND_SW_HARDENING_NEEDED
* 363 — OUT_OF_DATE
* 364 — OUT_OF_DATE_CONFIG_NEEDED
* 365 — TD_RELAUNCH_ADVISED
* 366 — TD_RELAUNCH_ADVISED_CONFIG_NEEDED
* 367 — INVALID_SIGNATURE (terminal)
* 368 — REVOKED (terminal)

For each, test both **strict policy** (only OK accepted) and **permissive
policy** (selected non-OKs accepted). New capability
`policy.accepted_qv_results` (list of strings) — strict-only SDKs declare `[]`.

## Phase 4 — Extended TD Checks / Validation (~25 fixtures, 1 week)

This is Intel §2.3.2 — fields the QVL **does not check** but the relying
party must. The high-leverage "is this verified TDX *trustworthy*" layer.

### TD Attributes (~10) — per §A.3.4 / §A.4.6 bitmap
* 400 — **TDATTRIBUTES.TUD.DEBUG (bit 0) = 1** → MUST reject. Flagship "debug TD" check.
* 401 — TDATTRIBUTES.TUD bits[7:1] reserved-non-zero → MUST reject
* 402 — TDATTRIBUTES.SEC bits[27:8] reserved-non-zero → MUST reject
* 403 — TDATTRIBUTES.SEC.SEPT_VE_DISABLE (bit 28) = 0 → policy decision
* 404 — TDATTRIBUTES.SEC bit[29] reserved-non-zero → MUST reject
* 405 — TDATTRIBUTES.SEC.PKS (bit 30) = 1 — policy decision
* 406 — TDATTRIBUTES.SEC.KL (bit 31) = 1 — policy decision
* 407 — TDATTRIBUTES.OTHER bits[62:32] reserved-non-zero → MUST reject
* 408 — TDATTRIBUTES.OTHER.PERFMON (bit 63) = 1 — policy decision
* 409 — TDATTRIBUTES happy path (DEBUG=0, all reserved=0, expected SEC bits) → accept

### XFAM (~3)
* 410 — XFAM required-zero bits non-zero → reject
* 411 — XFAM required-set bits zero → reject
* 412 — XFAM matches Tinfoil-pinned bitmap → accept

### MRSEAM / MRSIGNERSEAM / SEAMATTRIBUTES (~5)
* 420 — MRSIGNERSEAM != all-zero → reject (Intel-signed TDX Module rule)
* 421 — SEAMATTRIBUTES != all-zero (TDX 1.0) → reject
* 422 — MRSEAM matches Intel-published allowlist (Tinfoil SPEC §13.6) → accept
* 423 — MRSEAM not in allowlist → reject
* 424 — TDX 1.5 SEAMATTRIBUTES valid bits → accept

### MRTD / RTMR validation (~4)
* 430 — MRTD doesn't match expected → policy reject
* 431 — RTMR3 != all-zero → reject (SPEC §7.3.6 carry-over)
* 432 — RTMR3 = all-zero → accept
* 433 — RTMR[0..3] all-zero (pre-launch state) → reject

### REPORTDATA validation (~3) — SPEC §8 binding
* 440 — REPORTDATA[0:32] = SHA-256(TLS public key SPKI) per §8.2 → accept
* 441 — REPORTDATA[0:32] != expected → reject (`REPORT_DATA_BINDING_MISMATCH`)
* 442 — REPORTDATA[32:64] = expected attestation-hash binding (§9.4) → accept

## Phase 5 — Cross-Verification with Sigstore (~10 fixtures, 3-5 days)

End-to-end binding. Introduces stage `verify-full` (already declared in
capabilities). Chains `verify-sigstore` + `verify-hardware-measurements` +
`verify-measurement` + `verify-attestation-tdx`.

* 500 — happy E2E (Sigstore code = MP, TDX measurement = TDX, HW match,
  RTMR1/2 line up, RTMR3=0, REPORTDATA binds TLS key)
* 501 — Sigstore MP.RTMR1 ≠ TDX.RTMR1 → `SIGSTORE_TDX_RTMR_MISMATCH`
* 502 — Sigstore MP.RTMR2 ≠ TDX.RTMR2 → `SIGSTORE_TDX_RTMR_MISMATCH`
* 503 — TDX MRTD doesn't match any HW entry → `HARDWARE_NO_MATCH`
* 504 — TDX MRTD matches HW but RTMR0 doesn't → `HARDWARE_NO_MATCH`
* 505 — TDX RTMR3 != all-zero → `MEASUREMENT_RTMR3_NONZERO`
* 506 — REPORTDATA[0:32] != TLS cert SPKI fingerprint → `CERT_BINDING_MISMATCH`
* 507 — REPORTDATA[32:64] != attestation hash → `ATTESTATION_HASH_BINDING_MISMATCH`
* 508 — TDX genuine but for different repo's release digest → `RELEASE_BINDING_MISMATCH`
* 509 — TDX TCB out-of-date AND Sigstore HW measurements up-to-date → policy decision

## Totals & timeline

```
Phase 1 (foundation + happy path):        5 fixtures   ~2 days
Phase 2 (cryptographic verification):    25 fixtures   ~1 week
Phase 3 (TCB evaluation):                15 fixtures   ~4 days
Phase 4 (extended TD checks):            25 fixtures   ~1 week
Phase 5 (cross-verification w/ Sigstore): 10 fixtures   ~3 days
                                        ─────────────  ─────────
Total:                                   80 fixtures   ~3-4 weeks
```

Plus SDK-side work: each SDK binary needs `verify-attestation-tdx` +
`verify-full` subcommands. Mostly mechanical wrapping over existing TDX
verification, plus classifier per SDK (lib error → SPEC code). ~1 week SDK
work distributed across the 5 weeks.

**Total budget: ~5 weeks of focused work.**

## Fixture-generation strategy

Three sources, in priority order:

1. **Real bundles from production** (cheapest, most realistic).
   * Sigstore: have real one (fixture 001).
   * SEV-SNP attestation: have real one (`tinfoil-js/.../attestation-bundle.json`).
   * TDX attestation: need to capture from a TDX deployment. **Open action.**

2. **Tamper-mutation of real bundles** (medium). Flip a byte in the signature,
   swap a cert, modify a TCB level field. Same pattern as Sigstore fixtures
   030-079.

3. **Synthetic generation with test PCK chains** (most expensive). Need key
   material + harness for fixtures testing TCB component-wise comparison
   (synthetic PCK certs with controlled FMSPC/CPUSVN/PCESVN). Reference:
   Intel's QVL test vectors.

## Open questions

1. Real TDX quote + collateral bundle available for the happy-path fixture?
   If not, Phase 1 starts synthetic which is significantly more work.
2. Priority on Phases 3 vs 4: TCB evaluation vs extended TD checks first?
   Phase 4 (DEBUG bit etc.) is what catches "verified TDX but not
   trustworthy" — higher leverage. Phase 3 catches "verified TDX with
   stale patches" — also important but lower-likelihood-of-incident.
