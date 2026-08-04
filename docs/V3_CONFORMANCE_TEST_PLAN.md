# V3 Conformance Test Plan (point-by-point)
> Every rule in [SPEC_COVERAGE_V3.md](SPEC_COVERAGE_V3.md) mapped to a concrete shared
> fixture: id, harness stage, expected verdict, the single-field mutation that triggers it,
> and the Python generator that emits it. Build checklist — 100% when every box is green.

**Totals:** 117 rules (112 fixtured + 5 ambiguous/deferred).

## ENVELOPE — stage `v3-check-envelope` · generator `gen_envelope()`
- `[ ]` **envelope-happy** → accept (valid base = mutation baseline)

| rule | fixture | verdict | mutation |
|---|---|---|---|
| E1 | `e1` | reject | Document with `Format` or unknown top-level field `extra_field`. |
| E2 | `e2` | reject | Document with duplicate `"format"` member in `challenge` block. |
| E3 | `e3` | reject | Document with non-UTF-8 bytes (e.g., `0xFF 0xFE` without valid continuation). |
| E4 | `e4` | reject | Base64 with spaces: `SGVs bG8g V29y bGQ=`; or non-canonical padding: `SGVsbG8gV29ybGQ` (… |
| E5 | `e5` | reject | Hex with uppercase: `ABCD1234`; odd length: `abc`; length mismatch: 31-byte `nonce` inst… |
| E6 | `e6` | reject | Document with trailing `,` or `}}}` or extra whitespace after the JSON. |
| E7 | `e7` | reject | Document missing `crypto_material`; or with legacy `generated_at`; or with `format: v2`. |
| E8 | `e8` | reject | Missing `challenge.nonce`; or `report_data` not 64 bytes; or wrong algorithm URI. |
| E9 | `e9` | reject | Unknown format URI; or hashes not 32 bytes. |
| E10 | `e10` | reject | Invalid base64; non-JSON; missing `format` URI; duplicate `id`s (two items with `"id": "… |
| E11 | `e11` | reject | Unknown section format URI. |
| E12 | `e12` | reject | Missing `vendor` or `kind` field; unknown section format. |
| E13 | `e13` | reject | Duplicate `id` values in collateral array. |

## PROVENANCE — stage `v3-authenticate-provenance` · generator `gen_provenance()`
- `[ ]` **provenance-happy** → accept (valid base = mutation baseline)

| rule | fixture | verdict | mutation |
|---|---|---|---|
| P1 | `p1` | reject | Document without sigstore-code collateral. |
| P2 | `p2` | reject | Document without sigstore-platform collateral. |
| P3 | `p3` | reject | Legacy multi-cert bundle layout. |
| P4 | `p4` | reject | Bundle with 0 signatures; bundle with 2+ signatures. |
| P5 | `p5` | reject | Chain to untrusted root. |
| P6 | `p6` | reject | Certificate with 0 SCTs or invalid SCTs. |
| P7 | `p7` | reject | Bundle with 0 Rekor entries. |
| P8 | `p8` | reject | Bundle with observer timestamp outside certificate validity. |
| P9 | `p9` | reject | Invalid DSSE signature; non-in-toto payload. |
| P10 | `p10` | reject | Statement with subject[0] digest mismatch; multi-subject statements (use first). |
| P11 | `p11` | reject | Self-hosted runner; wrong issuer; unescaped SAN; SAN with trailing content. |
| P12 | `p12` | reject | Bundle with 2+ SCTs from same CT log. |
| P13 | `p13` | reject | Wrong predicate URI; schema-violating predicate (unknown field reject). |
| P14 | `p14` | reject | SAN with wrong repo; non-tag ref; wildcard workflow path outside `.github/workflows/`. |
| P15 | `p15` | reject | SAN with different workflow file; tag without `v` prefix; unanchored pattern. |
| P16 | `p16` | reject | Missing sigstore-code or sigstore-platform entry; expired bundle. |

## QUOTE-SEV — stage `v3-authenticate-quote/validate` · generator `gen_sev()`
- `[ ]` **sev-happy** → accept (valid base = mutation baseline)

| rule | fixture | verdict | mutation |
|---|---|---|---|
| S1 | `s1` | reject | Report VERSION = 2. |
| S2 | `s2` | reject | Report with GUEST_SVN < minimum. |
| S3 | `s3` | reject | Report with bit 17 = 0 or reserved bits set. |
| S4 | `s4` | reject | Report with different bit value than policy (e.g., policy `debug: false` but report has … |
| S5 | `s5` | reject | Report FAMILY_ID mismatch. |
| S6 | `s6` | reject | Report IMAGE_ID mismatch. |
| S7 | `s7` | reject | Report VMPL mismatch or out-of-range (e.g., 5). |
| S8 | `s8` | reject | Non-ECDSA algorithm or signature verification failure. |
| S9 | `s9` | reject | Report CURRENT_TCB < minimum; or CURRENT ≠ COMMITTED when provisional forbidden. |
| S10 | `s10` | reject | Report PLATFORM_INFO bit mismatch; reserved bits set. |
| S11 | `s11` | reject | Report with different platform_info bit (e.g., policy `smt_enabled: false` but report ha… |
| S12 | `s12` | reject | VLEK-signed report; AUTHOR_KEY_EN=1; masked CHIP_ID (all-zero). |
| S13 | `s13` | reject | Report REPORT_DATA mismatch (e.g., wrong nonce used). |
| S14 | `s14` | reject | Report MEASUREMENT mismatch. |
| S15 | `s15` | reject | Report HOST_DATA mismatch. |
| S16 | `s16` | reject | Report with non-zero ID_KEY_DIGEST or AUTHOR_KEY_DIGEST. |
| S17 | `s17` | reject | N/A (no rejection criterion). |
| S18 | `s18` | reject | N/A (policy enforcement covers this). |
| S19 | `s19` | reject | Report REPORTED_TCB < minimum; or REPORTED_TCB ≠ VCEK TCB. |
| S20 | `s20` | reject | Report with all-zero CPUID; VCEK from wrong product. |
| S21 | `s21` | reject | Report with CHIP_ID not in machines map (e.g., unknown machine). |
| S22 | `s22` | reject | Report TCB < minimum; or CURRENT ≠ COMMITTED when provisional forbidden. |
| S23 | `s23` | reject | Report LAUNCH_TCB < minimum. |
| S24 | `s24` | reject | Report missing required mitigation bits. |
| S25 | `s25` | reject | Invalid signature; chain to untrusted root; missing or revoked certificate. |
| S26 | `s26` | reject | VCEK from untrusted root; broken chain; missing CRL. |

## QUOTE-TDX — stage `v3-authenticate-quote/validate` · generator `gen_tdx()`
- `[ ]` **tdx-happy** → accept (valid base = mutation baseline)

| rule | fixture | verdict | mutation |
|---|---|---|---|
| T1 | `t1` | reject | Quote format v3 or v5; non-TDX-1.0 body. |
| T2 | `t2` | reject | Quote with Version ≠ 4, wrong Key Type, or wrong TEE Type. |
| T3 | `t3` | reject | Quote with non-zero RESERVED bytes. |
| T4 | `t4` | reject | Quote with different QE Vendor ID. |
| T5 | `t5` | reject | N/A (no rejection criterion). |
| T6 | `t6` | reject | Quote TEE_TCB_SVN byte < minimum; or TCB Info status not `UpToDate`. |
| T7 | `t7` | reject | Quote with MRSEAM ≠ policy `mr_seam`. |
| T8 | `t8` | reject | Quote with MRSIGNERSEAM ≠ Intel expectation. |
| T9 | `t9` | reject | Quote with SEAMATTRIBUTES mismatch; non-zero mask for TDX 1.0. |
| T10 | `t10` | reject | Quote TDATTRIBUTES ≠ policy; e.g., DEBUG bit set or reserved bit non-zero. |
| T11 | `t11` | reject | Quote with DEBUG=1, SEPT_VE_DISABLE=0, or other mismatches. |
| T12 | `t12` | reject | Quote XFAM ≠ policy; e.g., wrong FP/SSE/AVX bits. |
| T13 | `t13` | reject | Quote with different XFAM bits (e.g., reserved bits set). |
| T14 | `t14` | reject | Quote MRTD ≠ any shape-filtered measurements in policy. |
| T15 | `t15` | reject | Quote with non-zero MRCONFIGID. |
| T16 | `t16` | reject | Quote with non-zero MROWNER or MROWNERCONFIG. |
| T17 | `t17` | reject | Quote RTMR0 ≠ any shape-filtered measurements. |
| T18 | `t18` | reject | Quote RTMR1/RTMR2 mismatch. |
| T19 | `t19` | reject | Quote with non-zero RTMR3. |
| T20 | `t20` | reject | Quote REPORTDATA mismatch. |
| T21 | `t21` | reject | QE Report with mismatched fields or REPORTDATA. |
| T22 | `t22` | reject | Collateral with non-`UpToDate` status. |
| T23 | `t23` | reject | Collateral with `tcbEvaluationDataNumber` < minimum. |
| T24 | `t24` | reject | PCK chain to untrusted root; revoked certificate. |
| T25 | `t25` | reject | PCK from untrusted root; broken chain. |

## IDENTITY — stage `v3-assemble-policy` · generator `gen_identity()`

| rule | fixture | verdict | mutation |
|---|---|---|---|
| I1 | `i1` | reject | Identity extraction before authentication; wrong identity field. |
| I2 | `i2` | reject | CHIP_ID not in machines map; uppercase hex. |
| I3 | `i3` | reject | PPID not in machines map; extracted from untrusted source. |
| I4 | `i4` | reject | Lookup before authentication. |
| I5 | `i5` | reject | Identity absent from machines map. |
| I6 | `i6` | reject | Policy `platform: tdx` for a SEV quote. |
| I7 | `i7` | reject | Duplicate keys; ambiguous key lengths. |

## POLICY — stage `v3-assemble-policy/validate-quote` · generator `gen_policy()`

| rule | fixture | verdict | mutation |
|---|---|---|---|
| PL1 | `pl1` | reject | Policy with unknown field; missing required member; unimplemented constraint. |
| PL2 | `pl2` | reject | Missing `minimum_tcb`, `guest_policy`, `platform_info`, or other required field. |
| PL3 | `pl3` | reject | Missing `qe_vendor_id`, `minimum_tee_tcb_svn`, or other required field. |
| PL4 | `pl4` | reject | Policy with unknown field like `future_constraint: {...}`. |
| PL5 | `pl5` | reject | Policy with either set to `true`. |
| PL6 | `pl6` | reject | Policy with inverted semantics (e.g., exact on floor field). |
| PL7 | `pl7` | reject | Policy with inverted semantics. |
| PL8 | `pl8` | reject | Policy with multiple `mr_seam` values (array). |
| PL9 | `pl9` | reject | Empty `platform_measurements` array; MRTD/RTMR0 not found. |
| PL10 | `pl10` | reject | Map with metadata like `"<identifier>": {"policy": "...", "hostname": "..."}`. |
| PL11 | `pl11` | reject | Dangling policy reference; wrong identifier format; duplicate keys. |
| PL12 | `pl12` | reject | Policy with missing `minimum_build` or `minimum_tcb`. |

## STRUCTURAL — stage `v3-assemble-policy` · generator `gen_shape()`

| rule | fixture | verdict | mutation |
|---|---|---|---|
| ST1 | `st1` | reject | Code artifact with `vm_shape: {cpus: 16, memory: 65536}`; no measurements with matching … |
| ST2 | `st2` | reject | Shape-filtered candidates, but MRTD/RTMR0 pair not found. |
| ST3 | `st3` | reject | Lookup by shape alone (wrong); ambiguous resolution. |
| ST4 | `st4` | reject | Code artifact missing `vm_shape` (once deprecated fallback removed). |

## FRESHNESS — stage `v3-authenticate-provenance (gated)` · generator `gen_freshness()`

| rule | fixture | verdict | mutation |
|---|---|---|---|
| FR1 | `fr1` | probe | Document with stale/replayed nonce; document with expired collateral (no enforcement tod… |
| FR2 | `fr2` | probe | Witness with stale `issued_at` (outside window) — deferred check. |
| FR3 | `fr3` | probe | Single stack with forced upgrade (enforcement deferred). |

## UNCHECKED — stage `verify-attestation-v3 (negative)` · generator `gen_unchecked()`

| rule | fixture | verdict | mutation |
|---|---|---|---|
| U1 | `u1` | accept | N/A (no rejection). |
| U2 | `u2` | accept | N/A (policy enforcement). |
| U3 | `u3` | accept | N/A (no rejection). |
| U4 | `u4` | accept | Unknown `crypto_material` id. |
| U5 | `u5` | accept | Attempt to use legacy dcode SAN or cert-embedded hash. |
| U6 | `u6` | accept | Turin report (fails, deferred). |

## AMBIGUOUS — no fixture until resolved (spec-questions)

  AM1, AM2, AM3, AM4, AM5

---
**Planned fixtures:** 116. Coverage gate: every non-AM rule id above has a passing fixture.
