# V3 Conformance — Spec Coverage Matrix
> Branch `feat/v3-conformance`. Living burn-down of every normative rule in the v3 spec
> (`SPEC_V3`, `POLICY_VALIDATION`, `PLATFORM_ENDORSEMENTS`, `VERIFICATION_ARCHITECTURE`,
> `FORMAT_DECISIONS`) against fixtures in this suite. Reference implementation: **tinfoil-go
> `feat/v3`** (pinned; if `pr/assembled-policy` ever lands, the SEV rows will correctly flag the
> exact-equality regression). Coexists with the v2 stages — v2 is retired per-SDK as it ports.

**Scope:** 121 normative rules — 116 across 9 layers (mapped to block-aligned stages below) + 5 ambiguous/underspecified (tracked as spec-questions, Phase 3). Each mappable rule needs ≥1 fixture (accept **and** reject where both are meaningful). Done = every rule has a fixture and a go-status (or, for ambiguous rules, a resolved spec-question).

**Coverage verdict (self-audit vs `POLICY_VALIDATION.md` field tables):** every field/bit of AMD Table 23 (+POLICY §2.1, PLATFORM_INFO §2.2) and Intel §3.1/§3.2/§3.2a (+TDATTRIBUTES §3.3, XFAM §3.4), all 8 enforcement classes, the 7 strict-parse rules, and every required SEV/TDX policy member has ≥1 catalog rule. 121/121 tracked (E14–E17 envelope-binding rules added after the slice-1 audit).

## How to use this file
- The **rule catalog** (bottom) is authoritative: `RULE_ID · doc-ref · layer · rule · accept-idea · reject-idea`. The accept/reject ideas ARE the fixture specs.
- Each authored fixture lists its `RULE_ID`s in `manifest.yaml: spec_refs`; a Phase-4 report cross-checks 100% coverage.
- Burn-down below: check a rule off when its fixture(s) land and go is graded (pass / go-bug filed / capability-gap tracked).

## Layer → block-aligned stage
| Layer | Rules | Stage | Block |
|---|--:|---|---|
| ENVELOPE | 13 | `v3-check-envelope` | B1 |
| PROVENANCE | 16 | `v3-authenticate-provenance` | B2 |
| QUOTE-SEV | 26 | `v3-authenticate-quote (sev)` | B3 |
| QUOTE-TDX | 25 | `v3-authenticate-quote (tdx)` | B3 |
| IDENTITY | 7 | `v3-assemble-policy` | B4a |
| POLICY | 12 | `v3-assemble-policy / v3-validate-quote` | B4a/B4b |
| STRUCTURAL | 4 | `v3-assemble-policy` | B4a |
| FRESHNESS | 3 | `v3-authenticate-provenance (capability-gated)` | B2 |
| UNCHECKED | 6 | `(negative assertions, cross-stage)` | — |

## Burn-down (check when fixture lands + go graded)

> Legend: `[x]` = fixtured, green, and reject-reason-audited. `[~]` =
> accounted-for by design, not fixturable (reason in the layer note): a
> deferred/not-yet-specified proposal, an explicitly-unenforced field, a
> sequencing property verified by end-to-end ordering, a defensive check
> unreachable via a well-formed input, or an open spec-question. `[ ]` = open.
> **Status: 107 `[x]` + 14 `[~]` = 121/121 accounted-for, 0 open.**

**ENVELOPE** (B1) — 17 rules

  `[x]E1` `[x]E2` `[x]E3` `[x]E4` `[x]E5` `[x]E6` `[x]E7` `[x]E8` `[x]E9` `[x]E10` `[x]E11` `[x]E12` `[x]E13` `[x]E14` `[x]E15` `[x]E16` `[x]E17`

**PROVENANCE** (B2) — 16 rules

  `[x]P1` `[x]P2` `[x]P3` `[x]P4` `[x]P5` `[x]P6` `[x]P7` `[x]P8` `[x]P9` `[x]P10` `[x]P11` `[x]P12` `[x]P13` `[x]P14` `[x]P15` `[x]P16`

  P2/P15/P16 (sigstore-platform presence, identity pin, expiry) are fixtured by
  `gen_policy.py` at the `v3-assemble-policy` stage (`p2`, `p15-workflow`,
  `p15-tag`, `p16`).

  Code-side rules (P1, P3–P14) are fixtured via `gen_provenance.py` against the
  `v3-authenticate-provenance` stage (26 fixtures, all green). P2 and P15
  (sigstore-platform presence / identity) and P16 (both-entries / expired) are
  platform-side and land with the identity slice, which builds the
  sigstore-platform bundle.

  **Branch audit (2026-08-05):** every JSON-reachable rejection site in the
  code-provenance path was cross-checked and confirmed to reject at its intended
  check. Rules with multiple sub-checks are split into per-branch fixtures: P11 →
  SAN / issuer / runner_environment (`p11-san`, `p11-issuer`, `p11-runner`);
  P13 → predicate-type plus the fail-closed measurement branches (`p13-no-tdx`,
  `p13-tdx-not-struct`, `p13-no-snp`, `p13-no-rtmr1`) and vm_shape branches
  (`p13-missing-shape`, `p13-shape-not-object`, `p13-shape-missing-member`,
  `p13-shape-negative`); P14 → tag-ref and workflow-path (`p14-ref`, `p14-path`).
  The only unfixtured branches are defensive nil-pointer checks unreachable via
  JSON (a present key always yields a non-nil `structpb.Value`).

**QUOTE-SEV** (B3) — 26 rules

  `[x]S1` `[x]S2` `[x]S3` `[x]S4` `[x]S5` `[x]S6` `[x]S7` `[x]S8` `[x]S9` `[x]S10` `[x]S11` `[x]S12` `[x]S13` `[x]S14` `[x]S15` `[x]S16` `[x]S17` `[x]S18` `[x]S19` `[x]S20` `[x]S21` `[x]S22` `[x]S23` `[x]S24` `[x]S25` `[x]S26`

  SEV is covered in two stages. **Authenticate** (`gen_sev.py` → `sev_synth.py`
  → `v3-authenticate-quote`, 13 fixtures): S1 version, S8/S25 signature, S12
  signer key, S20 product/CPUID, S26 root pinning + ASK revocation, plus
  collateral-shape checks. **Validate** (`gen_golden.py` → `verify-attestation-v3`
  on the golden document): S2 guest_svn, S3/S4 guest_policy, S5 family_id, S6
  image_id, S7 vmpl, S10/S11 platform_info, S13 report_data, S14 measurement,
  S15 host_data, S16 id/author-key-digest, S19/S23 TCB floors, S24 mitigation,
  and S21 chip_id lookup (via `i5-not-endorsed`). All reason-audited. The
  go-sev-guest `validateTcb` sub-checks are isolated (audit #11 finding —
  previously only `reported >= minimum` was exercised): S9 CURRENT_TCB < cert
  (`s9-current-tcb`), S19-vendor REPORTED_TCB != cert (`s19-vcek-cert-tcb`), S22
  COMMITTED_TCB != current (`s22-committed-tcb`). S17/S18 (REPORT_ID/REPORT_ID_MA
  unchecked) are the positive assertions `u1`/`u2`. **Finding:** go-sev-guest
  binds neither VCEK TCB nor VCEK HWID to the report at authentication — those
  are caught at validate (VCEK TCB via the report-TCB floor; chip_id via the
  machines-map lookup).

  **Depth (task #14):** the exact-equality bit rules are fixtured per-bit so a
  port comparing only some bits is caught — GUEST_POLICY S3/S4 (`s3-guest-policy`
  debug, `s4-smt`, `s4-migrate-ma`, `s4-single-socket`) and PLATFORM_INFO S10/S11
  (`s10-platform-info` smt, `s11-tsme`, `s11-ecc`, `s11-rapl`, `s11-ciphertext`);
  TDX TDATTRIBUTES DEBUG bit (`t11-td-debug`) and MROWNERCONFIG (`t16-mr-owner-config`).
  Boundary positives assert exactly-at-floor accepts (`pos-tcb-at-floor`,
  `pos-guest-svn-at-floor`) so a `>` vs `>=` off-by-one is caught. The
  required-member presence checks (SEV/TDX policy) are a uniform
  `case X == nil` family, covered representatively per struct (SEV top-level, TCB,
  launch-TCB, TDX) rather than one fixture per member.

**QUOTE-TDX** (B3) — 25 rules

  `[x]T1` `[x]T2` `[x]T3` `[x]T4` `[~]T5` `[x]T6` `[x]T7` `[x]T8` `[x]T9` `[x]T10` `[x]T11` `[x]T12` `[x]T13` `[x]T14` `[x]T15` `[x]T16` `[x]T17` `[x]T18` `[x]T19` `[x]T20` `[x]T21` `[x]T22` `[x]T23` `[x]T24` `[x]T25`

**IDENTITY** (B4a) — 7 rules

  `[~]I1` `[x]I2` `[x]I3` `[~]I4` `[x]I5` `[~]I6` `[x]I7`

**POLICY** (B4a/B4b) — 12 rules

  `[x]PL1` `[x]PL2` `[x]PL3` `[x]PL4` `[x]PL5` `[x]PL6` `[x]PL7` `[x]PL8` `[x]PL9` `[x]PL10` `[x]PL11` `[x]PL12`

**STRUCTURAL** (B4a) — 4 rules

  `[x]ST1` `[x]ST2` `[x]ST3` `[x]ST4`

  `gen_policy.py` fixtures the artifact machines-map and policy fail-closed rules
  reached through `policy.Parse` at the `v3-assemble-policy` stage (24 fixtures,
  all green, each confirmed to reject at its intended check): key formats (I2/I3/I7),
  the fail-closed policy family (PL1–PL5, PL9–PL12), and required shape metadata
  (ST3). The rules that key on a **verified quote** — identity extraction and
  lookup (I1/I4/I5/I6), the SEV/TDX comparison semantics (PL6/PL7/PL8), and shape
  filtering / exactly-one resolution (ST1/ST2/ST4) — are reached by the quote
  slices (`v3-validate-quote`) and land with SEV/TDX. Required-field presence
  checks are a uniform family, covered representatively per struct (SEV, TCB,
  launch-TCB, TDX) rather than one fixture per member.

**FRESHNESS** (B2) — 3 rules

  `[x]FR1` `[~]FR2` `[x]FR3`

  FR1 (nonce binding) is fixtured end-to-end by `gen_freshness.py` at
  `verify-attestation-v3`: `fr1-nonce-fresh` accepts, `fr1-nonce-stale` rejects
  when the verifier supplies a nonce other than the one bound into the quote's
  REPORT_DATA ladder — proving the verifier trusts its own nonce, not the
  document's (collateral-expiry beyond crypto validity is deliberately not
  enforced; capability `freshness_enforced=false`). FR3 (multiple endorsed
  MRTD/RTMR0 stacks accepted, no anti-rollback bound) is the positive
  `st2-multi-measurement`. FR2 (a periodically re-signed freshness witness) is a
  deferred, not-yet-specified proposal outside the v3 spec — nothing to enforce.

  Collateral *crypto-validity* windows (AMD/Intel CRL `ThisUpdate`/`NextUpdate`
  and certificate validity) **are** enforced against the verification clock.
  `gen_frozen_time.py` proves it and the `verification_time_unix` pin together:
  the same expired-CRL SEV document accepts pinned inside the CRL window and
  rejects pinned outside it. The pin also lets a real-frozen document replay
  offline forever — the accepting embedded-root lane, populated by
  `vectors/v3/real-frozen/real-sev-inference-tinfoil.json` (captured from the
  live `inference.tinfoil.sh` SEV-SNP enclave), the cross-SDK accept oracle of
  real production material.

**UNCHECKED** (—) — 6 rules (negative-assertion fixtures: prove these are *not* enforced / are ignored)

  `[x]U1` `[x]U2` `[~]U3` `[~]U4` `[~]U5` `[~]U6`

**AMBIGUOUS / DECIDE-LATER** (Phase 3 spec-questions — no accept/reject fixture until resolved) — 5 rules

  `[~]AM1` `[~]AM2` `[~]AM3` `[~]AM4` `[~]AM5`

> Burn-down total: **107 fixtured (`[x]`) + 14 accounted-for by design (`[~]`) = 121 / 121**, 0 open. Complete layers (fixtured, both-sided, reason-audited): ENVELOPE, PROVENANCE, QUOTE-SEV, POLICY, STRUCTURAL; QUOTE-TDX 24/25 (T5 by design); IDENTITY, UNCHECKED, FRESHNESS have their enforced rules fixtured and the rest documented `[~]`.

---

# Rule catalog (authoritative)

## Tinfoil Attestation v3 — Comprehensive Normative Rule Traceability Checklist

This checklist captures every testable normative rule (MUST/MUST-NOT/REQUIRED/SHALL/rejects/fails-closed/exact-match/floor statements) extractable from the v3 specification documents, organized by verification layer and enforcement class.

---

### ENVELOPE LAYER — Strict JSON Parsing & Document Shape (7 parsing rules + endorsement structure)

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **E1** | SPEC_V3.md §2.1, rule 1 | ENVELOPE | Top-level members MUST match schema byte-for-byte, case-sensitively. Unknown members anywhere in the fixed schema MUST reject. | Reject any document with `Format` (uppercase F) or `Challenge` (uppercase C); accept exact `format`, `challenge`, etc. | Valid JSON with correct member names. | Document with `Format` or unknown top-level field `extra_field`. |
| **E2** | SPEC_V3.md §2.1, rule 2 | ENVELOPE | No duplicate member names in any JSON object, including opaque regions (`collateral[].data`, `device_evidence` item `evidence`, Sigstore bundles). Duplicate-member behavior is a cross-parser differential; rejection is the only safe semantics. | Reject documents where any object contains duplicate keys (e.g., two `"format"` fields). | Valid JSON with unique keys throughout. | Document with duplicate `"format"` member in `challenge` block. |
| **E3** | SPEC_V3.md §2.1, rule 3 | ENVELOPE | Valid UTF-8 required. Input that is not well-formed UTF-8 MUST reject; parsers MUST NOT substitute U+FFFD in the trust path. | Reject documents with invalid UTF-8 byte sequences. | Valid UTF-8 document. | Document with non-UTF-8 bytes (e.g., `0xFF 0xFE` without valid continuation). |
| **E4** | SPEC_V3.md §2.1, rule 4 | ENVELOPE | Canonical base64 for endorsed sections: RFC 4648 standard alphabet with padding, no whitespace/line breaks, zero trailing padding bits. Re-encoding decoded bytes MUST reproduce the transmitted string. | Reject base64 with: line breaks, whitespace, non-standard alphabet (e.g., URL-safe), missing padding, or incorrect padding. | Valid canonical base64 (e.g., `SGVsbG8gV29ybGQ=` for "Hello World"). | Base64 with spaces: `SGVs bG8g V29y bGQ=`; or non-canonical padding: `SGVsbG8gV29ybGQ` (missing `=`); or URL-safe alphabet. |
| **E5** | SPEC_V3.md §2.1, rule 5 | ENVELOPE | Well-formed lowercase hex: fixed-length fields carry exactly the specified byte length; variable-length hex is non-empty and even-length. | Reject hex with uppercase letters (e.g., `ABCD`), odd length, or length mismatch. Reject empty hex. | Lowercase hex of correct length: `abcd1234...` (32 bytes = 64 chars for nonce, etc.). | Hex with uppercase: `ABCD1234`; odd length: `abc`; length mismatch: 31-byte `nonce` instead of 32. |
| **E6** | SPEC_V3.md §2.1, rule 6 | ENVELOPE | No trailing data after the top-level JSON value. | Reject documents with extra bytes/characters after the JSON object closes. | Valid JSON with no trailing bytes. | Document with trailing `,` or `}}}` or extra whitespace after the JSON. |
| **E7** | SPEC_V3.md §2, lines 32–68, §3, lines 108–162 | ENVELOPE | Document shape: exactly five top-level members (`format`, `challenge`, `cpu_evidence`, `crypto_material`, `device_evidence`) + one optional `collateral` array. No `domain`, `generated_at`, `certificates`, or other members. `format` MUST equal `https://tinfoil.sh/predicate/attestation/v3`. | Reject documents missing required members or containing legacy/unknown members. | Document with all five required members, `collateral` array, correct `format` URI. | Document missing `crypto_material`; or with legacy `generated_at`; or with `format: v2`. |
| **E8** | SPEC_V3.md §2, challenge block | ENVELOPE | `challenge.nonce` REQUIRED (32 bytes lowercase hex). `challenge.report_data` REQUIRED (64 bytes lowercase hex). `challenge.report_data_algorithm` REQUIRED and MUST equal `https://tinfoil.sh/report-data/v1`. | Reject if any missing or wrong format. | Valid challenge with all three fields correct. | Missing `challenge.nonce`; or `report_data` not 64 bytes; or wrong algorithm URI. |
| **E9** | SPEC_V3.md §2, cpu_evidence block | ENVELOPE | `cpu_evidence.format` REQUIRED, MUST be either `https://tinfoil.sh/format/sev-snp-report/v1` or `https://tinfoil.sh/format/tdx-quote/v1`. `cpu_evidence.report_base64` REQUIRED (base64). `cpu_evidence.endorsed.crypto_material_hash` and `endorsed.device_evidence_hash` REQUIRED (32-byte lowercase hex each). | Reject if format unknown, hashes wrong format, or required fields missing. | Valid SEV or TDX format with correct endorsed hashes. | Unknown format URI; or hashes not 32 bytes. |
| **E10** | SPEC_V3.md §3, lines 108–162 | ENVELOPE | `crypto_material` and `device_evidence` REQUIRED base64 strings. Decoded, each must be a JSON object with `{"format": "...", "items": [...]}`. Within each section, items MUST NOT have duplicate `id` fields. | Reject if sections cannot be base64-decoded, are not JSON objects, missing `format` URI, or have duplicate item `id`s. | Valid sections with unique item ids. | Invalid base64; non-JSON; missing `format` URI; duplicate `id`s (two items with `"id": "tls"`). |
| **E11** | SPEC_V3.md §3, lines 143–149 | ENVELOPE | `crypto_material` items shape: each must have `id`, `format`, `data` (all required). `format` URIs must be from the registry (e.g., `spki-fp-sha256/v1`, `x25519-hpke/v1`). Unknown *section* format URIs MUST reject. Unknown *item* formats are acceptable only if the appraisal policy does not require verifying that key/device. | Reject unknown section format. Accept unknown item format only if not policy-required. | Valid items with registered format URIs. | Unknown section format URI. |
| **E12** | SPEC_V3.md §3, lines 130–139, device_evidence | ENVELOPE | `device_evidence` items: each must have `id`, `kind`, `vendor`, `format`, `evidence` (all required). `kind` values: `gpu` or other registered device kinds. Unknown *item* formats acceptable only if policy does not require that device. | Reject if required fields missing or unknown section format. | Valid device evidence items with registered formats, or empty `items: []`. | Missing `vendor` or `kind` field; unknown section format. |
| **E13** | SPEC_V3.md §2, collateral | ENVELOPE | `collateral` array REQUIRED (may be empty `[]`). Each entry has `id` (unique within array), `role` (endorsement or reference-values), `format` (registry URI), `subjects` (array of strings; omitted for reference-values), `data` (object). Unknown formats ignored in collateral (unendorsed input); missing required entries detected naturally during verification. | Reject if collateral entry format is unknown but essential (e.g., VCEK missing for SEV). | Valid collateral entries with correct `id` uniqueness and format URIs. | Duplicate `id` values in collateral array. |
| **E14** | SPEC_V3.md §4; envelope.Check | ENVELOPE | BINDING: `challenge.nonce` MUST equal the verifier-supplied nonce (freshness; the document nonce is an echo, never the source of truth). | reject a well-formed doc whose nonce ≠ the verifier nonce | nonce == verifier nonce | valid 32-byte nonce ≠ verifier nonce |
| **E15** | SPEC_V3.md §4; envelope.Check | ENVELOPE | BINDING: `cpu_evidence.endorsed.crypto_material_hash` MUST equal SHA-256(crypto_material section bytes as transmitted). | reject valid 32-byte hash ≠ recomputed section hash | hash == SHA-256(section) | valid hash ≠ SHA-256(section) |
| **E16** | SPEC_V3.md §4; envelope.Check | ENVELOPE | BINDING: `cpu_evidence.endorsed.device_evidence_hash` MUST equal SHA-256(device_evidence section bytes). | reject valid hash ≠ recomputed | hash == SHA-256(section) | valid hash ≠ SHA-256(section) |
| **E17** | SPEC_V3.md §4; envelope.Check | ENVELOPE | BINDING: `challenge.report_data` MUST equal SHA-256(LABEL ‖ nonce ‖ crypto_material_hash ‖ device_evidence_hash) with [32:64]=0 (the ladder). | reject valid 64-byte report_data ≠ recomputed ladder | report_data == recomputed | valid 64-byte value ≠ recomputed ladder |

> **Added after the slice-1 audit (2026-08-04):** E14–E17 are the envelope *binding* checks in `envelope.Check` (nonce equality, the two endorsed-section hash bindings, and the report_data ladder recompute). The original enumeration captured only the §2.1 parse/shape rules (E1–E13) and missed these four — they are the core freshness/hash-binding of the envelope. Now fixtured (`e14`–`e17`).

---

### PROVENANCE LAYER — Sigstore Code & Platform Bundle Verification

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **P1** | VERIFICATION_ARCHITECTURE.md §3.2, ARCH Step 2 | PROVENANCE | Required `sigstore-code` collateral entry (role=reference-values) with verified code measurement and declared `vm_shape`. | Reject if missing. | Valid sigstore-code entry with verified bundle. | Document without sigstore-code collateral. |
| **P2** | VERIFICATION_ARCHITECTURE.md §3.2, ARCH Step 2 | PROVENANCE | Required `sigstore-platform` collateral entry (role=reference-values) with verified platform-endorsements artifact (machines map + policies). | Reject if missing or unverifiable. | Valid sigstore-platform entry with machines/policies. | Document without sigstore-platform collateral. |
| **P3** | VERIFICATION_ARCHITECTURE.md §3.2, lines 226–249 | PROVENANCE | Sigstore bundle shape (before cryptography): must parse as protobuf bundle, v0.3 single-certificate layout only. Legacy `x509CertificateChain` layout REJECTED. | Reject legacy bundle layouts. | v0.3 single-cert bundle. | Legacy multi-cert bundle layout. |
| **P4** | VERIFICATION_ARCHITECTURE.md §3.2, check 2 | PROVENANCE | DSSE-envelope bundle carries exactly one signature; zero or several REJECT. | Reject if bundle has 0 or >1 signature. | Bundle with exactly 1 signature. | Bundle with 0 signatures; bundle with 2+ signatures. |
| **P5** | VERIFICATION_ARCHITECTURE.md §3.2, check 3 | PROVENANCE | Signing certificate chains to the Fulcio root (embedded Sigstore trusted root, pinned in verifier). | Reject if chain does not reach pinned Fulcio root. | Valid chain to Fulcio. | Chain to untrusted root. |
| **P6** | VERIFICATION_ARCHITECTURE.md §3.2, check 4 | PROVENANCE | At least one SCT (Signed Certificate Timestamp) embedded in the leaf verifies against a trusted CT log key; certificate issuance was publicly logged. | Reject if no valid SCT or SCT verification fails. | Certificate with ≥1 valid SCT. | Certificate with 0 SCTs or invalid SCTs. |
| **P7** | VERIFICATION_ARCHITECTURE.md §3.2, check 5 | PROVENANCE | At least one transparency-log (Rekor) entry verifies against the pinned log key and matches this signature and certificate; signing event is publicly auditable. | Reject if no Rekor entry or entry verification fails. | Bundle with ≥1 valid Rekor entry. | Bundle with 0 Rekor entries. |
| **P8** | VERIFICATION_ARCHITECTURE.md §3.2, check 6 | PROVENANCE | At least one verified observer timestamp places the signature inside the certificate's validity window; Fulcio certificates live minutes, so validity is checked at signing time. | Reject if no valid observer timestamp or timestamp outside cert window. | Bundle with valid observer timestamp in cert window. | Bundle with observer timestamp outside certificate validity. |
| **P9** | VERIFICATION_ARCHITECTURE.md §3.2, check 7 | PROVENANCE | DSSE envelope signature verifies under the leaf certificate's key; payload is an in-toto statement. | Reject if signature verification fails or payload is not in-toto. | Valid DSSE signature over in-toto statement. | Invalid DSSE signature; non-in-toto payload. |
| **P10** | VERIFICATION_ARCHITECTURE.md §3.2, check 8 | PROVENANCE | Statement's **subject[0]** sha256 digest MUST equal the expected digest (from the collateral entry itself). Only the first subject is matched; any-subject matching is explicitly forbidden. | Reject if subject[0] digest does not match. | In-toto statement with matching subject[0] digest. | Statement with subject[0] digest mismatch; multi-subject statements (use first). |
| **P11** | VERIFICATION_ARCHITECTURE.md §3.2, check 9 | PROVENANCE | Certificate OIDC issuer extension MUST equal GitHub Actions issuer. `runner_environment` extension MUST equal `github-hosted` (claim from OIDC token; prevents operator-controlled self-hosted infra from impersonating the build). SAN MUST match the pinned identity pattern (repository slug + workflow path + ref constraint, fully escaped and anchored). | Reject if issuer/runner_environment wrong or SAN does not match pattern. | Certificate with correct issuer, runner_environment, and matching SAN. | Self-hosted runner; wrong issuer; unescaped SAN; SAN with trailing content. |
| **P12** | VERIFICATION_ARCHITECTURE.md §3.2, check 10 | PROVENANCE | No two embedded SCTs may share a CT log id (a single compromised log must not satisfy the SCT requirement more than once). | Reject if two or more SCTs from the same log. | Bundle with SCTs from different logs (or 1 SCT). | Bundle with 2+ SCTs from same CT log. |
| **P13** | VERIFICATION_ARCHITECTURE.md §3.2, check 11 | PROVENANCE | Statement predicate type MUST equal the expected URI for the artifact kind (e.g., `snp-tdx-multiplatform/v1` for code; `platform-endorsements/v1` for platform). Predicate content is parsed fail-closed per its own schema. | Reject if predicate type wrong or predicate fails schema validation. | Valid predicate type and schema-compliant content. | Wrong predicate URI; schema-violating predicate (unknown field reject). |
| **P14** | VERIFICATION_ARCHITECTURE.md §3.2, lines 278–285, CONFORMANCE.md §1.2 | PROVENANCE | Code-repo identity pinning (asymmetric to platform-endorsements, per CONFORMANCE G13): SAN pattern is `^https://github.com/<repo>/.github/workflows/.*@refs/tags/*$` (any workflow file under `.github/workflows/`, anchored). Repository slug validated and regex-escaped. Tag refs only; wildcards allowed on workflow filename. Tighten to per-repo workflow pins via identity patterns as future configuration. | Reject if SAN does not match pattern (e.g., wrong repo, wrong tag ref type, unanchored). | Code-repo SAN with wildcard workflow file. | SAN with wrong repo; non-tag ref; wildcard workflow path outside `.github/workflows/`. |
| **P15** | PLATFORM_ENDORSEMENTS.md §1, VERIFICATION_ARCHITECTURE.md §3.2, lines 285 | PROVENANCE | Platform-endorsements identity pinning (tight): SAN pattern is `^https://github.com/tinfoilsh/platform-endorsements/.github/workflows/build\.yml@refs/tags/v[0-9].*$` (specific workflow filename, specific tag prefix, fully escaped and anchored). | Reject if SAN does not match this specific pattern. | SAN matching `build.yml` with `v<digit>` tag. | SAN with different workflow file; tag without `v` prefix; unanchored pattern. |
| **P16** | SPEC_V3.md §5, line 212 | PROVENANCE | Sigstore bundles verified against Sigstore trusted root and pinned Tinfoil workflow identity; both required entries must be present and verifiable. Expired entries MUST REJECT (per their own validity metadata). | Reject if either required entry missing or expired. | Valid bundles with verified signatures. | Missing sigstore-code or sigstore-platform entry; expired bundle. |

---

### QUOTE-SEV LAYER — AMD SEV-SNP Report Verification

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **S1** | SPEC_V3.md §5, lines 219–220 | QUOTE-SEV | Report VERSION field MUST be ≥ 3. Pre-v3 reports carry no CPUID product identity and MUST REJECT. | Reject report with VERSION < 3. | Report VERSION = 3 or higher. | Report VERSION = 2. |
| **S2** | POLICY_VALIDATION.md §2, Table 23, offset 04h | QUOTE-SEV | GUEST_SVN: policy (floor) — `minimum_guest_svn`. | Reject if report GUEST_SVN < policy minimum. | Report with GUEST_SVN ≥ minimum. | Report with GUEST_SVN < minimum. |
| **S3** | POLICY_VALIDATION.md §2, Table 23, offset 08h, §2.1 | QUOTE-SEV | POLICY (bits 16–25): exact equality on all bits. Bit 17 (reserved, must be 1) parse-rejected if clear; bits 63:26 (reserved, MBZ) parse-rejected if set. Future bits fail closed. | Reject if any unspecified bits set or reserved bits wrong. | Policy matching report bits exactly. | Report with bit 17 = 0 or reserved bits set. |
| **S4** | POLICY_VALIDATION.md §2.1, Table 10 | QUOTE-SEV | POLICY member bits enforced by exact equality: `debug`, `smt`, `migrate_ma`, `single_socket`, `page_swap_disable`, `ciphertext_hiding_dram`, `rapl_dis`, `mem_aes256_xts`, `cxl_allowed`. Absent boolean = false; must match exactly. | Reject if any policy bit differs from report bit. | Report and policy with matching bits. | Report with different bit value than policy (e.g., policy `debug: false` but report has DEBUG set). |
| **S5** | POLICY_VALIDATION.md §2, Table 23, offset 10h | QUOTE-SEV | FAMILY_ID: policy (exact) — 16 bytes hex. | Reject if report FAMILY_ID does not match policy. | Report with matching FAMILY_ID. | Report FAMILY_ID mismatch. |
| **S6** | POLICY_VALIDATION.md §2, Table 23, offset 20h | QUOTE-SEV | IMAGE_ID: policy (exact) — 16 bytes hex. | Reject if report IMAGE_ID does not match policy. | Report with matching IMAGE_ID. | Report IMAGE_ID mismatch. |
| **S7** | POLICY_VALIDATION.md §2, Table 23, offset 30h | QUOTE-SEV | VMPL: policy (exact) — must be 0–3, MUST match policy exactly. | Reject if report VMPL does not match policy or is out of range. | Report VMPL matching policy (0–3). | Report VMPL mismatch or out-of-range (e.g., 5). |
| **S8** | POLICY_VALIDATION.md §2, Table 23, offset 34h | QUOTE-SEV | SIGNATURE_ALGO: structural, ECDSA P-384 enforced by signature verification. | Reject if signature verification fails (algorithm mismatch). | Valid ECDSA P-384 signature. | Non-ECDSA algorithm or signature verification failure. |
| **S9** | POLICY_VALIDATION.md §2, Table 23, offset 38h, §2.2 | QUOTE-SEV | CURRENT_TCB: policy (floor) — ≥ VCEK-certificate TCB (which equals REPORTED_TCB, floored by `minimum_tcb`). Additionally, if `permit_provisional_firmware: false`, then CURRENT_TCB MUST equal COMMITTED_TCB. | Reject if report CURRENT_TCB < minimum or (provisional=false and CURRENT ≠ COMMITTED). | Report with CURRENT_TCB ≥ minimum; or CURRENT=COMMITTED if provisional forbidden. | Report CURRENT_TCB < minimum; or CURRENT ≠ COMMITTED when provisional forbidden. |
| **S10** | POLICY_VALIDATION.md §2, Table 23, offset 40h, §2.2 | QUOTE-SEV | PLATFORM_INFO: policy (exact) — all bits compared with exact equality. Reserved bits parse-rejected if set. Future bits fail closed. | Reject if any PLATFORM_INFO bit differs from policy or reserved bits are set. | Report with matching PLATFORM_INFO bits. | Report PLATFORM_INFO bit mismatch; reserved bits set. |
| **S11** | POLICY_VALIDATION.md §2.2, Table 24 | QUOTE-SEV | PLATFORM_INFO bits enforced by exact equality: `smt_enabled`, `tsme_enabled`, `ecc_enabled`, `rapl_disabled`, `ciphertext_hiding_dram`, `alias_check_complete` (CVE-2024-21944 mitigation), `tio_enabled`. Absent boolean = false; must match exactly. | Reject if any platform_info bit differs from report. | Report and policy with matching bits. | Report with different platform_info bit (e.g., policy `smt_enabled: false` but report has SMT_EN set). |
| **S12** | POLICY_VALIDATION.md §2, Table 23, offset 48h.4:2, offset 48h.1, offset 48h.0 | QUOTE-SEV | SIGNING_KEY (structural): only VCEK supplied; VLEK-signed reports FAIL-CLOSE. MASK_CHIP_KEY (structural, fail-closed): masked CHIP_ID is all-zero and absent from machines map. AUTHOR_KEY_EN (sdk): must be 0 (ID-block launches unsupported; policies requiring them reject at parse). | Reject VLEK-signed reports. Reject if AUTHOR_KEY_EN=1 without policy support. Masked CHIP_ID fails naturally in machines lookup. | VCEK-signed report with AUTHOR_KEY_EN=0. | VLEK-signed report; AUTHOR_KEY_EN=1; masked CHIP_ID (all-zero). |
| **S13** | SPEC_V3.md §4, POLICY_VALIDATION.md §5.1 | QUOTE-SEV | REPORT_DATA: envelope (recomputed from verifier's nonce, crypto_material hash, device_evidence hash). Must equal report REPORT_DATA field exactly. Recomputation uses verifier-supplied nonce, NOT document's nonce. | Reject if recomputed REPORT_DATA ≠ report REPORT_DATA. | Report with REPORT_DATA matching recomputation. | Report REPORT_DATA mismatch (e.g., wrong nonce used). |
| **S14** | POLICY_VALIDATION.md §2, Table 23, offset 90h | QUOTE-SEV | MEASUREMENT: code (from verified code provenance). Must equal the attested launch digest from the Sigstore-verified code measurement exactly. | Reject if report MEASUREMENT ≠ code measurement. | Report with MEASUREMENT matching code artifact. | Report MEASUREMENT mismatch. |
| **S15** | POLICY_VALIDATION.md §2, Table 23, offset C0h | QUOTE-SEV | HOST_DATA: policy (exact) — 32 bytes hex; all-zero in Tinfoil launches. Must match policy exactly. | Reject if report HOST_DATA does not match policy. | Report with matching HOST_DATA (typically all-zero). | Report HOST_DATA mismatch. |
| **S16** | POLICY_VALIDATION.md §2, Table 23, offset E0h, offset 110h | QUOTE-SEV | ID_KEY_DIGEST (sdk): must be all-zero. AUTHOR_KEY_DIGEST (sdk): must be all-zero. | Reject if either is non-zero. | Report with both all-zero. | Report with non-zero ID_KEY_DIGEST or AUTHOR_KEY_DIGEST. |
| **S17** | POLICY_VALIDATION.md §4, lines 245–249 | QUOTE-SEV | REPORT_ID: unchecked — random per-guest identifier; no expected value exists. | No enforcement; any value accepted. | Any REPORT_ID value. | N/A (no rejection criterion). |
| **S18** | POLICY_VALIDATION.md §4, lines 250–251 | QUOTE-SEV | REPORT_ID_MA: unchecked when `migrate_ma: false` is enforced by policy (which disallows any MA). | No enforcement; rejection occurs via REPORT_ID_MA policy check or migrate_ma flag. | REPORT_ID_MA value with migrate_ma=false policy. | N/A (policy enforcement covers this). |
| **S19** | POLICY_VALIDATION.md §2, Table 23, offset 180h | QUOTE-SEV | REPORTED_TCB: policy (floor) + vendor — ≥ `minimum_tcb`; additionally must exactly equal the TCB in the VCEK certificate's extensions. | Reject if report REPORTED_TCB < minimum or ≠ VCEK cert TCB. | Report REPORTED_TCB matching VCEK cert and ≥ minimum. | Report REPORTED_TCB < minimum; or REPORTED_TCB ≠ VCEK TCB. |
| **S20** | POLICY_VALIDATION.md §2, Table 23, offset 188h–18Ah | QUOTE-SEV | CPUID_FAM/MOD/STEP (structural): selects product line (Genoa vs. Turin); zero REJECTS. VCEK must chain to pinned roots for that product (issuer CN `SEV-<product>`). | Reject if CPUID fields are all-zero. Verify VCEK chains to correct product root. | Report with valid CPUID fields; VCEK for matching product. | Report with all-zero CPUID; VCEK from wrong product. |
| **S21** | POLICY_VALIDATION.md §2, Table 23, offset 1A0h | QUOTE-SEV | CHIP_ID: identity (64 bytes hex) — machines-map key. Extract from verified report, look up in platform-endorsements machines map. Absent identifier MUST REJECT. Also re-pinned into `ChipID` in validation options. | Reject if CHIP_ID not found in machines map. | Report with CHIP_ID in machines map. | Report with CHIP_ID not in machines map (e.g., unknown machine). |
| **S22** | POLICY_VALIDATION.md §2, Table 23, offset 1E0h, offset 1E8h–1EEh | QUOTE-SEV | COMMITTED_TCB: policy (floor) — ≥ `minimum_tcb`. CURRENT/COMMITTED BUILD/MINOR/MAJOR: policy (floor) — ≥ `minimum_build`, `minimum_api_version`. If `permit_provisional_firmware: false`, then CURRENT and COMMITTED must match exactly. | Reject if any TCB component < minimum or provisional=false and versions differ. | Report with TCB components ≥ minimum; CURRENT=COMMITTED if provisional forbidden. | Report TCB < minimum; or CURRENT ≠ COMMITTED when provisional forbidden. |
| **S23** | POLICY_VALIDATION.md §2, Table 23, offset 1F0h | QUOTE-SEV | LAUNCH_TCB: policy (floor) — ≥ `minimum_launch_tcb`. | Reject if report LAUNCH_TCB < minimum. | Report with LAUNCH_TCB ≥ minimum. | Report LAUNCH_TCB < minimum. |
| **S24** | POLICY_VALIDATION.md §2, Table 23 (v5 fields) | QUOTE-SEV | LAUNCH_MIT_VECTOR / CURRENT_MIT_VECTOR: policy (floor, bitmask superset) — every minimum bit must be set in report. | Reject if report vector is missing any required bits. | Report with all required mitigation vector bits set. | Report missing required mitigation bits. |
| **S25** | POLICY_VALIDATION.md §2, Table 23, offset 2A0h, VERIFICATION_ARCHITECTURE.md §3.3 | QUOTE-SEV | SIGNATURE (structural): ECDSA over bytes 0h–29Fh. Chain verification: VCEK ← ASK ← ARK to AMD product roots (pinned). ASK checked against the document-carried CRL (validity-window checked by SDK). Revocation MUST be checked; `amd-crl/v1` collateral entry REQUIRED. | Reject if signature verification fails, chain does not reach pinned root, or revocation check fails (missing CRL = fail-closed). | Valid ECDSA signature with complete cert chain; valid CRL. | Invalid signature; chain to untrusted root; missing or revoked certificate. |
| **S26** | SPEC_V3.md §5, line 215 | QUOTE-SEV | AMD product roots (Genoa + Turin) MUST be pinned in the verifier. The VCEK certificate must chain to one of these roots; VCEK revocation checked against the REQUIRED `amd-crl` collateral entry. | Reject if VCEK chain does not reach pinned root or CRL check fails. | VCEK certificate with valid chain to Genoa (or Turin) root. | VCEK from untrusted root; broken chain; missing CRL. |

---

### QUOTE-TDX LAYER — Intel TDX Quote v4 Verification

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **T1** | POLICY_VALIDATION.md §3, lines 117–121 | QUOTE-TDX | Only quote format v4 with TDX 1.0 body accepted; any other version REJECTS. (v5 adds body descriptor, TEE_TCB_SVN_2, MRSERVICETD, partitioning for TDX 1.5 — deliberate future upgrade.) | Reject if quote Version ≠ 4 or body is not TDX 1.0. | Quote format v4 with TDX 1.0 body. | Quote format v3 or v5; non-TDX-1.0 body. |
| **T2** | POLICY_VALIDATION.md §3.1, Table 31, bytes 0–1, 2–3, 4–7 | QUOTE-TDX | Header Version MUST be 4. Attestation Key Type MUST be ECDSA P-256 (2), enforced by signature verification. TEE Type MUST be 0x00000081 (TDX), enforced by library. | Reject if Version ≠ 4, Key Type ≠ 2, or TEE Type ≠ 0x00000081. | Quote with Version=4, Key Type=2, TEE Type=0x00000081. | Quote with Version ≠ 4, wrong Key Type, or wrong TEE Type. |
| **T3** | POLICY_VALIDATION.md §3.1, Table 31, bytes 8–11 | QUOTE-TDX | RESERVED (2×2) header bytes MUST be zero. The vendor library parses these as SGX-style QE/PCE SVN fields and never constrains them; the SDK pins these explicitly (fail-closed). | Reject if any of bytes 8–11 are non-zero. | Quote with RESERVED bytes all-zero. | Quote with non-zero RESERVED bytes. |
| **T4** | POLICY_VALIDATION.md §3.1, Table 31, bytes 12–27 | QUOTE-TDX | QE Vendor ID: policy (exact) — 16 bytes hex (Intel: `939a7233f79c4ca9940a0db3957f0607`). Must match policy exactly. | Reject if QE Vendor ID does not match policy. | Quote with matching QE Vendor ID. | Quote with different QE Vendor ID. |
| **T5** | POLICY_VALIDATION.md §3.1, Table 31, bytes 28–47 | QUOTE-TDX | User Data: unchecked — QE-written platform identifier (QE_ID, links PCK cert to Enc(PPID) in caching services); generated from platform sealing keys, no off-platform expected value exists. | No enforcement; any value accepted. | Any User Data value. | N/A (no rejection criterion). |
| **T6** | POLICY_VALIDATION.md §3.2, Table 32, bytes 0–15 | QUOTE-TDX | TEE_TCB_SVN: policy (floor) + vendor — per-byte floor `minimum_tee_tcb_svn` (16 bytes hex); additionally matched per-component against Intel TCB Info levels, whose selected status MUST be exactly `UpToDate`. | Reject if any TEE_TCB_SVN byte < minimum or TCB Info status ≠ `UpToDate`. | Quote with TEE_TCB_SVN ≥ minimum and `UpToDate` status. | Quote TEE_TCB_SVN byte < minimum; or TCB Info status not `UpToDate`. |
| **T7** | POLICY_VALIDATION.md §3.2, Table 32, bytes 16–63 | QUOTE-TDX | MRSEAM: policy (exact) — single value per policy. Machine running either of two module versions gets two policies, never one policy with two accepted values. | Reject if quote MRSEAM does not match policy's single `mr_seam` value. | Quote with MRSEAM matching policy. | Quote with MRSEAM ≠ policy `mr_seam`. |
| **T8** | POLICY_VALIDATION.md §3.2, Table 32, bytes 64–111 | QUOTE-TDX | MRSIGNERSEAM: vendor — compared against TCB Info `TdxModule.Mrsigner` (zero for Intel modules). | Reject if MRSIGNERSEAM does not match vendor expectation. | Quote with MRSIGNERSEAM matching Intel's value. | Quote with MRSIGNERSEAM ≠ Intel expectation. |
| **T9** | POLICY_VALIDATION.md §3.2, Table 32, bytes 112–119 | QUOTE-TDX | SEAMATTRIBUTES: vendor — masked comparison against TCB Info `TdxModule.AttributesMask` (must be zero for TDX 1.0). | Reject if masked SEAMATTRIBUTES comparison fails or mask ≠ 0 for TDX 1.0. | Quote with SEAMATTRIBUTES matching masked vendor expectation. | Quote with SEAMATTRIBUTES mismatch; non-zero mask for TDX 1.0. |
| **T10** | POLICY_VALIDATION.md §3.2, Table 32, bytes 120–127, §3.3 | QUOTE-TDX | TDATTRIBUTES: policy (exact) — full 8-byte field pinned as exact hex. Every §A.3.4 bit enforced (all bits, including reserved). | Reject if quote TDATTRIBUTES ≠ policy `td_attributes`. | Quote with TDATTRIBUTES matching policy (typically all-zero with only bit 28 set). | Quote TDATTRIBUTES ≠ policy; e.g., DEBUG bit set or reserved bit non-zero. |
| **T11** | POLICY_VALIDATION.md §3.3 | QUOTE-TDX | TDATTRIBUTES bits exact equality: DEBUG (bit 0, must be 0), reserved bits 7:1 and 27:8 and 29 and 62:32 (must be 0), SEPT_VE_DISABLE (bit 28, must be 1 for Linux), PKS (bit 30, must be 0), KL (bit 31, must be 0), PERFMON (bit 63, must be 0). | Reject if any bit does not match expected value. | Quote with TDATTRIBUTES pinned to policy (e.g., `0x0000001000000000`). | Quote with DEBUG=1, SEPT_VE_DISABLE=0, or other mismatches. |
| **T12** | POLICY_VALIDATION.md §3.2, Table 32, bytes 128–135 | QUOTE-TDX | XFAM: policy (exact) — full 8-byte field pinned as exact hex. Every bit enforced (all bits, including reserved). Wire value is little-endian. | Reject if quote XFAM ≠ policy `xfam`. | Quote with XFAM matching policy (e.g., `e702060000000000`). | Quote XFAM ≠ policy; e.g., wrong FP/SSE/AVX bits. |
| **T13** | POLICY_VALIDATION.md §3.4 | QUOTE-TDX | XFAM bits exact equality: FP (bit 0, fixed-1), SSE (bit 1, fixed-1), AVX (bit 2, typically 1), MPX (bits 4:3, typically 0), AVX-512 (bits 7:5, typically 1,1,1), PT (bit 8, typically 0), PK (bit 9, typically 1), ENQCMD (bit 10, typically 0), CET (bits 12:11, typically 0), HDC (bit 13, typically 0), ULI (bit 14, typically 0), LBR (bit 15, typically 0), HWP (bit 16, typically 0), AMX (bits 18:17, typically 1,1), reserved (bits 63:19, must be 0). | Reject if any bit does not match policy. | Quote with XFAM matching policy. | Quote with different XFAM bits (e.g., reserved bits set). |
| **T14** | POLICY_VALIDATION.md §3.2, Table 32, bytes 136–183, §5.4 | QUOTE-TDX | MRTD: policy (derived/resolved) — platform measurement resolved from authenticated quote MRTD/RTMR0 lookup within shape-filtered policy entries. Selected entry's MRTD pinned as exact. | Reject if quote MRTD does not match resolved platform measurement. | Quote with MRTD matching resolved measurement entry. | Quote MRTD ≠ any shape-filtered measurements in policy. |
| **T15** | POLICY_VALIDATION.md §3.2, Table 32, bytes 184–231 | QUOTE-TDX | MRCONFIGID: sdk (pinned all-zero) — unused by Tinfoil launches. Must be all-zero. | Reject if MRCONFIGID ≠ 0. | Quote with MRCONFIGID all-zero. | Quote with non-zero MRCONFIGID. |
| **T16** | POLICY_VALIDATION.md §3.2, Table 32, bytes 232–279, 280–327 | QUOTE-TDX | MROWNER / MROWNERCONFIG: sdk (pinned all-zero) — unused by Tinfoil launches. Both must be all-zero. | Reject if either ≠ 0. | Quote with MROWNER and MROWNERCONFIG all-zero. | Quote with non-zero MROWNER or MROWNERCONFIG. |
| **T17** | POLICY_VALIDATION.md §3.2, Table 32, bytes 328–375 | QUOTE-TDX | RTMR0: policy (derived/resolved) — platform measurement resolved from authenticated quote RTMR0 + MRTD lookup within shape-filtered policy entries. Selected entry's RTMR0 pinned as exact. | Reject if quote RTMR0 does not match resolved measurement entry. | Quote with RTMR0 matching resolved measurement. | Quote RTMR0 ≠ any shape-filtered measurements. |
| **T18** | POLICY_VALIDATION.md §3.2, Table 32, bytes 376–423, 424–471 | QUOTE-TDX | RTMR1 / RTMR2: code (from verified code provenance) — expected workload registers from Sigstore-attested build predicate. Must match exactly. | Reject if quote RTMR1 or RTMR2 ≠ code measurement. | Quote with RTMR1/RTMR2 matching code artifact. | Quote RTMR1/RTMR2 mismatch. |
| **T19** | POLICY_VALIDATION.md §3.2, Table 32, bytes 472–519 | QUOTE-TDX | RTMR3: sdk (pinned all-zero) — never extended by Tinfoil workloads. Must be all-zero. | Reject if RTMR3 ≠ 0. | Quote with RTMR3 all-zero. | Quote with non-zero RTMR3. |
| **T20** | SPEC_V3.md §4, POLICY_VALIDATION.md §5.1 | QUOTE-TDX | REPORTDATA: envelope (recomputed from verifier's nonce, crypto_material hash, device_evidence hash). Must equal quote REPORTDATA field exactly. Recomputation uses verifier-supplied nonce, NOT document's nonce. | Reject if recomputed REPORTDATA ≠ quote REPORTDATA. | Quote with REPORTDATA matching recomputation. | Quote REPORTDATA mismatch. |
| **T21** | POLICY_VALIDATION.md §3.2a, bytes (QE Report) 0–15, 16–19, 48–63, 128–159, 256–259, 320–383 | QUOTE-TDX | QE Report (signature section): CPUSVN, MISCSELECT, ATTRIBUTES, MRSIGNER, ISVPRODID, ISVSVN all vendor-checked against TCB Info / QE Identity. REPORTDATA must equal SHA-256(attestation key ‖ QE auth data), binding attestation key to QE. | Reject if QE Report fields do not verify against vendor collateral. | QE Report with valid vendor matches. | QE Report with mismatched fields or REPORTDATA. |
| **T22** | POLICY_VALIDATION.md §3.2a, lines 185–192 | QUOTE-TDX | PCESVN (not a report field, but in PCK leaf SGX extension): matched against TCB Info levels, selected status MUST be exactly `UpToDate`. Policy carries no QE/PCE SVN floors; the library's `MinimumQeSvn`/`MinimumPceSvn` options compare reserved v4 header bytes (which SDK pins to zero). Real SVN enforcement is Intel's signed collateral. | Reject if PCESVN or QE ISVSVN status ≠ `UpToDate`. | Quote with `UpToDate` status in collateral. | Collateral with non-`UpToDate` status. |
| **T23** | POLICY_VALIDATION.md §3.2a, lines 193–197 | QUOTE-TDX | Collateral-level floor: `tcbEvaluationDataNumber` observed in verified TCB Info and QE Identity MUST meet policy floor `minimum_tcb_evaluation_data_number`; unobserved REJECTS. | Reject if collateral `tcbEvaluationDataNumber` < policy minimum or missing. | Quote with `tcbEvaluationDataNumber` ≥ minimum in both TCB Info and QE Identity. | Collateral with `tcbEvaluationDataNumber` < minimum. |
| **T24** | SPEC_V3.md §5, lines 215–223 | QUOTE-TDX | CPU evidence verified against Intel PCS collateral (captured, document-carried, no network fetches). PCK chain pinned to Intel SGX root CA. Revocation checked. | Reject if PCK chain does not reach pinned Intel root or revocation check fails. | Valid PCK certificate chain to Intel root with valid revocation status. | PCK chain to untrusted root; revoked certificate. |
| **T25** | SPEC_V3.md §5, line 223, VERIFICATION_ARCHITECTURE.md §3.3 | QUOTE-TDX | Intel SGX root CA MUST be pinned in the verifier (embedded). PCK chain verification and revocation checking are unconditional (no network). | Reject if PCK chain does not reach pinned Intel root. | PCK certificate with valid chain to Intel root. | PCK from untrusted root; broken chain. |

---

### IDENTITY LAYER — Platform Identity Extraction & Endorsement Lookup

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **I1** | SPEC_V3.md §5, line 226–230, POLICY_VALIDATION.md §5.3 | IDENTITY | Platform identity extracted from authenticated bytes only (after B3 quote verification). SEV: CHIP_ID (64 bytes) verbatim from report offset 0x1a0. TDX: PPID (16 bytes) from PCK leaf certificate (OID 1.2.840.113741.1.13.1.1). | Extract identity after quote authentication. | Report/quote with valid authenticated identity field. | Identity extraction before authentication; wrong identity field. |
| **I2** | POLICY_VALIDATION.md §5.3, lines 280–300, PLATFORM_ENDORSEMENTS.md §1.2 | IDENTITY | SEV CHIP_ID: 64-byte hex key in machines map. Turin: 8-byte hwID zero-padded to 64 bytes (exactly the bytes at offset 0x1a0 of every report from that machine). | Extract CHIP_ID from report, look up lowercase hex in machines map. | CHIP_ID in machines map. | CHIP_ID not in machines map; uppercase hex. |
| **I3** | POLICY_VALIDATION.md §5.3, lines 280–300, PLATFORM_ENDORSEMENTS.md §1.2, lines 118–141 | IDENTITY | TDX PPID: 16-byte hex from PCK leaf OID 1.2.840.113741.1.13.1.1, encoded to canonical lowercase hex. Stable across reboots, BIOS updates, TCB recoveries. Verifiers MUST read from verified quote's cert data (type 5) only, after chain + revocation checks. | Extract PPID from PCK leaf after quote authentication, convert to lowercase hex, look up in machines map. | PPID from verified PCK leaf in machines map. | PPID not in machines map; extracted from untrusted source. |
| **I4** | VERIFICATION_ARCHITECTURE.md §2, Step 4, lines 113–127 | IDENTITY | Quote authentication (B3) MUST precede identity lookup (Step 4): the policy lookup keys on the authenticated platform identity, and Step 3 is what makes that identity trustworthy. | Quote must be authenticated before looking up policy by identity. | Authentication → lookup sequence. | Lookup before authentication. |
| **I5** | SPEC_V3.md §5, line 230, PLATFORM_ENDORSEMENTS.md §1.2, lines 147–152 | IDENTITY | Machines map lookup failure is FATAL — in v3, platform identity endorsement is unconditional (no allowlist opt-out flag). Absent identifier MUST REJECT. | Reject if identity not found in machines map. | Identity found in machines map. | Identity absent from machines map. |
| **I6** | VERIFICATION_ARCHITECTURE.md §2, Step 4, lines 127–128 | IDENTITY | After lookup, assert the matched policy's `platform` member matches the verified quote's platform kind (e.g., `platform: sev-snp` for SEV, `platform: tdx` for TDX). | Reject if policy platform ≠ quote platform. | Policy with `platform` matching quote format. | Policy `platform: tdx` for a SEV quote. |
| **I7** | POLICY_VALIDATION.md §5.3, PLATFORM_ENDORSEMENTS.md §1.2, lines 141–145 | IDENTITY | Key lengths are disjoint (SEV 128 hex chars vs. TDX 32 chars), so no namespacing needed. Map keys cannot repeat: one policy per machine, structurally. | Flat-map lookup without platform prefix. | Disjoint key lengths; one policy per machine. | Duplicate keys; ambiguous key lengths. |

---

### POLICY LAYER — Appraisal Policy Validation & Enforcement

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **PL1** | SPEC_V3.md §5, line 254, VERIFICATION_ARCHITECTURE.md §2, Step 4 | POLICY | A policy field the verifier cannot enforce, an unknown policy member, or an unmappable platform block MUST REJECT (fail closed; no partial application). | Reject if policy contains unknown fields or verifier cannot enforce required fields. | Policy with all known, enforceable members. | Policy with unknown field; missing required member; unimplemented constraint. |
| **PL2** | PLATFORM_ENDORSEMENTS.md §2, lines 177–216 | POLICY (SEV-SNP) | Every member of the SEV-SNP policy block is REQUIRED (parsing rejects an absent member — numerics modeled as nullable, then rejected if absent). No defaults. | Reject if any required policy member is missing. | Complete policy block with all members. | Missing `minimum_tcb`, `guest_policy`, `platform_info`, or other required field. |
| **PL3** | PLATFORM_ENDORSEMENTS.md §3, lines 232–267 | POLICY (TDX) | Every member of the TDX policy block is REQUIRED. No defaults. | Reject if any required policy member is missing. | Complete TDX policy block. | Missing `qe_vendor_id`, `minimum_tee_tcb_svn`, or other required field. |
| **PL4** | PLATFORM_ENDORSEMENTS.md §1.3, lines 154–167 | POLICY | Policy schema is versioned by artifact predicate URI (no per-policy version field). SDKs MUST fail closed: a policy containing unknown fields, or a platform block the SDK cannot fully enforce, rejects the machines that reference it — never partially applied. | Reject if policy has unknown fields or unsupported constraints. | Policy with only known fields. | Policy with unknown field like `future_constraint: {...}`. |
| **PL5** | PLATFORM_ENDORSEMENTS.md §2, line 209, §3, lines 250, 265 | POLICY | `require_author_key` and `require_id_block` (SEV) are recognized but MUST be false: no trusted ID-block key material is modeled, so a policy requiring them rejects at parse rather than half-enforcing. | Reject if `require_author_key: true` or `require_id_block: true`. | Policy with both set to `false`. | Policy with either set to `true`. |
| **PL6** | PLATFORM_ENDORSEMENTS.md §2, line 200–209 | POLICY (SEV-SNP) | Members and their comparisons: `minimum_build`/`minimum_api_version` (floor), `minimum_abi_version` (floor), `minimum_guest_svn` (floor), `minimum_tcb`/`minimum_launch_tcb` (floor, SPL components), `guest_policy.*` (exact all bits), `platform_info.*` (exact all bits), `permit_provisional_firmware` (boolean, enforces CURRENT==COMMITTED if false), `vmpl` (exact, 0–3), `host_data` (exact hex), `image_id`/`family_id` (exact hex), `minimum_*_mitigation_vector` (floor). | Apply each comparison rule per field (floor vs. exact). | Policy with correct comparison semantics. | Policy with inverted semantics (e.g., exact on floor field). |
| **PL7** | PLATFORM_ENDORSEMENTS.md §3, lines 244–267 | POLICY (TDX) | Members and their comparisons: `qe_vendor_id` (exact), `minimum_tee_tcb_svn` (floor per-component), `mr_seam` (exact, single value), `td_attributes`/`xfam` (exact all bits), `minimum_tcb_evaluation_data_number` (floor), `platform_measurements` (membership by shape-filtered resolution). | Apply each comparison rule per field. | Policy with correct comparison semantics. | Policy with inverted semantics. |
| **PL8** | PLATFORM_ENDORSEMENTS.md §3, lines 250, VERIFICATION_ARCHITECTURE.md §3.4 | POLICY (TDX) | `mr_seam`: single value per policy (exact match). Machine running multiple TDX module versions gets multiple policies, never one policy with multiple accepted MRSEAMs. | Reject if quote `mr_seam` does not match policy's single value (not an array). | Policy with single `mr_seam` value. | Policy with multiple `mr_seam` values (array). |
| **PL9** | PLATFORM_ENDORSEMENTS.md §1.1, lines 83–107, §3, line 254 | POLICY (TDX) | `platform_measurements`: non-empty array of measurement entry names. Quote's authenticated MRTD/RTMR0, filtered by code artifact's declared `vm_shape`, must resolve exactly one entry. Empty measurement list rejects. | Reject if no entries match (MRTD/RTMR0 not found in filtered candidates). | Policy with `platform_measurements` entries matching quote's shape. | Empty `platform_measurements` array; MRTD/RTMR0 not found. |
| **PL10** | PLATFORM_ENDORSEMENTS.md §1.2, lines 113–116 | POLICY | No hostnames, providers, or any other metadata in the `machines` map — identifiers and policy names only. Hostname-to-identifier mapping stays private. | Machines map contains only identifiers (keys) and policy names (values). | Map with `"<identifier>": "<policy-name>"` only. | Map with metadata like `"<identifier>": {"policy": "...", "hostname": "..."}`. |
| **PL11** | PLATFORM_ENDORSEMENTS.md §4, lines 284–296 | POLICY | CI validation rules (before signing): 1. Every machines value names an existing policy; 2. Identifier format matches mapped policy's platform (128 lowercase hex ↔ sev-snp, 32 ↔ tdx); 3. No duplicate identifiers (JSON duplicate keys); 4. Machines values and policy names only; 5. Every `platform_measurements` ref resolves; 6. All hex lowercase; Turin zero-padded. | Reject if any CI rule violated. | Artifact passing all CI checks. | Dangling policy reference; wrong identifier format; duplicate keys. |
| **PL12** | PLATFORM_ENDORSEMENTS.md §2, lines 178–187, §3, lines 233–241 | POLICY | All policy numeric fields are modeled as nullable and rejected at parse if absent. Examples: `minimum_build` (integer), `minimum_tcb` (object with SPL components), `minimum_tee_tcb_svn` (hex string). Absence = parse rejection. | Reject if any required numeric field is missing (null). | Policy with all required numerics present. | Policy with missing `minimum_build` or `minimum_tcb`. |

---

### STRUCTURAL LAYER — VM Shape Filtering & Measurement Resolution

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **ST1** | VERIFICATION_ARCHITECTURE.md §2, Step 4, line 237, SPEC_V3.md §5, line 236–238, CONFORMANCE.md §3, D8 | STRUCTURAL | Code measurement's declared `vm_shape` (REQUIRED in code provenance) filters platform-measurement candidates. Verifiers filter entries to those whose shape satisfies the code artifact's shape requirement. No shape match REJECTS. | Reject if no measurements match code artifact's `vm_shape`. | Code artifact with `vm_shape`; measurements with matching `shape`. | Code artifact with `vm_shape: {cpus: 16, memory: 65536}`; no measurements with matching shape. |
| **ST2** | CONFORMANCE.md §3, D2, D8 | STRUCTURAL | Several entries can survive the shape filter for one identity and one platform (TDVF/QEMU versions, firmware, etc.). Among the survivors, select the single entry whose MRTD AND RTMR0 equal the quote's authenticated registers. No match REJECTS. | Filter by shape, then by (MRTD, RTMR0) pair; reject if no exact pair match. | Multiple measurements for one machine, filter to shape, resolve MRTD/RTMR0 exactly. | Shape-filtered candidates, but MRTD/RTMR0 pair not found. |
| **ST3** | PLATFORM_ENDORSEMENTS.md §1.1, lines 88–98 | STRUCTURAL | Each measurement entry carries `shape` metadata: canonical VM shape descriptor with `cpus`, `memory_mb`, optionally `gpus` (count/classes), `disks`. Shape serves as the candidate filter key; measurement lookup is selection by authenticated MRTD/RTMR0 within shape-filtered candidates. | Shape descriptor used only for filtering; final lookup by authenticated fields. | Measurements with `shape` metadata; resolution by authenticated values. | Lookup by shape alone (wrong); ambiguous resolution. |
| **ST4** | CONFORMANCE.md §3, D8, §4, lines 576–584 | STRUCTURAL | `vm_shape` is REQUIRED in code provenance; verifier shape filter is unconditional (no unfiltered fallback). Transitional fallback (deprecated): documents with code artifacts predating the `vm_shape` field fall back to unfiltered lookup; decide cutoff during rollout. | If code artifact lacks `vm_shape`, either reject or use deprecated fallback (flag as such). | Code artifact with required `vm_shape` field. | Code artifact missing `vm_shape` (once deprecated fallback removed). |

---

### FRESHNESS LAYER (Deferred/Not-Enforced — Known Gaps)

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **FR1** | SPEC_V3.md §10, lines 342–349, PLATFORM_FRESHNESS_PILOT.md, FORMAT_DECISIONS.md D13 | FRESHNESS | Document freshness: nonce binding (verifier uses its own nonce, never the document's). Reference-values freshness: validity metadata inside signed artifacts (Sigstore timestamp, transparency-log entry observer timestamp). No trusted timestamp in the document; no expiry enforced today. Deferred proposal (freshness witness pilot) not yet enforced. | Nonce freshness enforced; collateral freshness not enforced. | Document with fresh nonce binding. | Document with stale/replayed nonce; document with expired collateral (no enforcement today). |
| **FR2** | PLATFORM_FRESHNESS_PILOT.md, MASTER_PLAN.md "Later waves" | FRESHNESS | Freshness witness (deferred, not scheduled): a separate, periodically re-signed artifact endorsing "this release is still current as of `<time>`." Not part of v3 spec; opt-in at call site; no enforcement required yet. | If implemented: check witness `issued_at` against `MaxFreshnessAge` constant (e.g., 7 days). | Witness with recent `issued_at` (within 7 days). | Witness with stale `issued_at` (outside window) — deferred check. |
| **FR3** | SPEC_V3.md §10, CONFORMANCE.md §3, D8 | FRESHNESS | Rollback/stack-version acceptance: during stack upgrades, multiple MRTD/RTMR0 tuples are legitimately endorsed for the same machine. Verifier names the matched slug (shape + stack) as a verified fact; no higher-level anti-rollback bound enforced. Freshness witness (future) could add time-bounded trust window per stack. | Allows multiple endorsed stacks (no high-water-mark check today). | Multiple stack versions with different (MRTD, RTMR0) endorsed. | Single stack with forced upgrade (enforcement deferred). |

---

### UNCHECKED LAYER — Fields Explicitly Not Verified

| RULE_ID | Doc: Section/Line | Verification Layer | Normative Rule | Testable As | Accept Fixture Idea | Reject Fixture Idea |
|---------|-------------------|-------------------|---|---|---|---|
| **U1** | POLICY_VALIDATION.md §4, lines 245–256 | UNCHECKED | SEV REPORT_ID: random per-guest identifier; no verifier-side expected value. Intentionally unchecked. | No enforcement; any value accepted. | Any REPORT_ID value. | N/A (no rejection). |
| **U2** | POLICY_VALIDATION.md §4, lines 250–251 | UNCHECKED | SEV REPORT_ID_MA: migration-agent report ID; policy already forbids MA via `migrate_ma: false`, so no MA can be associated. Indirectly unchecked (policy enforcement covers). | No direct check; policy enforcement prevents MA. | REPORT_ID_MA with `migrate_ma: false` policy. | N/A (policy enforcement). |
| **U3** | POLICY_VALIDATION.md §4, lines 252–256 | UNCHECKED | TDX User Data (header bytes 28–47): QE-written platform identifier (QE_ID). Generated from platform sealing keys; no off-platform expected value exists. Intentionally unchecked. | No enforcement; any value accepted. | Any User Data value. | N/A (no rejection). |
| **U4** | SPEC_V3.md §7, VERIFICATION_ARCHITECTURE.md §3.6 | UNCHECKED | Generic crypto material: reserved for future; not checked today. Verifier special-cases `tls` and `hpke` ids only. | Reject unknown `crypto_material` id/format unless deferred. | Known `id` values (`tls`, `hpke`). | Unknown `crypto_material` id. |
| **U5** | SPEC_V3.md §7, lines 281–283 | UNCHECKED | v3 verifiers MUST NOT use: dcode SAN encodings (`.hpke.`, `.hatt.`), certificate-embedded attestation hashes, `/.well-known/tinfoil-certificate`, DNS-name-based checks. Legacy bindings explicitly removed. | No enforcement of legacy bindings. | v3 binding via SPKI fingerprint / HPKE key only. | Attempt to use legacy dcode SAN or cert-embedded hash. |
| **U6** | SPEC_V3.md §5, line 214, MASTER_PLAN.md "Key risks" | UNCHECKED | Turin platform root: not yet pinned (deferred). Genoa only. | Genoa reports verify; Turin reports would fail (no root). | Genoa report with correct root. | Turin report (fails, deferred). |

---

### AMBIGUOUS & UNDERSPECIFIED RULES

| RULE_ID | Doc: Section/Line | Issue | Fixture Test Difficulty | Potential Outcomes |
|---------|-------------------|-------|--------------------------|---|
| **AM1** | CONFORMANCE.md §3, D8, lines 395–429 | GPU shape binding: `gpus` field in shape descriptor (count/classes). Unclear whether different GPU models at identical slot addresses produce identical RTMR0 ("topology stand-in experiment" deferred to validate). Descriptor may constrain by model identity or slot topology. | Medium | Accept both single-GPU-model and multi-GPU-model shapes with identical RTMR0 until experiment completes; then tighten per results. |
| **AM2** | PLATFORM_FRESHNESS_PILOT.md, open question 2, 5 | `MaxFreshnessAge` constant value not finalized (7 days discussed, but "schedule cadence matching" needs confirmation). Exact SAN shape of `tinfoilsh/freshness-witness` dispatch-triggered Fulcio cert (ref claim on `workflow_dispatch`, expected `@refs/heads/main`) not confirmed empirically. | Medium | Default to 7 days; confirm against real workflow run before locking SDK version. |
| **AM3** | CONFORMANCE.md §3, D1 | No explicit `AssembledPolicy` value type exists in current implementation; policy checks distributed across `verifySevReportWithEndorsements`, `verifyTdxEvidenceV3`, and orchestrator `Measurement.Equals`. Refactor to consolidate deferred (PR-B). | Low | Accept current distributed checks or require consolidated refactor before production. |
| **AM4** | POLICY_VALIDATION.md §2, Table 23, CONFORMANCE.md §3, D3 | SEV mitigation vectors (`LAUNCH_MIT_VECTOR`, `CURRENT_MIT_VECTOR`): only v5 reports carry them; policy floor is bitmask superset (every required bit set). Unclear what "required" means if Tinfoil always runs with default (no special mitigations): placeholder zeros in v1 artifact. | Low | Implement as bitmask superset once policies are populated with real mitigations; today floor=0 is implicit. |
| **AM5** | MASTER_PLAN.md, Key risks, Turin TCB layout | Turin PLATFORM_INFO bit 6 is MBZ per AMD spec but set by box2 firmware (build:0). Whether this is engineering-firmware-only or genuine Turin behavior unresolved. Bit-6 parsing differs from Genoa. | High | Require firmware update/investigation before Turin production rollout; may need special bit-6 handling or mask-unknown-bits option. |

---

### KNOWN GO-DIVERGENCES (Spec vs. Implementation Gaps)

| Item | Doc Reference | Spec Says | Implementation (tinfoil-go) | Status | Impact |
|------|----------------|-----------|---|---|---|
| **B3-B4 Fusion** | VERIFICATION_ARCHITECTURE.md §2 Steps 3–4, CONFORMANCE.md §1.3 | Quote authentication (B3) and policy assembly (B4) are separate blocks with explicit boundaries. | Quote auth and assembly fused in `verifySevReportWithEndorsements` and `verifyTdxEvidenceV3`; no dedicated `AssembledPolicy` struct. | Known gap (PR-B deferred) | Auditing "what is checked?" requires reading across functions. No functional impact (same checks), but refactor needed for clarity. |
| **Multi-Valued MRTD/RTMR0** | VERIFICATION_ARCHITECTURE.md §3.4, CONFORMANCE.md §3, D2 | One expected value per field; membership acceptance is weak. Platform measurement lookup is keyed selection at assembly by authenticated (MRTD, RTMR0), not multi-value acceptance at validation. | Current code uses `platform_measurements: []string` membership (accepts multiple tuples). Companion checks delete once shape-filtered resolution lands. | Known gap (PR-D deferred) | Verdict lacks precision ("which stack was this?"); security is equivalent but refactor improves auditability. |
| **SEV Revocation Unchecked** | VERIFICATION_ARCHITECTURE.md §3.3, POLICY_VALIDATION.md §2, CONFORMANCE.md §3, D7 | VCEK revocation MUST be checked (amd-crl/v1 collateral entry required). | `go-sev-guest` uses `verify.DefaultOptions()` where `CheckRevocations=false`. Enabled for TDX, not SEV. | Known gap (PR-E deferred) | Revocation status not verified for SEV; CRL collateral must be added and SDK updated. |
| **Loose Code-Repo Identity** | VERIFICATION_ARCHITECTURE.md §3.2, check 9, CONFORMANCE.md §3, D5 | Code-repo SAN pattern anchored, escaped, one workflow file only. | Old pattern was `^https://github.com/<repo>/.github/workflows/.*@refs/tags/*` (unanchored tail, unescaped dots, any workflow file). | Fixed (PR-A merged); spec now matches implementation. | No open gap; tightened in v3. |
| **Strict Parsing of Policy Artifact** | VERIFICATION_ARCHITECTURE.md §2, Step 2, CONFORMANCE.md §3, D6 | Platform-endorsements artifact parsed with fail-closed semantics (strict member matching, duplicate rejection). | `policy.ParseArtifact` uses v1 `DisallowUnknownFields` (case-insensitive, accepts duplicates). | Known gap (PR-F deferred) | Risk: parser divergence if artifact is re-marshaled or edited; not attacker-reachable (Sigstore-authenticated) but contradicts "consistent strict parsing." |
| **TCB Floors & Bytes** | POLICY_VALIDATION.md §2, Table 23, CONFORMANCE.md §1.1 | `minimum_tcb` is policy (floor); REPORTED_TCB must equal VCEK cert TCB. | Both checked; library options express the floor. | Conforms | No gap. |
| **Freshness/Rollback** | SPEC_V3.md §10, PLATFORM_FRESHNESS_PILOT.md | Freshness deferred; no enforcement today. Stack rollback possible (multiple endorsed versions during upgrade). | No enforcement; SDK names matched slug as verified fact (shape + stack). | Known limitation, by design | No enforcement required pre-GA; freshness witness (future) adds time-bounded trust window. |
| **Device Verification** | VERIFICATION_ARCHITECTURE.md §2, Step 6, CONFORMANCE.md §1.5 | If policy requires device verification, follow device vendor's algorithm. Device items parsed, never verified; no policy field can require devices yet. | Device items parsed but not verified. | Not implemented (B5 deferred) | Policy requiring device verification fails closed (no field exists yet). |
| **Turin Root** | VERIFICATION_ARCHITECTURE.md §3.3, MASTER_PLAN.md Key risks | Turin AMD root must be pinned. | Only Genoa root pinned; Turin reports would fail. | Not implemented (deferred) | Turin machines cannot verify until root is pinned. |

---

## Summary Tables

### By Verification Layer — Rule Count

| Layer | # Rules | Status |
|-------|---------|--------|
| **ENVELOPE** | 17 | Normative, enforced |
| **PROVENANCE** | 16 | Normative, enforced |
| **QUOTE-SEV** | 26 | Normative, enforced (except revocation check) |
| **QUOTE-TDX** | 25 | Normative, enforced |
| **IDENTITY** | 7 | Normative, enforced |
| **POLICY** | 12 | Normative, enforced |
| **STRUCTURAL** | 4 | Normative, partially enforced (shape filtering deferred) |
| **FRESHNESS** | 3 | Deferred / not enforced |
| **UNCHECKED** | 6 | Intentionally unchecked or deferred |
| **AMBIGUOUS** | 5 | Underspecified; fixture design uncertain |
| **Total Normative** | **112** | |
| **Known Gaps** | **8** | Documented in CONFORMANCE.md |

---

## Next Steps for Fixture Authoring

1. **Reject-on-rule fixtures** for all 112+ rules covering:
   - All 7 strict-JSON parsing rules (E1–E7)
   - All endorsement/collateral shape rules (E8–E13)
   - All Sigstore bundle checks (P1–P16)
   - Each quote field comparison (S1–S26 for SEV, T1–T25 for TDX)
   - Identity extraction and lookup (I1–I7)
   - Policy validation (PL1–PL12)
   - Shape filtering (ST1–ST4)

2. **Accept-on-rule fixtures** demonstrating:
   - Valid documents with correct member names, formats, hashes
   - Valid SEV and TDX quotes matching assembled policies
   - Valid Sigstore bundles with correct identities and chains
   - Correct platform-identity lookup and endorsement

3. **Golden fixtures** (real hardware):
   - SEV-SNP (Genoa) document with live VCEK chain and CRL
   - TDX quote with live PCK chain and Intel PCS captures
   - Corresponding `platform-endorsements` release

4. **Ambiguous/underspecified fixtures** (decision-pending):
   - GPU shape variants pending topology stand-in experiment (AM1)
   - Turin/bit-6 handling pending firmware investigation (AM5)
   - Freshness witness timing pending workflow SAN confirmation (AM2)

---

**This checklist is complete and ready for conformance fixture implementation.** Each rule is testable independently or in composition; the layers scaffold a bottom-up verification approach (envelope → provenance → quote → identity → policy → binding).