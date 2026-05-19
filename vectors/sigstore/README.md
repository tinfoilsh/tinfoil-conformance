# Sigstore stage fixtures

Each fixture targets the Tinfoil Sigstore policy layer described in `sdk-flywheel/SPEC.md` §5. Per-fixture metadata lives in `manifest.yaml`; piped stdin lives in `input.json`; the canonical expected output lives in `expected.json`.

## Catalog (planned)

The full v0.1 catalog has ~26 fixtures grouped by category. This repo seeds with the happy path and grows from there.

| # | ID | Category | Spec § | Targets divergence in |
|---|---|---|---|---|
| 001 | happy-path-snp-tdx-multiplatform | Happy path | 5.2–5.5 | (baseline) |
| 002 | happy-path-hardware-measurements | Happy path | 5.5 | SDKs that hardcoded only one predicate type |
| 010 | workflow-ref-refs-heads-rejected | Workflow ref | 5.3 | Loose substring/regex implementations |
| 011 | workflow-ref-heads-trojan | Workflow ref | 5.3 | Go `.*@refs/tags/*` style regex |
| 012 | workflow-ref-tags-v0 | Workflow ref | 5.3 | Realistic tag formats |
| 013 | workflow-repo-mismatch | Workflow repo | 5.3 | — |
| 020 | oidc-issuer-mismatch | OIDC issuer | 5.3 | — |
| 021 | oidc-issuer-empty-subject-trojan | OIDC issuer | 5.3 | Go's empty-string secondary-check skip |
| 030 | predicate-type-not-allowed | Predicate | 5.5 | Go's deferred predicate pinning |
| 031 | predicate-type-snp-tdx-extraction | Predicate | 5.5 | JS partial extraction (drops rtmr1/rtmr2) |
| 032 | predicate-fields-missing-tdx | Predicate | 5.5 | — |
| 040 | subject-digest-uppercase | Digest | 5.4/7.3 | Strict-`!=` implementations |
| 041 | subject-digest-mismatch | Digest | 5.4 | — |
| 042 | subject-empty | Subject | 5.4 | — |
| 050 | payload-type-parameterised | Payload type | 5.4 | SDKs without exact-match |
| 051 | payload-type-checked-after-signature | Payload type | 5.4 | Ordering bugs |
| 060 | tlog-zero-entries | Rekor | 5.2 #3 | — |
| 061 | tlog-two-entries | Rekor | 5.2 #3 | Rust's `exactly 1` over-strictness |
| 062 | sct-duplicate-log | SCT | 5.2 #4 | — |
| 063 | checkpoint-root-mismatch | Rekor | 5.2 #3 | — |
| 070 | dsse-signature-bitflip | DSSE | 5.2 #1 | — |
| 071 | fulcio-chain-broken | Fulcio | 5.2 #2 | — |
| 072 | cert-expired-at-verification-time | Fulcio | 5.2 / 8 | — |

Status: `001` is real-frozen and pinned. The rest will be added incrementally, most as **synthetic** fixtures produced by `fixturegen/` (planned).

## Conventions

* `bundle_b64`/`trust_root_b64` in `input.json` are inline base64. The same payloads are also in `files/{bundle,trust_root}.json` for human inspection. SDKs MUST consume the base64 form via stdin; the `files/` copies exist only for diffing/debugging.
* `verification_time_unix` is **mandatory**. No fixture relies on system clock.
* `expected.json` lists only the output fields the harness diffs. SDKs MAY emit additional fields; the harness ignores them.
* Hex comparisons in `expected.json` are case-insensitive (SPEC §7.3 lowercase normalization rule).
