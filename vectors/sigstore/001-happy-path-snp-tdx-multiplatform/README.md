# 001 — happy-path-snp-tdx-multiplatform

A real production Sigstore bundle for `tinfoilsh/confidential-model-router`. Verifies the four core Tinfoil Sigstore policy checks (SPEC §5.2 – §5.5) at once:

1. Bundle signature + Fulcio chain + Rekor inclusion + SCTs (§5.2).
2. Cert identity: GitHub Actions OIDC issuer + repo + `refs/tags/` prefix (§5.3).
3. DSSE `payload_type` and subject digest match the expected release digest (§5.4).
4. Predicate type allow-listed and three registers extracted as the canonical `SnpTdxMultiPlatformV1` measurement (§5.5).

If this fixture fails, the SDK is broken at the Sigstore stage entirely. Every other fixture in `vectors/sigstore/` assumes this one passes.
