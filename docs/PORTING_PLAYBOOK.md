# Porting Playbook — bringing a new SDK to v3 conformance

The repeatable recipe that produced the tinfoil-js port: byte-identical to Go
on every fixture, zero cross-module fixes at integration. Target audience: a
person or agent team starting `tinfoil-python`, `tinfoil-rs`, etc.

## What you are building

1. A **v3 verifier** in your language, function-by-function from the reference.
2. A **conformance adapter** speaking [CONFORMANCE_ADAPTER_SPEC.md](CONFORMANCE_ADAPTER_SPEC.md)
   (stages, exit codes, wire shapes) and exposing the public API pinned by
   [SDK_SURFACE_SPEC.md](SDK_SURFACE_SPEC.md) (Tier 1 now, Tier 2 before release).

References, in order of authority: the two specs → `tinfoil-go` `feat/v3`
(primary source — port its check order and error conditions exactly) →
`tinfoil-js` `feat/v3-verifier` (second opinion; shows the shape of a port,
including full TDX DCAP without a platform library). Where Go delegates to
go-sev-guest / go-tdx-guest / sigstore-go, implement exactly the subset its
configured options exercise — read those libraries, not just the wrappers.

## Definition of done

```
tools/run_adapter.py --adapter "<your cli>"                  # all fixtures pass
tools/run_adapter.py --adapter "<go cli>" --report go.json
tools/run_adapter.py --adapter "<your cli>" --report x.json
tools/compare_adapters.py go.json x.json                     # 0 divergent — byte-identical
tools/run_adapter.py --live <host>,<repo> --adapter "<go>" --adapter "<yours>"   # facts identical
```

Byte-identical means: same exit codes, verdicts, rejection layers, and every
accept fact (`code_digest`, measurements with register order, channel keys).

## The recipe

**Phase 0 — fix the interfaces first.** Write a PORTING.md for your repo: the
module map below, each module's exact public signatures (mirroring Go names,
idiomatically cased), the error type (one exception/error carrying the layer:
`ENVELOPE/PROVENANCE/QUOTE/POLICY_REJECTED`), and file ownership per worker.
Parallel workers must code against frozen interfaces, never each other's WIP.

**Phase 1 — foundation (one worker, first).** Strict JSON + envelope +
measurement + policy artifact + adapter CLI skeleton (envelope stage working,
others exit 20). Gate: `--dirs envelope` all pass.

**Phase 2 — three crypto slices in parallel.** Each is self-contained, tests
via its own fixture directory, and must not touch the others' files:

| slice | Go source | gate (`--dirs`) | notes |
|---|---|---|---|
| provenance + freshness | `verifier/provenance/` | `provenance,policy` | use your language's Sigstore library if it verifies v0.3 DSSE bundles against a supplied trusted root with SCT + tlog-inclusion + observer-timestamp semantics; implement every tinfoil check it lacks (identity regex, issuer/runner_env/source-ref extensions, subject digest, one-signature, legacy-format rejection, freshness witness) |
| SEV-SNP | `verifier/quote/sev/` + go-sev-guest | `quote-sev` | chain (RSA-PSS-SHA384), CRL fail-closed, report ABI, expectations |
| TDX | `verifier/quote/tdx/` + go-tdx-guest | `quote-tdx` | the long pole: full DCAP quote-v4 verification, no library exists outside Go. `fixturegen/lib/tdx_synth.py` is a complete spec of the material; tinfoil-js `v3/tdx/` is a worked port |

**Phase 3 — integration (one worker).** `quote` dispatch + `verifyDocumentV3`
(one appraisal time pins freshness *and* the quote clock) + remaining adapter
stages with layer attribution and the five accept facts. Gate: full suite,
then the comparator, then the browser/live lanes as applicable.

**Phase 4 — surface + product.** Export Tier 1 from the package's public entry
in its native style; re-point the adapter's full-verify and live paths at it
(spec rule — no deep imports there). Add a surface-presence test. Then Tier 2:
wire the product client (fetch → verify → ground truth → channel binding:
`tls-spki` if your platform can inspect the transport, `hpke` via EHBP if not).

## Pitfalls we paid for (check each explicitly)

- **Strict JSON is not your stdlib.** Go semantics: unknown members reject,
  duplicate members reject *everywhere* (compared on **decoded** names, after
  replacing unpaired surrogates with U+FFFD), integers parsed from the raw
  literal (fraction/exponent/range reject), no trailing data. Python `json`
  and serde each diverge from this out of the box.
- **Integer width.** Policy u64 fields must survive > 2^53 (use your big/exact
  int type). Known open issue: Go's structpb round-trip is itself lossy here.
- **Canonical encodings.** Base64: exactly one accepted encoding (round-trip
  check). Hex: lowercase only, exact lengths. These are asserted by fixtures.
- **Signature forms.** SEV report signature is r‖s **little-endian**, 72-byte
  padded, over bytes `[0, 0x2A0)`. WebCrypto-style APIs want raw r‖s; DER
  X.509 signatures need strict canonical-DER conversion (reject non-minimal
  integers — permissive converters weaken conformance).
- **RSA-PSS details.** SHA-384, salt length 48; some APIs only import
  `rsaEncryption`-labeled SPKIs (relabel `id-RSASSA-PSS` if needed).
- **DER strictness.** Match Go's `encoding/asn1`: UTCTime/GeneralizedTime
  require the trailing `Z`; extension critical flag must be BOOLEAN; reject
  indefinite lengths and non-minimal forms.
- **Clock pinning.** `verification_time_unix` pins collateral validity windows
  (CRL this/next-update, cert validity) *and* the freshness appraisal — one
  value, two uses. Sigstore verification uses bundle-internal timestamps only.
- **Collateral resolution.** First matching reference-values entry wins;
  freshness entries are looked up by id (`code-freshness`/`platform-freshness`)
  and duplicates reject.
- **Channel keys.** Full verify requires both endorsed keys (`tls` spki-fp +
  `hpke` x25519); absence rejects `ENVELOPE_REJECTED`.
- **Don't trust "identical" copies.** Diff everything you duplicate or port
  twice — two of our worst latent bugs were found by diffing supposedly
  identical code (a laxer extension parser, a split-trust CRL root).

## Effort map (from the JS port)

Foundation ≈ 2k lines; provenance ≈ 1k (with a Sigstore library); SEV ≈ 2k;
TDX ≈ 2.5k (largest, least library support); integration + adapter ≈ 0.7k;
surface/Tier-2 ≈ 0.5k plus product-client wiring. The harness, fixtures,
comparator, and live lane cost you nothing — they are this repository.
