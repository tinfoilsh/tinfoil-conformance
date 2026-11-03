# Layer vectors — key-signed approval bundles and RFC 3161 timestamps

Two verification layers sit underneath the v3 adapter stages and are not
reachable through them: the verifier for **key-signed approval bundles**
(a Sigstore DSSE bundle signed by a pinned key rather than a Fulcio
certificate) and the verifier for **RFC 3161 timestamps** (the independent
time an approval carries). `vectors/v3-layers/` holds one directory of test
vectors per layer so every SDK can test them with the same inputs and the
same expected verdicts.

These vectors are **consumed by SDK unit tests**, not driven by the
conformance adapter: an SDK loads each JSON file, calls its own layer
verifier with the `input` fields, and asserts the `expected` verdict (and
the accept fact). They live outside `vectors/v3/` on purpose, so the adapter
fixture schema and the coverage-matrix gate do not apply to them;
`python3 tools/validate_suite.py` validates them against
[`schemas/v3-layers/`](../schemas/v3-layers/).

The reference verdicts are tinfoil-go's: every vector was run through the
Go key-signed verifier and timestamp verifier, and `expected` records what
the reference does. Where that is stricter than the wire standards allow,
the vector says so in its `description` (see the notes under each layer).

```
vectors/v3-layers/
  approval-bundle/   key-signed approval bundles   (schemas/v3-layers/approval-bundle.schema.json)
  rfc3161/           RFC 3161 timestamp responses  (schemas/v3-layers/rfc3161.schema.json)
fixturegen/v3-layers/
  gen_approval_bundle.py, gen_rfc3161.py   deterministic generators (fixed keys, RFC 6979 nonces)
```

Both vector kinds share one shape:

```json
{ "id": "<file basename>", "description": "<one sentence>",
  "input": { "schema_version": "1", ... }, "expected": { "accepted": true|false, ... } }
```

`expected.reason` (rejects only) is an informative tag naming the rule the
vector breaks; it is not a closed taxonomy and SDKs need not echo it.

Regenerate from the repo root (needs the `cryptography` package, e.g.
`uv run --with cryptography fixturegen/v3-layers/gen_approval_bundle.py`);
re-running changes nothing.

## 1. Key-signed approval bundles — `approval-bundle/`

### Input

| field | meaning |
|---|---|
| `trusted_root_json_b64` | Sigstore trusted root (`trustedroot+json` v0.1) listing the transparency logs that may witness the bundle's entries: an ECDSA P-256 log and an Ed25519 log (both key types appear in production) |
| `signing_keys_pem` | the pinned approval signing keys, each a PEM ECDSA P-256 SubjectPublicKeyInfo (two keys, so key selection by hint is exercised) |
| `bundle_json_b64` | the Sigstore v0.3 bundle (protojson) under test |
| `artifact_digest_hex` | SHA-256 of the approved artifact |

### What a verifier must enforce

Verifying a key-signed approval bundle means all of the following; an
accept reports the hint of the pinned key that verified
(`expected.signing_key_hint`).

1. **Layout.** Media type `application/vnd.dev.sigstore.bundle.v0.3+json`;
   `verificationMaterial.publicKey.hint` set (no certificate, no legacy
   certificate chain); a DSSE envelope of payload type
   `application/vnd.in-toto+json` with **exactly one** signature.
2. **Key selection.** The hint is the standard base64 of SHA-256 over the DER
   SubjectPublicKeyInfo of a pinned key, and must name one of
   `signing_keys_pem`. The DSSE `keyid` must be `""`/absent (see the note
   below on `keyid-equals-hint`).
3. **Signature.** The DSSE signature verifies under the hinted key over the
   pre-authentication encoding `PAE(payloadType, payload)`.
4. **Log entries.** Between 1 and 8 `tlogEntries`, each `hashedrekord` /
   `0.0.2` (Rekor v2), each with an `inclusionProof` carrying a signed
   checkpoint, and **none** with an `integratedTime` or an `inclusionPromise`.
   No `timestampVerificationData.rfc3161Timestamps` in the bundle: nothing in
   a key-signed bundle states a time; the approval's own signed timestamp
   does (layer 2 below).
5. **Entry bodies.** Each `canonicalizedBody` is the RFC 8785 canonical
   hashedrekord 0.0.2 record the log would have built from this bundle:
   `spec.hashedRekordV002.data` = `{algorithm: SHA2_256, digest: SHA-256 of
   the signed PAE bytes}`, `signature.content` = the DSSE signature, and
   `signature.verifier` = `{keyDetails: PKIX_ECDSA_P256_SHA_256, publicKey:
   {rawBytes: the pinned key's SPKI DER}}`. (The reference rebuilds this
   record from the bundle and the pinned key and checks the inclusion proof
   against it, so a body that disagrees fails inclusion.)
6. **Inclusion.** The RFC 6962 inclusion proof from `sha256(0x00 || body)`
   at the entry's log index reaches the checkpoint's root at its tree size.
7. **Checkpoint.** The checkpoint is a signed note whose origin line is the
   hostname of the log's `baseUrl` in the trusted root, signed under that
   name by the log identified by the entry's `logId`. The 4-byte key hint
   on the signature line is `sha256(SPKI DER)[:4]` for an ECDSA log and
   `sha256(origin || "\n" || 0x01 || raw key)[:4]` for an Ed25519 log; the
   signature is DER ECDSA over SHA-256 of the note text, or a raw Ed25519
   signature over it. A duplicate (log id, log index) pair rejects.
8. **Subject binding.** The signed in-toto statement has a subject whose
   `digest.sha256` equals `artifact_digest_hex` (any subject, not only the
   first).

### Vectors

| id | expected | rule |
|---|---|---|
| `happy` | accept | one entry at index 2 of a 5-leaf tree under the ECDSA log |
| `happy-ed25519-log` | accept | the checkpoint is signed by the Ed25519 log |
| `happy-second-key` | accept | signed by the second pinned key; the hint selects it |
| `eight-entries` | accept | the maximum of eight entries, each with its own proof |
| `digest-in-second-subject` | accept | the artifact digest is on the second subject |
| `keyid-equals-hint` | reject | DSSE `keyid` set, equal to the hint — see note |
| `wrong-hint` | reject | the hint names an unpinned key |
| `keyid-mismatch` | reject | DSSE `keyid` set and different from the hint |
| `zero-entries` / `nine-entries` | reject | entry count outside 1–8 |
| `entry-wrong-kind` / `entry-wrong-version` | reject | not `hashedrekord` / not `0.0.2` |
| `integrated-time-present` | reject | an entry carries `integratedTime` |
| `inclusion-promise-present` | reject | an entry carries an `inclusionPromise` |
| `rfc3161-timestamps-present` | reject | the bundle carries an RFC 3161 timestamp |
| `body-digest-mismatch` | reject | body digest is over the bare payload, not the PAE (proof consistent with the body) |
| `body-key-mismatch` | reject | body verifier key is another pinned key (proof consistent with the body) |
| `bad-inclusion-proof` | reject | a sibling hash is corrupted |
| `checkpoint-unknown-log` | reject | log id and checkpoint signer not in the trusted root |
| `checkpoint-bad-signature` | reject | entry names the trusted log but the checkpoint is signed by another key |
| `bad-dsse-signature` | reject | signature by another key; hint, body and proof name the pinned key |
| `subject-digest-mismatch` | reject | no subject names the artifact digest |
| `certificate-instead-of-key` | reject | verification material is a certificate, not a hint |

**Note on `keyid-equals-hint`.** The reference accepts no non-empty DSSE
`keyid` at all: its layout check allows `keyid == hint`, but its DSSE
library then honours a `keyid` only when it equals the SSH SHA-256
fingerprint of the key, which a hint never is. The vector records the
reference verdict (reject). An SDK that would accept `keyid == hint` is
more permissive than the reference and fails this vector.

## 2. RFC 3161 timestamps — `rfc3161/`

### Input

| field | meaning |
|---|---|
| `trusted_root_json_b64` | Sigstore trusted root whose `timestampAuthorities` may authenticate the response (a P-256 authority and a P-384 authority) |
| `response_b64` | the DER `TimeStampResp` under test |
| `input_b64` | the bytes the timestamp covers |

### What a verifier must enforce

An accept reports the TSTInfo `genTime` (`expected.time`, RFC 3339 UTC).
The vectors pin no freshness policy: an SDK that also applies a max-age /
future-skew policy must anchor its clock to `expected.time` when running
them.

1. **Status.** The `PKIStatus` is `granted` (0). The reference treats every
   other status as a failure, including `grantedWithMods` (1) — see the note
   below.
2. **Token.** The token is a CMS `SignedData` with `eContentType`
   `id-ct-TSTInfo` and exactly one `SignerInfo`, identified by issuer and
   serial number, whose signed attributes carry `content-type` (=
   id-ct-TSTInfo) and `message-digest` (= the digest of the TSTInfo DER).
   The signature covers the signed attributes re-encoded as a `SET`.
3. **Imprint.** The TSTInfo `messageImprint` is SHA-256 of `input`.
4. **Policy.** The TSTInfo `policy` is `1.3.6.1.4.1.57264.2`, the Sigstore
   timestamp policy.
5. **Authority.** The signer (issuer + serial) is the signing certificate of
   some authority in the trusted root (its chain's first certificate), and
   chains to that authority's root, which must be byte-identical to the
   chain's last certificate. Certificates embedded in the token are never
   trusted on their own.
6. **Signing certificate.** An end entity (not a CA) with a **critical**
   extended key usage naming **only** `id-kp-timeStamping`; an intermediate
   with an EKU must allow timestamping or any usage.
7. **Time.** Every certificate in the chain is valid at `genTime`, and the
   authority's `validFor` window contains `genTime`.
8. **Encoding.** The response is exactly one DER value; trailing bytes reject.

The production Sigstore TSA key is P-384 but signs **SHA-256** digests with
`ecdsa-with-SHA256`; `granted-p384-key-sha256-digest` pins that. Its
certificates are signed with SHA-384, as a P-384 CA issues them.

### Vectors

| id | expected | rule |
|---|---|---|
| `granted-p256` | accept | granted, P-256 authority |
| `granted-p384-key-sha256-digest` | accept | granted, P-384 authority signing a SHA-256 digest |
| `granted-with-mods` | reject | status `grantedWithMods` with a valid token — see note |
| `status-rejected` | reject | status `rejection`, no token |
| `imprint-mismatch` | reject | imprint over other bytes |
| `wrong-policy` | reject | policy OID is not the Sigstore one |
| `unknown-authority` | reject | signer and root not in the trusted root |
| `before-window` / `after-window` | reject | `genTime` outside the authority's `validFor` (certificates valid) |
| `signer-expired` | reject | signing certificate expired before `genTime` (window contains it) |
| `eku-not-critical` | reject | timestamping EKU present but not critical |
| `no-eku` | reject | no EKU extension |
| `trailing-bytes` | reject | a byte follows the DER response |
| `tampered-gentime` | reject | `genTime` altered after signing (message-digest mismatch) |

**Note on `granted-with-mods`.** RFC 3161 lets a `grantedWithMods` response
carry a token, but the reference's timestamp parser accepts only
`granted`. The vector records the reference verdict (reject). An SDK that
accepts `grantedWithMods` is more permissive than the reference and fails
this vector.
