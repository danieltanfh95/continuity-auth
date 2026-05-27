# continuity-auth — cryptographic protocol

This document specifies, byte-for-byte, what the client signs and what the server verifies. It is the contract between the ClojureScript client library and the Clojure-JVM service. Bugs here are catastrophic.

## Signature algorithms

| Algorithm | Identifier | Pubkey encoding | Signature |
|---|---|---|---|
| Ed25519 (preferred) | `:ed25519` | 32 raw bytes (Web Crypto `raw` format) | 64 raw bytes R \|\| S |
| ECDSA P-256 + SHA-256 (fallback) | `:p256` | 65 bytes uncompressed SEC1 (`0x04 \|\| X[32] \|\| Y[32]`) | 64 raw bytes R \|\| S |

Wire format for both is base64url-unpadded. We do **not** accept DER-encoded ECDSA signatures on the wire. That would create two representations for the same value.

## Pubkey thumbprint (`key_id`)

```
thumbprint = SHA-256(canonical_pubkey_bytes)
```

32 bytes, used as `:pubkey/id` in the database (unique-identity attribute) and as the `key_id` field of every envelope. The client computes this when generating its key. The server recomputes and verifies the match during bootstrap.

## Canonical signing input

The signature covers a deterministic length-prefixed binary representation of the envelope. This is NOT JSON. JSON canonicalization has too many edge cases (Unicode normalization, number formatting, key ordering, whitespace).

```
"FPL2\n"                                   ; version tag, 5 bytes literal
uint32-BE(len) || method                   ; UTF-8 method, e.g. "POST"
uint32-BE(len) || path                     ; UTF-8 path + canonical query
uint32-BE(len) || body_sha256              ; 32 bytes raw SHA-256 of body
uint32-BE(len) || ts_iso8601               ; UTF-8 ISO-8601 with ms precision
uint32-BE(len) || nonce                    ; 16 bytes raw
uint32-BE(len) || fp_digest                ; 32 bytes raw SHA-256 of fingerprint signals
uint32-BE(len) || host_user_id             ; UTF-8 string; empty allowed (len=0)
uint32-BE(len) || key_id                   ; 32 bytes raw (pubkey thumbprint)
```

`len` is the field's byte length as a big-endian unsigned 32-bit integer. Field ordering is fixed. The version tag `FPL2\n` prevents accidental signing-compatibility with adjacent protocol revisions. (FPL1 was the initial wire tag. The bump to FPL2 on 2026-05-25 went alongside the route-binding tightening on control endpoints. Envelopes signed under FPL1 will not verify against the FPL2 server.)

**Maximum field sizes** (enforced):
- `method`: 16 bytes
- `path`: 4096 bytes
- `ts_iso8601`: 40 bytes
- `host_user_id`: 256 bytes

Sizes for `body_sha256`, `nonce`, `fp_digest`, `key_id` are fixed by algorithm and rejected otherwise.

## Canonical query-string ordering

The signed path includes any query string. Query parameters MUST be in canonical (lexicographic) order before signing. The server reorders any received query string to canonical order before reconstructing the bytes. **Do not include duplicated parameter names** in queries. Client behavior is undefined.

Example:
- Sent: `/v1/foo?z=1&a=2`
- Canonical: `/v1/foo?a=2&z=1`

## Body hash

```
body_sha256 = SHA-256(request_body_bytes)
```

For requests with no body (e.g. `GET`), `body_sha256 = SHA-256(empty_string)` =
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Fingerprint digest

```
fp_digest = SHA-256(canonical_fingerprint_signals)
```

`fp-digest` is a 32-byte SHA-256 of a substrate-chosen, substrate-stable signal bundle. The protocol accepts any 32-byte value (the digest is treated as a **claimed** signal, see `ontology.md §2`, and never gates merges), but a caller that emits a stable digest across calls earns the corroborating-signal benefit when the (ip, fp-digest, pubkey) tuple recurs.

### Browser substrate (canonical)

For the browser substrate, `canonical_fingerprint_signals` is the concatenation of, in fixed order:

1. UTF-8 of `navigator.userAgent`
2. UTF-8 of `screen.width "x" screen.height "x" screen.colorDepth`
3. UTF-8 of `Intl.DateTimeFormat().resolvedOptions().timeZone`
4. UTF-8 of `navigator.hardwareConcurrency`
5. UTF-8 of `navigator.language + "," + navigator.languages.join(",")`
6. Canvas hash (drawn fixed text + emoji + gradient, then SHA-256 of pixel buffer)
7. UTF-8 of WebGL `getParameter(VENDOR)` + `","` + `getParameter(RENDERER)`
8. SHA-256 of 100ms of AudioContext output for a fixed oscillator
9. UTF-8 of font-probe widths, joined by `,`

Each signal is preceded by its UTF-8 name and a `:` separator, then `\n`-terminated. The browser client library is the authoritative implementation (`src/continuity_auth/client/fingerprint.cljs`).

### CLI substrate (current, unprincipled)

The current `bin/continuity auth init` (see `src/continuity_auth/client/cli.clj` `cmd-init`) emits 32 random bytes at bootstrap and persists them to `$CONTINUITY_AUTH_HOME/identity.edn`. This is **functionally correct** (the digest stays stable across subsequent verifies, so the tuple-recurrence path works) but **structurally unprincipled** (the digest carries no machine-identifying information, so an operator who copies `$CONTINUITY_AUTH_HOME` across two machines presents the same fp-digest from both, losing the ip-mismatch signal). A v1.1 follow-on derives the CLI bundle from machine-stable signals (hostname, OS, arch, machine-id where available). The wire format does not change.

### Other substrates

Hardware-anchored substrates (TPM, Secure Enclave, Android Keystore, iOS Keychain) MAY derive the bundle from substrate-natural attestation properties. Substrate authors choose their canonical bundle. The protocol cares only about the 32-byte output.

## Replay protection parameters

- Timestamp tolerance: ±60 seconds.
- Nonce TTL in cache: 120 seconds.
- Nonce is 16 raw random bytes per request. Cache key is `SHA-256(nonce)` (32 bytes).

## Verification sequence (server)

The server, on receiving any signed envelope:

1. Parse the wire envelope. Reject `E_BAD_REQUEST` on malformed input or size violations.
2. Confirm `ts` is within ±60 s of server clock. Reject `E_UNAUTHORIZED` otherwise.
3. Resolve the pubkey:
   - For `/v1/verify` and other post-bootstrap paths: look up `key_id` in the database (`:pubkey/id`). Reject `E_UNAUTHORIZED` if not found.
   - For `/v1/bootstrap`: take the pubkey from the request body, then confirm `SHA-256(pubkey) == key_id`.
4. Reject `E_FORBIDDEN` if the pubkey has `:pubkey/revoked-at` set.
5. Reconstruct the canonical signing input (deterministic, the same bytes the client signed).
6. Verify the signature against the pubkey bytes + algorithm. Reject `E_UNAUTHORIZED` on failure.
7. Atomically check + record the nonce (single transact with `:db.unique/value`). Reject `E_REPLAY` on duplicate.

Only on success is downstream logic (identity classification, rate-limit decision) executed.

## Test vectors

The server-side verification is tested against externally-verified vectors:

- **Ed25519:** RFC 8032 §7.1 Test 1 and Test 2 (`test/.../crypto/verify_test.clj` `ed25519-rfc8032-test1-valid`).
- **ECDSA P-256 + SHA-256:** RFC 6979 §A.2.5 "sample" and "test" deterministic vectors.

The envelope codec is tested for cross-platform parity:

- `test/.../envelope_test.cljc` — deterministic, ordering-insensitive, field-injective.
- `test/.../envelope_property_test.cljc` — roundtrip, base64url roundtrip, uint32-BE invertibility (200 trials each).

Cross-platform parity is asserted at `test/continuity_auth/client/envelope_parity_test.cljs`. The same fixture envelope is canonicalized in cljs. The test pins the version-tag prefix, the uint32-BE length-prefix layout, determinism, and method-sensitivity at byte granularity, so any drift from the JVM's canonical bytes would manifest as a failing hex comparison.

## Forward compatibility

The current version tag is `FPL2\n`. A future revision would emit a new tag (e.g. `FPL3\n`). The server can support adjacent tags side-by-side during migration. The wire tag is the only signal a verifier needs to discriminate versions. Clients of any vintage embed it in the bytes they signed.
