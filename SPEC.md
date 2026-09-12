# Protocol specification

Authority for algorithms and wire formats. Product mapping (which entity kinds
exist) lives in the CurbApps monorepo `docs/data-model.md`.

## Key hierarchy

```
password
  -> Argon2id (m=19456 KiB, t=2, p=1, 32-byte output) -> master key (MK)
       -> AES-KW-256 wraps AEK
AEK (32 random bytes)
  -> AES-256-GCM entity payloads (EncryptedEnvelopeV1)
  -> AES-256-GCM device X25519 private key
  -> AES-256-GCM identity X25519 private key
  -> AES-256-GCM identity Ed25519 private key
  -> HKDF-SHA256 -> HMAC-SHA256 lookup digests
```

Password change rewraps the AEK. Entity ciphertext is not rewritten.

Unlock rejects Argon2 parameters below the floor above. KDF parameters are
bound into the AEK verifier AAD so a swapped descriptor cannot be used with
the same wrapped key.

## Envelopes

### EncryptedEnvelopeV1

JSON:

- `version`: `1`
- `algorithm`: `AES-GCM-256`
- `keyId`: opaque identifier (entity envelopes use `aek_v1_` + 16-byte hex)
- `ivBase64`: 12 bytes
- `ciphertextBase64`
- `authTagBase64`: 16 bytes
- `aadBase64`: optional additional authenticated data

Entity AAD is `curbapps/entity-envelope/v1\0` + `keyId`.

### EncryptedEnvelopeV2

JSON:

- `version`: `2`
- `algorithm`: `XCHACHA20-POLY1305`
- `keyId`
- `nonceBase64`: 24 bytes
- `ciphertextBase64`
- `authTagBase64`: 16 bytes
- `aadBase64`

Used for chunked attachments. Entity writes remain v1.

### WrappedAccountKeyV1

AES-KW-256 of the AEK under MK, plus an AEK verifier envelope. Verifier AAD
(new wraps) is `curbapps/aek-verifier/v1\0` + canonical KDF fields.

## Identity

Each account has:

- X25519 keypair (ECDH)
- Ed25519 keypair (signatures)

The identity document is `{ version: 1, x25519PublicKeyBase64, ed25519PublicKeyBase64, signatureBase64 }`
where the signature is Ed25519 over `curbapps/identity/v1\0 || x25519_public`.

Legacy rows may be a raw 32-byte X25519 public key. New grants should verify
the signed document before wrapping a key to that peer.

## ECDH wrap

v1 info string: `curbapps-ecdh-wrap-v1` (legacy grants).

v2 info string: `curbapps/ecdh-wrap/v2\0 || min(pub_a, pub_b) || max(pub_a, pub_b) || purpose \0 grantId \0 entityId`

## Shares

New password-protected shares use Argon2id at the same floor as the master
key, then AES-KW of a random share key. Open still accepts PBKDF2-SHA256
100k envelopes.

## What the server sees

Ciphertext, sizes, timestamps, routing metadata (account, data scope, entity
kind), public identity keys, and wrapped recovery blobs. It never receives
the password, MK, or AEK.

## Test vectors

See `vectors/v1.json`. `pnpm test` checks them in TypeScript.
`python3 verify/verify.py` checks them independently. AES-KW includes the
RFC 3394 §4.1 (128-bit) and §4.6 (256-bit) wrap/unwrap pairs.
