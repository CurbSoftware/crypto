# Changelog

## 0.3.0

- Version 3 domain envelopes. Each scope gets its own random 256-bit key, wrapped with the existing AEK.
- Resource AAD binds account, scope, entity id, entity kind, key epoch, and protocol version. No server revision.
- Domain lookup HMACs use a scope-separated HKDF info string. Account lookup HMACs are unchanged.
- Version 1 envelopes and recovery blob version 1 still open.

## 0.2.0

- Standalone package: no `@curbapps/core` or other workspace dependencies.
- Argon2id unlock floor (19 MiB, t=2, p=1). Weaker recovery descriptors fail closed.
- AEK verifier AAD binds KDF parameters.
- Ed25519-signed account identity documents.
- Transcript-bound X25519 ECDH wrap (v2).
- Argon2id note shares; PBKDF2 shares still decrypt.
- Opaque key types, `SecureAekStore`, lookup HMAC helper.
- Room, password-payload, sealed-file, XChaCha, and chunked-attachment APIs.
- Published test vectors (including RFC 3394 AES-KW-256) and a Python verifier.

## 0.1.0

- Initial in-monorepo keyring: Argon2id, AES-KW, AES-GCM, X25519, recovery blobs.
