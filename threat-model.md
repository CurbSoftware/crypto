# Threat model

## Assets

- Account encryption key (AEK)
- Master password and derived master key
- Entity plaintext (bookmarks, notes, vault entries, OTP secrets, ...)
- Identity private keys (X25519, Ed25519)
- Share keys and room keys

## Adversaries

### Stolen D1 / Worker disk

Sees ciphertext, recovery blobs, public keys, grant wrappers, sizes, and
timestamps. Cannot decrypt without the password or a device AEK.

### Malicious Worker

Can withhold or replay ciphertext. Can try to swap a recovery blob (blocked
by ETag compare-and-swap). Can try to inject an identity public key; signed
identity documents make that detectable. Cannot mint a valid AEK verifier.

### Stolen browser profile (auto-unlock)

Reads the raw AEK from `storage.local` and decrypts local and synced entities
for that install. This is the documented cost of passwordless local unlock.
Master-password mode stores only wrapped material.

### Offline password guessing

Attacker with a recovery blob can run Argon2id at the published floor. Unlock
refuses weaker parameters. There is no server-side password hash to steal.

### Share URL phishing

Passwordless shares put the key in the URL fragment. Anyone with the link can
decrypt that snapshot. Password-protected shares require the share password.
