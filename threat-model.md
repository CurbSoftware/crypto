# Threat model

## Assets

- Account encryption key (AEK)
- Per-scope domain keys (random 256-bit keys wrapped by the AEK)
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

### Domain keys

Each scope has its own random key, wrapped by the AEK. A version 3 envelope
also carries that wrap, so anyone who holds the AEK can open every scope. A
client that holds only one domain key cannot open the others. Grants that
deliver a single domain key are not issued by this package yet. The recovery
blob stays version 1 and does not include the domain-key set.

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
