# @curbapps/crypto

Auditable end-to-end encryption for CurbApps. This package is the only place
client code should derive keys, wrap keys, or encrypt user data.

The implementation is TypeScript on [`@noble/hashes`](https://github.com/paulmillr/noble-hashes),
[`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers),
[`@noble/curves`](https://github.com/paulmillr/noble-curves), and WebCrypto
AES-GCM when `crypto.subtle` is available. There is no WASM blob and no
server-side decrypt path.

## Algorithms

- Argon2id (OWASP floor: 19 MiB, t=2, p=1) derives a master key from a password
- AES-KW-256 wraps the random Account Encryption Key (AEK)
- AES-256-GCM encrypts entity payloads (protocol v1 under the AEK, protocol v3 under a per-scope domain key)
- XChaCha20-Poly1305 encrypts chunked attachments (protocol v2)
- X25519 ECDH wraps keys for another device or account
- Ed25519 signs identity public keys so the sync server cannot inject a peer key

Read [SPEC.md](./SPEC.md) for envelopes, the key hierarchy, and test vectors.
Read [threat-model.md](./threat-model.md) for what a stolen server or stolen
browser profile can and cannot do.

## Install

```bash
pnpm add @curbapps/crypto
```

In the CurbApps monorepo this directory is a git submodule. Clone with:

```bash
git clone --recurse-submodules https://github.com/CurbSoftware/curbapps-monorepo.git
```

## What this package does not do

- It does not talk to the network.
- It does not persist keys. Hosts use `SecureAekStore` for auto-unlock.
- It does not implement billing, apps, or UI.
- Auto-unlock in a browser extension is as strong as `browser.storage.local`.
  A master password is required for cloud recovery.

## Develop

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm lint
```

Python verifier (optional, for published vectors):

```bash
python3 -m pip install -r verify/requirements.txt
python3 verify/verify.py
```
