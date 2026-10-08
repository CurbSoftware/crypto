#!/usr/bin/env python3
"""Independent check of vectors/v1.json. Fail if TypeScript and Python disagree."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors" / "v1.json"
DOMAIN_VECTORS = ROOT / "vectors" / "domain-v1.json"


def b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    import base64

    return base64.b64decode(value.encode("ascii"))


def hexd(value: str) -> bytes:
    return bytes.fromhex(value)


def hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 with an empty salt, matching @noble/hashes."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(
            prk, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        okm += block
        counter += 1
    return okm[:length]


def check_domain_vector() -> str | None:
    domain = json.loads(DOMAIN_VECTORS.read_text())
    if b"revision" in bytes.fromhex(domain["aadHex"]):
        return "domain aad binds a server revision"
    aes = AESGCM(hexd(domain["domainKeyHex"]))
    ciphertext = aes.encrypt(
        hexd(domain["ivHex"]),
        hexd(domain["plaintextHex"]),
        hexd(domain["aadHex"]),
    )
    body, tag = ciphertext[:-16], ciphertext[-16:]
    if body.hex() != domain["ciphertextHex"] or tag.hex() != domain["tagHex"]:
        return "domain aes-gcm mismatch"
    wrapped = aes_key_wrap(hexd(domain["aekHex"]), hexd(domain["domainKeyHex"]))
    if wrapped.hex() != domain["wrappedKeyHex"]:
        return "domain aes-kw mismatch"
    if aes_key_unwrap(hexd(domain["aekHex"]), wrapped).hex() != domain["domainKeyHex"]:
        return "domain aes-kw unwrap mismatch"
    info = b"curbapps/domain-key-id/v1\0curbpage\x001"
    key_id = "dk_v1_" + hkdf_sha256(hexd(domain["domainKeyHex"]), info, 16).hex()
    if key_id != domain["keyId"]:
        return "domain key id mismatch"
    return None


def main() -> int:
    payload = json.loads(VECTORS.read_text())
    argon = payload["argon2id"]
    derived = hash_secret_raw(
        secret=argon["password"].encode("utf-8"),
        salt=hexd(argon["saltHex"]),
        time_cost=argon["t"],
        memory_cost=argon["m"],
        parallelism=argon["p"],
        hash_len=argon["dkLen"],
        type=Type.ID,
    )
    if derived.hex() != argon["masterKeyHex"]:
        print("argon2id mismatch", file=sys.stderr)
        return 1

    gcm = payload["aesGcm"]
    aes = AESGCM(hexd(gcm["keyHex"]))
    aad = hexd(gcm["aadHex"]) if gcm.get("aadHex") else None
    ciphertext = aes.encrypt(hexd(gcm["ivHex"]), hexd(gcm["plaintextHex"]), aad)
    body, tag = ciphertext[:-16], ciphertext[-16:]
    if body.hex() != gcm["ciphertextHex"] or tag.hex() != gcm["tagHex"]:
        print("aes-gcm mismatch", file=sys.stderr)
        return 1

    wrap = payload["aesKw"]
    wrapped = aes_key_wrap(hexd(wrap["kekHex"]), hexd(wrap["keyHex"]))
    if wrapped.hex() != wrap["wrappedHex"]:
        print("aes-kw wrap mismatch", file=sys.stderr)
        return 1
    unwrapped = aes_key_unwrap(hexd(wrap["kekHex"]), wrapped)
    if unwrapped.hex() != wrap["keyHex"]:
        print("aes-kw unwrap mismatch", file=sys.stderr)
        return 1

    wrap256 = payload["aesKw256"]
    wrapped256 = aes_key_wrap(hexd(wrap256["kekHex"]), hexd(wrap256["keyHex"]))
    if wrapped256.hex() != wrap256["wrappedHex"]:
        print("aes-kw-256 wrap mismatch", file=sys.stderr)
        return 1
    unwrapped256 = aes_key_unwrap(hexd(wrap256["kekHex"]), wrapped256)
    if unwrapped256.hex() != wrap256["keyHex"]:
        print("aes-kw-256 unwrap mismatch", file=sys.stderr)
        return 1

    domain_error = check_domain_vector()
    if domain_error:
        print(domain_error, file=sys.stderr)
        return 1

    print("ok")
    return 0


def generate() -> None:
    password = "correct horse battery staple"
    salt = bytes(range(16))
    params = dict(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, type=Type.ID)
    master = hash_secret_raw(secret=password.encode("utf-8"), salt=salt, **params)

    key = bytes(range(32))
    iv = bytes(range(12))
    aad = b"curbapps/vector/v1"
    plaintext = b"attack at dawn"
    ciphertext = AESGCM(key).encrypt(iv, plaintext, aad)

    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    wrap_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    wrapped = aes_key_wrap(kek, wrap_key)

    kek256 = bytes.fromhex(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    )
    wrap_key256 = bytes.fromhex(
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
    )
    wrapped256 = aes_key_wrap(kek256, wrap_key256)

    payload = {
        "argon2id": {
            "password": password,
            "saltHex": salt.hex(),
            "t": 2,
            "m": 19456,
            "p": 1,
            "dkLen": 32,
            "masterKeyHex": master.hex(),
        },
        "aesGcm": {
            "keyHex": key.hex(),
            "ivHex": iv.hex(),
            "aadHex": aad.hex(),
            "plaintextHex": plaintext.hex(),
            "ciphertextHex": ciphertext[:-16].hex(),
            "tagHex": ciphertext[-16:].hex(),
        },
        "aesKw": {
            "kekHex": kek.hex(),
            "keyHex": wrap_key.hex(),
            "wrappedHex": wrapped.hex(),
        },
        "aesKw256": {
            "kekHex": kek256.hex(),
            "keyHex": wrap_key256.hex(),
            "wrappedHex": wrapped256.hex(),
        },
    }
    VECTORS.parent.mkdir(parents=True, exist_ok=True)
    VECTORS.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {VECTORS}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--generate"]:
        generate()
        raise SystemExit(0)
    raise SystemExit(main())
