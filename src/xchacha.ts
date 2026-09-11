import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { randomBytes } from './aes';
import { base64ToBytes, bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV2 } from './envelope';

const TAG_BYTES = 16;
const NONCE_BYTES = 24;

export interface XChaChaEncryptOptions {
  aad?: Uint8Array;
  nonce?: Uint8Array;
  keyId: string;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export async function xchachaEncrypt(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  opts: XChaChaEncryptOptions,
): Promise<EncryptedEnvelopeV2> {
  if (keyBytes.length !== 32) {
    throw new Error('XChaCha20-Poly1305 requires a 32-byte key');
  }
  if (
    typeof opts.keyId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(opts.keyId)
  ) {
    throw new Error('XChaCha keyId must be a non-empty opaque identifier');
  }

  const nonce = opts.nonce ?? randomBytes(NONCE_BYTES);
  if (nonce.length !== NONCE_BYTES) {
    throw new Error('XChaCha20-Poly1305 nonce must be 24 bytes');
  }

  const full = xchacha20poly1305(keyBytes, nonce, opts.aad).encrypt(plaintext);
  return {
    version: 2,
    algorithm: 'XCHACHA20-POLY1305',
    keyId: opts.keyId,
    nonceBase64: bytesToBase64(nonce),
    ciphertextBase64: bytesToBase64(full.subarray(0, full.length - TAG_BYTES)),
    authTagBase64: bytesToBase64(full.subarray(full.length - TAG_BYTES)),
    aadBase64: opts.aad ? bytesToBase64(opts.aad) : undefined,
  };
}

export async function xchachaDecrypt(
  envelope: EncryptedEnvelopeV2,
  keyBytes: Uint8Array,
): Promise<Uint8Array> {
  if (envelope.version !== 2 || envelope.algorithm !== 'XCHACHA20-POLY1305') {
    throw new Error('Unsupported XChaCha envelope');
  }
  const nonce = base64ToBytes(envelope.nonceBase64);
  const ciphertext = base64ToBytes(envelope.ciphertextBase64);
  const tag = base64ToBytes(envelope.authTagBase64);
  const aad = envelope.aadBase64
    ? base64ToBytes(envelope.aadBase64)
    : undefined;
  return xchacha20poly1305(keyBytes, nonce, aad).decrypt(
    concatBytes(ciphertext, tag),
  );
}
