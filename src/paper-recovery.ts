import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { aesKwUnwrap, aesKwWrap, randomBytes } from './aes';
import { base64ToBytes, bytesToBase64 } from './base64';
import { wipe } from './wipe';

const PAPER_RECOVERY_INFO = new TextEncoder().encode(
  'curbapps/paper-recovery/v1',
);
const PAPER_KEY_BYTES = 32;
const PAPER_SALT_BYTES = 16;

/**
 * High-entropy recovery secret, generated on the client. The server stores
 * only {@link PaperRecoveryWrapV1}. This is not part of EncryptedRecoveryBlobV1.
 */
export interface PaperRecoveryWrapV1 {
  version: 1;
  algorithm: 'AES-KW-256';
  kdf: 'HKDF-SHA256';
  saltBase64: string;
  wrappedAekBase64: string;
}

export function generatePaperRecoveryKey(): Uint8Array {
  return randomBytes(PAPER_KEY_BYTES);
}

function paperKek(paperKey: Uint8Array, salt: Uint8Array): Uint8Array {
  if (paperKey.length !== PAPER_KEY_BYTES) {
    throw new Error('Paper recovery key must be 32 bytes');
  }
  if (salt.length !== PAPER_SALT_BYTES) {
    throw new Error('Paper recovery salt must be 16 bytes');
  }
  return hkdf(sha256, paperKey, salt, PAPER_RECOVERY_INFO, 32);
}

export async function wrapAekWithPaperKey(
  aek: Uint8Array,
  paperKey: Uint8Array,
  salt: Uint8Array = randomBytes(PAPER_SALT_BYTES),
): Promise<PaperRecoveryWrapV1> {
  if (aek.length !== 32) throw new Error('AEK must be 32 bytes');
  const kek = paperKek(paperKey, salt);
  try {
    const wrapped = await aesKwWrap(aek, kek);
    return {
      version: 1,
      algorithm: 'AES-KW-256',
      kdf: 'HKDF-SHA256',
      saltBase64: bytesToBase64(salt),
      wrappedAekBase64: bytesToBase64(wrapped),
    };
  } finally {
    wipe(kek);
  }
}

export async function unwrapAekWithPaperKey(
  paperKey: Uint8Array,
  wrap: PaperRecoveryWrapV1,
): Promise<Uint8Array> {
  if (
    wrap.version !== 1 ||
    wrap.algorithm !== 'AES-KW-256' ||
    wrap.kdf !== 'HKDF-SHA256'
  ) {
    throw new Error('Paper recovery wrap is invalid');
  }
  const salt = base64ToBytes(wrap.saltBase64);
  const kek = paperKek(paperKey, salt);
  try {
    const aek = await aesKwUnwrap(base64ToBytes(wrap.wrappedAekBase64), kek);
    if (aek.length !== 32) {
      aek.fill(0);
      throw new Error('Paper recovery wrap is invalid');
    }
    return aek;
  } finally {
    wipe(kek);
  }
}
