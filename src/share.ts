import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesKwUnwrap,
  aesKwWrap,
  randomBytes,
} from './aes';
import {
  DEFAULT_ARGON2_PARAMS,
  deriveUnlockMasterKey,
  generateSalt,
} from './argon2';
import { base64ToBytes, bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV1, KdfDescriptor } from './envelope';
import { asShareKey, type ShareKey } from './opaque';
import { wipe } from './wipe';

/**
 * Zero-knowledge note sharing primitives.
 *
 * A share is a note snapshot encrypted under a random 32-byte "share key":
 *
 * - **password-protected**: the share key is AES-KW-wrapped under a KEK derived
 *   from the recipient password via Argon2id (new shares) or PBKDF2 (legacy).
 *   The server stores only the salt, the wrapped key, and the ciphertext.
 * - **passwordless**: the raw share key travels in the URL *fragment* (which
 *   never reaches the server); the server stores only the ciphertext.
 */

const SHARE_KEY_BYTES = 32;
const SHARE_SALT_BYTES = 16;
export const SHARE_PBKDF2_ITERATIONS = 100_000;

export type ShareKdfDescriptor =
  | {
      algorithm: 'ARGON2ID';
      saltBase64: string;
      iterations: number;
      memoryKb: number;
      parallelism: number;
      hashLength: number;
    }
  | {
      algorithm: 'PBKDF2-SHA256';
      iterations: number;
      saltBase64: string;
    };

export interface BuiltShare {
  ciphertext: string;
  passwordProtected: boolean;
  saltBase64: string | null;
  wrappedShareKeyBase64: string | null;
  kdf: ShareKdfDescriptor | null;
  /**
   * Raw share key as base64url. Non-null only for passwordless shares, where
   * the caller embeds it in the URL fragment. Null when password-protected
   * (the key must never leave the caller's memory in that mode).
   */
  shareKeyBase64Url: string | null;
}

export interface OpenShareInput {
  ciphertext: string;
  passwordProtected: boolean;
  saltBase64: string | null;
  kdf?: ShareKdfDescriptor | KdfDescriptor | null;
  wrappedShareKeyBase64?: string | null;
  password?: string;
  shareKeyBase64Url?: string;
}

export function generateShareKey(): ShareKey {
  return asShareKey(randomBytes(SHARE_KEY_BYTES));
}

export function generateShareSalt(): Uint8Array {
  return randomBytes(SHARE_SALT_BYTES);
}

export async function deriveShareKek(
  password: string,
  salt: Uint8Array,
  kdf?: ShareKdfDescriptor | KdfDescriptor | null,
): Promise<Uint8Array> {
  if (kdf?.algorithm === 'ARGON2ID') {
    return deriveUnlockMasterKey(password, salt, {
      memoryKb: kdf.memoryKb,
      iterations: kdf.iterations,
      parallelism: kdf.parallelism,
      hashLength: kdf.hashLength ?? SHARE_KEY_BYTES,
    });
  }
  const iterations =
    kdf && 'iterations' in kdf && typeof kdf.iterations === 'number'
      ? kdf.iterations
      : SHARE_PBKDF2_ITERATIONS;
  return pbkdf2Async(sha256, password, salt, {
    c: iterations,
    dkLen: SHARE_KEY_BYTES,
  });
}

export async function wrapShareKey(
  shareKey: Uint8Array,
  kek: Uint8Array,
): Promise<string> {
  return bytesToBase64(await aesKwWrap(shareKey, kek));
}

export async function unwrapShareKey(
  wrappedBase64: string,
  kek: Uint8Array,
): Promise<ShareKey> {
  return asShareKey(await aesKwUnwrap(base64ToBytes(wrappedBase64), kek));
}

export async function encryptSharePayload(
  plaintext: string,
  shareKey: Uint8Array,
): Promise<string> {
  const envelope = await aesGcmEncrypt(
    new TextEncoder().encode(plaintext),
    shareKey,
    { keyId: 'note-share' },
  );
  return JSON.stringify(envelope);
}

export async function decryptSharePayload(
  encryptedJson: string,
  shareKey: Uint8Array,
): Promise<string> {
  const envelope = JSON.parse(encryptedJson) as EncryptedEnvelopeV1;
  const bytes = await aesGcmDecrypt(envelope, shareKey);
  return new TextDecoder().decode(bytes);
}

function toBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value: string): Uint8Array {
  let b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return base64ToBytes(b64);
}

function argon2ShareKdf(salt: Uint8Array): ShareKdfDescriptor {
  return {
    algorithm: 'ARGON2ID',
    saltBase64: bytesToBase64(salt),
    iterations: DEFAULT_ARGON2_PARAMS.iterations,
    memoryKb: DEFAULT_ARGON2_PARAMS.memoryKb,
    parallelism: DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: DEFAULT_ARGON2_PARAMS.hashLength,
  };
}

export async function buildEncryptedShare(input: {
  plaintext: string;
  password?: string;
}): Promise<BuiltShare> {
  const shareKey = generateShareKey();

  if (input.password) {
    const salt = generateSalt();
    const kdf = argon2ShareKdf(salt);
    const kek = await deriveShareKek(input.password, salt, kdf);
    const wrappedShareKeyBase64 = await wrapShareKey(shareKey, kek);
    wipe(kek);

    const ciphertext = await encryptSharePayload(input.plaintext, shareKey);
    wipe(shareKey);

    return {
      ciphertext,
      passwordProtected: true,
      saltBase64: bytesToBase64(salt),
      wrappedShareKeyBase64,
      kdf,
      shareKeyBase64Url: null,
    };
  }

  return {
    ciphertext: await encryptSharePayload(input.plaintext, shareKey),
    passwordProtected: false,
    saltBase64: null,
    wrappedShareKeyBase64: null,
    kdf: null,
    shareKeyBase64Url: toBase64Url(shareKey),
  };
}

export async function openEncryptedShare(
  input: OpenShareInput,
): Promise<string> {
  if (input.passwordProtected) {
    if (!input.password) throw new Error('Password required');
    if (!input.saltBase64) throw new Error('Share is missing its salt');
    if (!input.wrappedShareKeyBase64) {
      throw new Error('Share is missing its wrapped key');
    }

    const kek = await deriveShareKek(
      input.password,
      base64ToBytes(input.saltBase64),
      input.kdf,
    );
    let shareKey: ShareKey;
    try {
      shareKey = await unwrapShareKey(input.wrappedShareKeyBase64, kek);
    } finally {
      wipe(kek);
    }
    try {
      return await decryptSharePayload(input.ciphertext, shareKey);
    } finally {
      wipe(shareKey);
    }
  }

  if (!input.shareKeyBase64Url) throw new Error('Missing share key');
  const shareKey = asShareKey(fromBase64Url(input.shareKeyBase64Url));
  try {
    return await decryptSharePayload(input.ciphertext, shareKey);
  } finally {
    wipe(shareKey);
  }
}
