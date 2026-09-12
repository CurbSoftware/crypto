import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { aesGcmDecrypt, aesGcmEncrypt } from './aes';
import {
  DEFAULT_ARGON2_PARAMS,
  deriveUnlockMasterKey,
  generateSalt,
} from './argon2';
import { base64ToBytes, bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV1, KdfDescriptor } from './envelope';
import { wipe } from './wipe';

const LEGACY_PBKDF2_ITERATIONS = 100_000;
const PAYLOAD_KEY_ID = 'password-payload';

export interface PasswordPayloadV1 {
  v: 1;
  alg: 'argon2id-aes-gcm-256';
  kdf: KdfDescriptor;
  enc: EncryptedEnvelopeV1;
}

function isPasswordPayloadV1(value: unknown): value is PasswordPayloadV1 {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.v === 1 &&
    record.alg === 'argon2id-aes-gcm-256' &&
    typeof record.kdf === 'object' &&
    record.kdf !== null &&
    typeof record.enc === 'object' &&
    record.enc !== null
  );
}

export async function encryptPasswordPayload(
  plaintext: string,
  password: string,
): Promise<string> {
  const cipher = await createPasswordPayloadCipher(password);
  try {
    return cipher.encrypt(plaintext);
  } finally {
    cipher.dispose();
  }
}

export interface PasswordPayloadCipher {
  encrypt(plaintext: string): Promise<string>;
  dispose(): void;
}

/**
 * Derive the project-password key once, then encrypt many fields. Dispose
 * after the batch so the key does not linger.
 */
export async function createPasswordPayloadCipher(
  password: string,
): Promise<PasswordPayloadCipher> {
  const salt = generateSalt();
  const kdf: KdfDescriptor = {
    algorithm: 'ARGON2ID',
    saltBase64: bytesToBase64(salt),
    iterations: DEFAULT_ARGON2_PARAMS.iterations,
    memoryKb: DEFAULT_ARGON2_PARAMS.memoryKb,
    parallelism: DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: DEFAULT_ARGON2_PARAMS.hashLength,
  };
  const key = await deriveUnlockMasterKey(
    password,
    salt,
    DEFAULT_ARGON2_PARAMS,
  );
  let live = true;
  return {
    async encrypt(plaintext: string): Promise<string> {
      if (!live) {
        throw new Error('password payload cipher has been disposed');
      }
      const enc = await aesGcmEncrypt(
        new TextEncoder().encode(plaintext),
        key,
        { keyId: PAYLOAD_KEY_ID },
      );
      const payload: PasswordPayloadV1 = {
        v: 1,
        alg: 'argon2id-aes-gcm-256',
        kdf,
        enc,
      };
      return JSON.stringify(payload);
    },
    dispose(): void {
      live = false;
      wipe(key);
    },
  };
}

async function decryptLegacyPasswordPayload(
  ciphertext: string,
  password: string,
): Promise<string> {
  const parsed = JSON.parse(
    new TextDecoder().decode(base64ToBytes(ciphertext)),
  ) as {
    salt?: unknown;
    iv?: unknown;
    data?: unknown;
  };
  if (
    !Array.isArray(parsed.salt) ||
    !Array.isArray(parsed.iv) ||
    !Array.isArray(parsed.data)
  ) {
    throw new Error('legacy password payload is malformed');
  }
  const salt = Uint8Array.from(parsed.salt);
  const iv = Uint8Array.from(parsed.iv);
  const data = Uint8Array.from(parsed.data);
  const key = await pbkdf2Async(sha256, password, salt, {
    c: LEGACY_PBKDF2_ITERATIONS,
    dkLen: 32,
  });
  try {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
      throw new Error(
        'WebCrypto is required to open a legacy password payload',
      );
    }
    const cryptoKey = await subtle.importKey(
      'raw',
      new Uint8Array(key),
      'AES-GCM',
      false,
      ['decrypt'],
    );
    const plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      cryptoKey,
      new Uint8Array(data),
    );
    return new TextDecoder().decode(plaintext);
  } finally {
    wipe(key);
  }
}

export function isPasswordPayloadCiphertext(value: string): boolean {
  const trimmed = value.trimStart();
  if (!trimmed.startsWith('{')) return false;
  try {
    return isPasswordPayloadV1(JSON.parse(trimmed));
  } catch {
    return false;
  }
}

export async function decryptPasswordPayload(
  ciphertext: string,
  password: string,
): Promise<string> {
  const trimmed = ciphertext.trimStart();
  if (trimmed.startsWith('{')) {
    const parsed: unknown = JSON.parse(trimmed);
    if (!isPasswordPayloadV1(parsed)) {
      throw new Error('Unsupported password payload');
    }
    const salt = base64ToBytes(parsed.kdf.saltBase64);
    const key = await deriveUnlockMasterKey(password, salt, {
      memoryKb: parsed.kdf.memoryKb,
      iterations: parsed.kdf.iterations,
      parallelism: parsed.kdf.parallelism,
      hashLength: parsed.kdf.hashLength,
    });
    try {
      const bytes = await aesGcmDecrypt(parsed.enc, key);
      return new TextDecoder().decode(bytes);
    } finally {
      wipe(key);
    }
  }

  try {
    return await decryptLegacyPasswordPayload(ciphertext.trim(), password);
  } catch {
    throw new Error(
      'Failed to decrypt data - incorrect password or corrupted file',
    );
  }
}
