import { gcm as gcmNoble, unsafe } from '@noble/ciphers/aes.js';

import { base64ToBytes, bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV1 } from './envelope';

const GCM_TAG_BYTES = 16;
const GCM_IV_BYTES = 12;
const AES_KW_BLOCK_BYTES = 8;

type CryptoLike = {
  getRandomValues?: <T extends ArrayBufferView>(array: T) => T;
  subtle?: SubtleCrypto;
};

function getCrypto(): CryptoLike | undefined {
  return (globalThis as unknown as { crypto?: CryptoLike }).crypto;
}

function getSubtle(): SubtleCrypto | undefined {
  return getCrypto()?.subtle;
}

/** Copy bytes into a fresh, `ArrayBuffer`-backed typed array for WebCrypto. */
function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

function assertAes256Key(keyBytes: Uint8Array): void {
  if (keyBytes.length !== 32) {
    throw new Error('AES-256 requires a 32-byte key');
  }
}

function assertAesKwKey(kekBytes: Uint8Array): void {
  if (
    kekBytes.length !== 16 &&
    kekBytes.length !== 24 &&
    kekBytes.length !== 32
  ) {
    throw new Error('AES-KW KEK must be 16, 24, or 32 bytes');
  }
}

export function randomBytes(n: number): Uint8Array {
  const cryptoObj = getCrypto();
  if (!cryptoObj?.getRandomValues) {
    throw new Error('randomBytes: no secure random source available');
  }
  const bytes = new Uint8Array(n);
  cryptoObj.getRandomValues(bytes);
  return bytes;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export type AesGcmEngine = 'auto' | 'webcrypto' | 'noble';

export interface AesGcmEncryptOptions {
  /** Additional authenticated data. */
  aad?: Uint8Array;
  /** Explicit 12-byte IV. Generated when omitted. */
  iv?: Uint8Array;
  /** Public identifier for the key. It must not contain key bytes. */
  keyId: string;
  /** Force a specific AES-GCM implementation. */
  engine?: AesGcmEngine;
}

export interface AesGcmDecryptOptions {
  /** Force a specific AES-GCM implementation. */
  engine?: AesGcmEngine;
}

async function gcmEncryptWebCrypto(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array }> {
  const subtle = getSubtle();
  if (!subtle) {
    throw new Error('WebCrypto (crypto.subtle) is unavailable');
  }

  const key = await subtle.importKey(
    'raw',
    toBufferSource(keyBytes),
    'AES-GCM',
    false,
    ['encrypt'],
  );

  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: toBufferSource(iv),
    tagLength: 128,
  };
  if (aad) {
    params.additionalData = toBufferSource(aad);
  }

  const full = new Uint8Array(
    await subtle.encrypt(params, key, toBufferSource(plaintext)),
  );
  return {
    ciphertext: full.subarray(0, full.length - GCM_TAG_BYTES),
    authTag: full.subarray(full.length - GCM_TAG_BYTES),
  };
}

async function gcmDecryptWebCrypto(
  ciphertext: Uint8Array,
  authTag: Uint8Array,
  keyBytes: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getSubtle();
  if (!subtle) {
    throw new Error('WebCrypto (crypto.subtle) is unavailable');
  }

  const key = await subtle.importKey(
    'raw',
    toBufferSource(keyBytes),
    'AES-GCM',
    false,
    ['decrypt'],
  );

  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: toBufferSource(iv),
    tagLength: 128,
  };
  if (aad) {
    params.additionalData = toBufferSource(aad);
  }

  const plaintext = await subtle.decrypt(
    params,
    key,
    toBufferSource(concatBytes(ciphertext, authTag)),
  );

  return new Uint8Array(plaintext);
}

function gcmEncryptNoble(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
): { ciphertext: Uint8Array; authTag: Uint8Array } {
  const full = gcmNoble(keyBytes, iv, aad).encrypt(plaintext);
  return {
    ciphertext: full.subarray(0, full.length - GCM_TAG_BYTES),
    authTag: full.subarray(full.length - GCM_TAG_BYTES),
  };
}

function gcmDecryptNoble(
  ciphertext: Uint8Array,
  authTag: Uint8Array,
  keyBytes: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  return gcmNoble(keyBytes, iv, aad).decrypt(concatBytes(ciphertext, authTag));
}

/**
 * AES-256-GCM encryption producing an `EncryptedEnvelopeV1`.
 *
 * Both the WebCrypto and the `@noble/ciphers` paths return `ciphertext || tag`
 * internally; the 16-byte tag is always split into a separate `authTag` so the
 * two paths produce byte-identical envelopes.
 */
export async function aesGcmEncrypt(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  opts: AesGcmEncryptOptions,
): Promise<EncryptedEnvelopeV1> {
  assertAes256Key(keyBytes);
  if (
    typeof opts?.keyId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(opts.keyId)
  ) {
    throw new Error('AES-GCM keyId must be a non-empty opaque identifier');
  }

  const iv = opts.iv ?? randomBytes(GCM_IV_BYTES);
  if (iv.length !== GCM_IV_BYTES) {
    throw new Error('AES-GCM IV must be 12 bytes');
  }

  const engine = opts.engine ?? 'auto';
  const useWebCrypto =
    engine === 'webcrypto' || (engine === 'auto' && !!getSubtle());

  const { ciphertext, authTag } = useWebCrypto
    ? await gcmEncryptWebCrypto(plaintext, keyBytes, iv, opts.aad)
    : gcmEncryptNoble(plaintext, keyBytes, iv, opts.aad);

  return {
    version: 1,
    algorithm: 'AES-GCM-256',
    keyId: opts.keyId,
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(ciphertext),
    authTagBase64: bytesToBase64(authTag),
    aadBase64: opts.aad ? bytesToBase64(opts.aad) : undefined,
  };
}

export async function aesGcmDecrypt(
  env: EncryptedEnvelopeV1,
  keyBytes: Uint8Array,
  opts: AesGcmDecryptOptions = {},
): Promise<Uint8Array> {
  assertAes256Key(keyBytes);

  const iv = base64ToBytes(env.ivBase64);
  const fullCiphertext = base64ToBytes(env.ciphertextBase64);

  // Tolerate envelopes that predate the separate authTag field by splitting
  // the trailing tag off the ciphertext when necessary.
  let ciphertext: Uint8Array;
  let authTag: Uint8Array;
  if (env.authTagBase64) {
    ciphertext = fullCiphertext;
    authTag = base64ToBytes(env.authTagBase64);
  } else {
    ciphertext = fullCiphertext.subarray(
      0,
      fullCiphertext.length - GCM_TAG_BYTES,
    );
    authTag = fullCiphertext.subarray(fullCiphertext.length - GCM_TAG_BYTES);
  }

  const aad = env.aadBase64 ? base64ToBytes(env.aadBase64) : undefined;

  const engine = opts.engine ?? 'auto';
  const useWebCrypto =
    engine === 'webcrypto' || (engine === 'auto' && !!getSubtle());

  return useWebCrypto
    ? await gcmDecryptWebCrypto(ciphertext, authTag, keyBytes, iv, aad)
    : gcmDecryptNoble(ciphertext, authTag, keyBytes, iv, aad);
}

const AES_KW_IV = Uint8Array.from([
  0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6,
]);

/**
 * XOR the 64-bit big-endian counter `t` into the low 8 bytes of `state`,
 * which hold the AES-KW `A` register. The counter is split into two 32-bit
 * halves because JavaScript's `>>>` wraps the shift count modulo 32.
 */
function xorAesKwCounter(state: Uint8Array, t: number): void {
  const low = t >>> 0;
  const high = Math.floor(t / 0x100000000);

  for (let k = 0; k < 4; k++) {
    state[7 - k] = (state[7 - k] ?? 0) ^ ((low >>> (8 * k)) & 0xff);
    state[3 - k] = (state[3 - k] ?? 0) ^ ((high >>> (8 * k)) & 0xff);
  }
}

/**
 * AES Key Wrap (RFC 3394) implemented in pure JS over the `@noble/ciphers`
 * AES block primitive. Used on every platform so wrapped keys are
 * byte-identical regardless of whether WebCrypto is present.
 */
export async function aesKwWrap(
  rawKeyBytes: Uint8Array,
  kekBytes: Uint8Array,
): Promise<Uint8Array> {
  assertAesKwKey(kekBytes);

  if (
    rawKeyBytes.length < 16 ||
    rawKeyBytes.length % AES_KW_BLOCK_BYTES !== 0
  ) {
    throw new Error(
      'aesKwWrap: key must be at least 16 bytes and a multiple of 8',
    );
  }

  const n = rawKeyBytes.length / AES_KW_BLOCK_BYTES;
  const xk = unsafe.expandKeyLE(kekBytes);

  const state = new Uint8Array(8 + rawKeyBytes.length);
  state.set(AES_KW_IV, 0);
  state.set(rawKeyBytes, 8);

  // Reusable 16-byte work block, byteOffset 0 so it is 4-byte aligned for the
  // underlying u32 reinterpretation used by encryptBlock.
  const block = new Uint8Array(16);
  for (let j = 0; j < 6; j++) {
    for (let i = 1; i <= n; i++) {
      block.set(state.subarray(0, 8), 0);
      block.set(state.subarray(8 + (i - 1) * 8, 8 + i * 8), 8);

      unsafe.encryptBlock(xk, block);
      state.set(block.subarray(0, 8), 0);
      xorAesKwCounter(state, n * j + i);
      state.set(block.subarray(8, 16), 8 + (i - 1) * 8);
    }
  }

  xk.fill(0);
  return state;
}

export async function aesKwUnwrap(
  wrappedKeyBytes: Uint8Array,
  kekBytes: Uint8Array,
): Promise<Uint8Array> {
  assertAesKwKey(kekBytes);

  if (
    wrappedKeyBytes.length < 24 ||
    wrappedKeyBytes.length % AES_KW_BLOCK_BYTES !== 0
  ) {
    throw new Error(
      'aesKwUnwrap: ciphertext must be at least 24 bytes and a multiple of 8',
    );
  }

  const n = wrappedKeyBytes.length / AES_KW_BLOCK_BYTES - 1;
  const xk = unsafe.expandKeyDecLE(kekBytes);

  const state = new Uint8Array(wrappedKeyBytes.length);
  state.set(wrappedKeyBytes);

  const block = new Uint8Array(16);
  for (let j = 5; j >= 0; j--) {
    for (let i = n; i >= 1; i--) {
      xorAesKwCounter(state, n * j + i);
      block.set(state.subarray(0, 8), 0);
      block.set(state.subarray(8 + (i - 1) * 8, 8 + i * 8), 8);

      unsafe.decryptBlock(xk, block);
      state.set(block.subarray(0, 8), 0);
      state.set(block.subarray(8, 16), 8 + (i - 1) * 8);
    }
  }

  xk.fill(0);

  let diff = 0;
  for (let i = 0; i < 8; i++) {
    diff |= (state[i] ?? 0) ^ (AES_KW_IV[i] ?? 0);
  }
  if (diff !== 0) {
    throw new Error('aesKwUnwrap: integrity check failed');
  }

  return state.subarray(8);
}
