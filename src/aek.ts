import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesKwUnwrap,
  aesKwWrap,
  randomBytes,
} from './aes';
import {
  DEFAULT_ARGON2_PARAMS,
  assertArgon2UnlockParams,
  generateSalt,
} from './argon2';
import { base64ToBytes, bytesToBase64 } from './base64';
import type {
  EncryptedEnvelopeV1,
  KdfDescriptor,
  WrappedAccountKeyV1,
} from './envelope';
import { asAccountKey, type AccountKey } from './opaque';
import { constantTimeEqual, wipe } from './wipe';

const AEK_BYTES = 32;
const VERIFIER_KEY_ID = 'aek-verifier';

export const AEK_VERIFIER_PLAINTEXT = 'CURBAPPS_AEK_V1';

/** Generate a fresh 32-byte Account Encryption Key (AEK). */
export async function generateAek(): Promise<AccountKey> {
  return asAccountKey(randomBytes(AEK_BYTES));
}

export function kdfVerifierAad(kdf: KdfDescriptor): Uint8Array {
  return new TextEncoder().encode(
    `curbapps/aek-verifier/v1\0${kdf.algorithm}\0${kdf.memoryKb ?? ''}\0${kdf.iterations ?? ''}\0${kdf.parallelism ?? ''}\0${kdf.hashLength ?? ''}\0${kdf.saltBase64}`,
  );
}

function defaultKdf(salt: Uint8Array): KdfDescriptor {
  return {
    algorithm: 'ARGON2ID',
    saltBase64: bytesToBase64(salt),
    iterations: DEFAULT_ARGON2_PARAMS.iterations,
    memoryKb: DEFAULT_ARGON2_PARAMS.memoryKb,
    parallelism: DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: DEFAULT_ARGON2_PARAMS.hashLength,
  };
}

/**
 * Wrap an AEK under a derived master key using AES-KW.
 *
 * The KDF descriptor records how the master key was derived so it can be
 * reproduced on unlock. When omitted, a fresh Argon2id descriptor is generated
 * (useful for standalone wrapping); callers that already hold the salt should
 * pass `kdf` explicitly.
 */
export async function wrapAekWithMasterKey(
  aek: Uint8Array,
  masterKey: Uint8Array,
  kdf?: KdfDescriptor,
): Promise<WrappedAccountKeyV1> {
  const descriptor = kdf ?? defaultKdf(generateSalt());
  if (descriptor.algorithm === 'ARGON2ID') {
    assertArgon2UnlockParams({
      memoryKb: descriptor.memoryKb ?? DEFAULT_ARGON2_PARAMS.memoryKb,
      iterations: descriptor.iterations ?? DEFAULT_ARGON2_PARAMS.iterations,
      parallelism: descriptor.parallelism ?? DEFAULT_ARGON2_PARAMS.parallelism,
      hashLength: descriptor.hashLength ?? DEFAULT_ARGON2_PARAMS.hashLength,
    });
  }
  const wrappedKey = await aesKwWrap(aek, masterKey);

  return {
    version: 1,
    algorithm: 'AES-KW-256',
    kdf: descriptor,
    wrappedKeyBase64: bytesToBase64(wrappedKey),
    verifierEnvelope: await buildAekVerifier(aek, descriptor),
  };
}

export async function unwrapAek(
  wrapped: WrappedAccountKeyV1,
  masterKey: Uint8Array,
): Promise<AccountKey> {
  return asAccountKey(
    await aesKwUnwrap(base64ToBytes(wrapped.wrappedKeyBase64), masterKey),
  );
}

/** Encrypt a known constant with the AEK to prove possession of it. */
export async function buildAekVerifier(
  aek: Uint8Array,
  kdf?: KdfDescriptor,
): Promise<EncryptedEnvelopeV1> {
  const plaintext = new TextEncoder().encode(AEK_VERIFIER_PLAINTEXT);
  return aesGcmEncrypt(plaintext, aek, {
    keyId: VERIFIER_KEY_ID,
    aad: kdf ? kdfVerifierAad(kdf) : undefined,
  });
}

function verifierMatchesKdf(
  verifier: EncryptedEnvelopeV1,
  kdf: KdfDescriptor,
): boolean {
  if (!verifier.aadBase64) return true;
  return verifier.aadBase64 === bytesToBase64(kdfVerifierAad(kdf));
}

/** Return `true` when `aek` is the key that produced `verifier`. */
export async function verifyAekVerifier(
  verifier: EncryptedEnvelopeV1,
  aek: Uint8Array,
  kdf?: KdfDescriptor,
): Promise<boolean> {
  try {
    if (kdf && !verifierMatchesKdf(verifier, kdf)) {
      return false;
    }
    const plaintext = await aesGcmDecrypt(verifier, aek);
    const expected = new TextEncoder().encode(AEK_VERIFIER_PLAINTEXT);
    const ok = constantTimeEqual(plaintext, expected);
    wipe(plaintext);
    return ok;
  } catch {
    return false;
  }
}
