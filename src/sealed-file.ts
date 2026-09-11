import { aesGcmDecrypt, aesGcmEncrypt, randomBytes } from './aes';
import {
  type Argon2Params,
  DEFAULT_ARGON2_PARAMS,
  deriveMasterKey,
  generateSalt,
} from './argon2';
import { base64ToBytes, bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV1 } from './envelope';
import { constantTimeEqual, wipe } from './wipe';

export interface SealedFileKdfHeader {
  alg: 'argon2id';
  salt: string;
  t: number;
  m: number;
  p: number;
}

export interface SealedFileV1 {
  v: 1;
  kdf: SealedFileKdfHeader;
  enc: EncryptedEnvelopeV1;
}

export function buildSealedFileKdfHeader(
  salt: Uint8Array = generateSalt(),
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): SealedFileKdfHeader {
  return {
    alg: 'argon2id',
    salt: bytesToBase64(salt),
    t: params.iterations,
    m: params.memoryKb,
    p: params.parallelism,
  };
}

export function parseSealedFileKdfHeader(json: string): SealedFileKdfHeader {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new Error('sealed-file: kdf header is not valid JSON');
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('sealed-file: kdf header is not an object');
  }
  const header = raw as Record<string, unknown>;
  const { t, m, p } = header;
  if (
    header.alg !== 'argon2id' ||
    typeof header.salt !== 'string' ||
    typeof t !== 'number' ||
    typeof m !== 'number' ||
    typeof p !== 'number'
  ) {
    throw new Error('sealed-file: malformed kdf header fields');
  }
  return { alg: 'argon2id', salt: header.salt, t, m, p };
}

export async function deriveSealedFileKey(
  passphrase: string,
  header: SealedFileKdfHeader,
  override?: Partial<Argon2Params>,
): Promise<Uint8Array> {
  return deriveMasterKey(passphrase, base64ToBytes(header.salt), {
    memoryKb: header.m,
    iterations: header.t,
    parallelism: header.p,
    ...override,
  });
}

export async function sealPassphraseFile(
  key: Uint8Array,
  plaintext: string,
  kdf: SealedFileKdfHeader,
  keyId = 'sealed-file',
): Promise<string> {
  const sealed: SealedFileV1 = {
    v: 1,
    kdf,
    enc: await aesGcmEncrypt(new TextEncoder().encode(plaintext), key, {
      keyId,
    }),
  };
  return JSON.stringify(sealed);
}

export async function openPassphraseFile(
  key: Uint8Array,
  sealedJson: string,
): Promise<string> {
  const sealed = JSON.parse(sealedJson) as SealedFileV1;
  if (sealed.v !== 1 || !sealed.enc?.ciphertextBase64) {
    throw new Error('sealed-file: unsupported sealed file version');
  }
  const bytes = await aesGcmDecrypt(sealed.enc, key);
  return new TextDecoder().decode(bytes);
}

export async function buildPassphraseVerifier(
  key: Uint8Array,
  plaintext: string,
  keyId = 'sealed-file-verifier',
): Promise<EncryptedEnvelopeV1> {
  return aesGcmEncrypt(new TextEncoder().encode(plaintext), key, { keyId });
}

export async function verifyPassphraseVerifier(
  verifier: EncryptedEnvelopeV1,
  key: Uint8Array,
  plaintext: string,
): Promise<boolean> {
  try {
    const opened = await aesGcmDecrypt(verifier, key);
    const expected = new TextEncoder().encode(plaintext);
    const ok = constantTimeEqual(opened, expected);
    wipe(opened);
    return ok;
  } catch {
    return false;
  }
}

export function generateSealedFileKey(): Uint8Array {
  return randomBytes(32);
}
