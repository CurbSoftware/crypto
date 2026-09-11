import { aesGcmDecrypt, aesGcmEncrypt } from './aes';
import type {
  EncryptedEnvelope,
  EncryptedEnvelopeV1,
  EncryptedEnvelopeV2,
} from './envelope';
import { isEncryptedEnvelopeV2 } from './envelope';
import { xchachaDecrypt, xchachaEncrypt } from './xchacha';

export type ProtocolVersion = 1 | 2;

export async function encryptPayload(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  options: { keyId: string; aad?: Uint8Array; version?: ProtocolVersion },
): Promise<EncryptedEnvelope> {
  const version = options.version ?? 1;
  if (version === 1) {
    return aesGcmEncrypt(plaintext, keyBytes, {
      keyId: options.keyId,
      aad: options.aad,
    });
  }
  return xchachaEncrypt(plaintext, keyBytes, {
    keyId: options.keyId,
    aad: options.aad,
  });
}

export async function decryptPayload(
  envelope: EncryptedEnvelope,
  keyBytes: Uint8Array,
): Promise<Uint8Array> {
  if (isEncryptedEnvelopeV2(envelope)) {
    return xchachaDecrypt(envelope, keyBytes);
  }
  return aesGcmDecrypt(envelope, keyBytes);
}

export function parseEncryptedEnvelope(raw: string): EncryptedEnvelope {
  const parsed = JSON.parse(raw) as Partial<EncryptedEnvelope>;
  if (parsed.version === 2) {
    return parsed as EncryptedEnvelopeV2;
  }
  if (parsed.version === 1) {
    return parsed as EncryptedEnvelopeV1;
  }
  throw new Error('Unsupported encrypted envelope version');
}
