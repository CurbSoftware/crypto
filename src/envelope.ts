export type EncryptionAlgorithm = 'AES-GCM-256' | 'XCHACHA20-POLY1305';
export type KeyDerivationAlgorithm = 'PBKDF2-SHA256' | 'ARGON2ID';
export type WrappedKeyAlgorithm = 'AES-KW-256';

export interface KdfDescriptor {
  algorithm: KeyDerivationAlgorithm;
  saltBase64: string;
  iterations?: number;
  memoryKb?: number;
  parallelism?: number;
  hashLength?: number;
}

export interface EncryptedEnvelopeV1 {
  version: 1;
  algorithm: 'AES-GCM-256';
  keyId: string;
  ivBase64: string;
  ciphertextBase64: string;
  authTagBase64?: string;
  aadBase64?: string;
  kdf?: KdfDescriptor;
}

export interface EncryptedEnvelopeV2 {
  version: 2;
  algorithm: 'XCHACHA20-POLY1305';
  keyId: string;
  nonceBase64: string;
  ciphertextBase64: string;
  authTagBase64: string;
  aadBase64?: string;
}

export type EncryptedEnvelope = EncryptedEnvelopeV1 | EncryptedEnvelopeV2;

export interface WrappedAccountKeyV1 {
  version: 1;
  algorithm: WrappedKeyAlgorithm;
  kdf: KdfDescriptor;
  wrappedKeyBase64: string;
  verifierEnvelope: EncryptedEnvelopeV1;
}

export interface DeviceKeyRecordV1 {
  version: 1;
  deviceId: string;
  publicKeyBase64: string;
  /** The device private key, encrypted with the account encryption key. */
  wrappedPrivateKey: EncryptedEnvelopeV1;
  createdAt: string;
}

export interface AccountIdentityV1 {
  version: 1;
  accountId: string;
  wrappedAek: WrappedAccountKeyV1;
  deviceKeys: DeviceKeyRecordV1[];
  /** Account-level X25519 identity public key. */
  identityPublicKeyBase64?: string;
  /** Account identity private key, AEK-encrypted (never stored in plaintext). */
  wrappedIdentityPrivateKey?: EncryptedEnvelopeV1;
  /** Ed25519 identity public key used to sign the X25519 public key. */
  identitySigningPublicKeyBase64?: string;
  /** Ed25519 private key, AEK-encrypted. */
  wrappedIdentitySigningPrivateKey?: EncryptedEnvelopeV1;
  /** Signature of the X25519 public key under the Ed25519 identity key. */
  identityPublicKeySignatureBase64?: string;
}

export interface EncryptedRecoveryBlobV1 {
  version: 1;
  account: AccountIdentityV1;
  createdAt: string;
}

export interface EntityKeyGrantV1 {
  version: 1;
  entityId: string;
  granteePublicKeyBase64: string;
  /** AES-KW wrapped entity key, keyed under the ECDH-derived KEK. */
  wrappedKeyBase64: string;
  createdAt: string;
  /** Transcript version for the ECDH wrap (`v1` = fixed info, `v2` = bound). */
  wrapVersion?: 1 | 2;
}

export function isEncryptedEnvelopeV2(
  envelope: EncryptedEnvelope,
): envelope is EncryptedEnvelopeV2 {
  return envelope.version === 2;
}
