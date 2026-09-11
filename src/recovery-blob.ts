import type {
  DeviceKeyRecordV1,
  EncryptedEnvelopeV1,
  EncryptedRecoveryBlobV1,
  WrappedAccountKeyV1,
} from './envelope';

export interface BuildRecoveryBlobInput {
  accountId: string;
  wrappedAek: WrappedAccountKeyV1;
  deviceKeys?: DeviceKeyRecordV1[];
  identityPublicKeyBase64?: string;
  wrappedIdentityPrivateKey?: EncryptedEnvelopeV1;
  identitySigningPublicKeyBase64?: string;
  wrappedIdentitySigningPrivateKey?: EncryptedEnvelopeV1;
  identityPublicKeySignatureBase64?: string;
  createdAt?: string;
}

/**
 * Assemble the zero-knowledge recovery material for an account. The wrapped
 * AEK plus the wrapped device keys are the only thing needed to restore the
 * account from the master password; no plaintext key material is stored.
 */
export function buildRecoveryBlob(
  input: BuildRecoveryBlobInput,
): EncryptedRecoveryBlobV1 {
  return {
    version: 1,
    createdAt: input.createdAt ?? new Date().toISOString(),
    account: {
      version: 1,
      accountId: input.accountId,
      wrappedAek: input.wrappedAek,
      deviceKeys: input.deviceKeys ?? [],
      ...(input.identityPublicKeyBase64
        ? { identityPublicKeyBase64: input.identityPublicKeyBase64 }
        : {}),
      ...(input.wrappedIdentityPrivateKey
        ? { wrappedIdentityPrivateKey: input.wrappedIdentityPrivateKey }
        : {}),
      ...(input.identitySigningPublicKeyBase64
        ? {
            identitySigningPublicKeyBase64:
              input.identitySigningPublicKeyBase64,
          }
        : {}),
      ...(input.wrappedIdentitySigningPrivateKey
        ? {
            wrappedIdentitySigningPrivateKey:
              input.wrappedIdentitySigningPrivateKey,
          }
        : {}),
      ...(input.identityPublicKeySignatureBase64
        ? {
            identityPublicKeySignatureBase64:
              input.identityPublicKeySignatureBase64,
          }
        : {}),
    },
  };
}

export function serializeRecoveryBlob(blob: EncryptedRecoveryBlobV1): string {
  return JSON.stringify(blob);
}

export function parseRecoveryBlob(json: string): EncryptedRecoveryBlobV1 {
  const parsed = JSON.parse(json) as EncryptedRecoveryBlobV1;

  if (!parsed || parsed.version !== 1) {
    throw new Error('parseRecoveryBlob: unsupported recovery blob version');
  }

  if (!parsed.account || parsed.account.version !== 1) {
    throw new Error('parseRecoveryBlob: malformed account identity');
  }

  if (
    typeof parsed.account.accountId !== 'string' ||
    !parsed.account.accountId
  ) {
    throw new Error('parseRecoveryBlob: missing account id');
  }

  const { wrappedAek } = parsed.account;
  if (!wrappedAek || wrappedAek.version !== 1) {
    throw new Error('parseRecoveryBlob: malformed wrapped AEK');
  }

  if (
    !wrappedAek.kdf ||
    typeof wrappedAek.kdf.saltBase64 !== 'string' ||
    !wrappedAek.kdf.saltBase64 ||
    typeof wrappedAek.wrappedKeyBase64 !== 'string' ||
    !wrappedAek.wrappedKeyBase64 ||
    !wrappedAek.verifierEnvelope ||
    !wrappedAek.verifierEnvelope.ivBase64 ||
    !wrappedAek.verifierEnvelope.ciphertextBase64
  ) {
    throw new Error('parseRecoveryBlob: malformed wrapped AEK fields');
  }

  if (!Array.isArray(parsed.account.deviceKeys)) {
    throw new Error('parseRecoveryBlob: malformed device keys');
  }

  return parsed;
}
