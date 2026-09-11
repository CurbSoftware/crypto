import type {
  EncryptedEnvelopeV1,
  KdfDescriptor,
  WrappedAccountKeyV1,
} from './envelope';

export type EncryptionKeyScope = 'account' | 'group' | 'local_device';

/**
 * Product-agnostic key descriptor. Hosts may attach their own account/app ids;
 * this package does not import application registries.
 */
export interface EncryptionKeyDescriptor {
  id: string;
  accountId: string;
  scope: EncryptionKeyScope;
  appId?: string | null;
  entityId?: string | null;
  keyVersion: number;
  algorithm: 'AES-GCM-256';
  kdf: KdfDescriptor | null;
  createdBy?: string | null;
  createdAt: string;
  updatedAt: string;
  rotatedAt?: string | null;
  revokedAt?: string | null;
}

export interface UnlockRequirement {
  scope: EncryptionKeyScope;
  requiresPassword: boolean;
  supportsBiometricUnlock: boolean;
}

export interface KeyGrantRecord {
  id: string;
  accountId: string;
  keyId: string;
  granteeUserId: string;
  deviceId?: string | null;
  wrappedKey: WrappedAccountKeyV1;
  verifier: EncryptedEnvelopeV1;
  createdBy?: string | null;
  revokedAt?: string | null;
  createdAt: string;
  updatedAt: string;
}
