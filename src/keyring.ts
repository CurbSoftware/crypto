import { ed25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  generateAek,
  unwrapAek,
  verifyAekVerifier,
  wrapAekWithMasterKey,
} from './aek';
import { aesGcmDecrypt, aesGcmEncrypt, randomBytes } from './aes';
import {
  type Argon2Params,
  DEFAULT_ARGON2_PARAMS,
  assertArgon2UnlockParams,
  deriveUnlockMasterKey,
  generateSalt,
} from './argon2';
import { base64ToBytes, bytesToBase64 } from './base64';
import {
  type DeviceKeypair,
  generateDeviceKeypair,
  importDevicePrivateKey,
  publicKeyToBase64,
} from './device-keys';
import type {
  AccountIdentityDocument,
  GeneratedAccountIdentity,
} from './identity';
import {
  generateAccountIdentity,
  verifyAccountIdentityDocument,
  wipeIdentitySecrets,
} from './identity';
import type {
  DeviceKeyRecordV1,
  EncryptedEnvelopeV1,
  EncryptedRecoveryBlobV1,
  KdfDescriptor,
  WrappedAccountKeyV1,
} from './envelope';
import { hmacLookup as hmacLookupFromAek } from './lookup';
import { asAccountKey, type AccountKey } from './opaque';
import { buildRecoveryBlob } from './recovery-blob';
import { bytesToHex, wipe } from './wipe';

const ENTITY_ENVELOPE_KEY_ID_INFO = new TextEncoder().encode(
  'curbapps/entity-envelope-key-id/v1',
);
const ENTITY_ENVELOPE_AAD_PREFIX = 'curbapps/entity-envelope/v1\0';
const IDENTITY_PRIVATE_KEY_ID = 'account-identity-private-key';
const IDENTITY_SIGNING_PRIVATE_KEY_ID = 'account-identity-signing-private-key';

function entityEnvelopeKeyId(aek: Uint8Array): string {
  const identity = hkdf(
    sha256,
    aek,
    undefined,
    ENTITY_ENVELOPE_KEY_ID_INFO,
    16,
  );
  const hex = bytesToHex(identity);
  wipe(identity);
  return `aek_v1_${hex}`;
}

function entityEnvelopeAad(keyId: string): Uint8Array {
  return new TextEncoder().encode(`${ENTITY_ENVELOPE_AAD_PREFIX}${keyId}`);
}

function hasOnlyEnvelopeKeys(
  envelope: EncryptedEnvelopeV1,
  allowedKeys: readonly string[],
): boolean {
  const allowed = new Set(allowedKeys);
  return Object.keys(envelope).every((key) => allowed.has(key));
}

function isCanonicalBase64(
  value: unknown,
  expectedLength?: number,
  allowEmpty = false,
): boolean {
  if (typeof value !== 'string') return false;
  try {
    const bytes = base64ToBytes(value);
    return (
      (allowEmpty || bytes.length > 0) &&
      (expectedLength === undefined || bytes.length === expectedLength) &&
      bytesToBase64(bytes) === value
    );
  } catch {
    return false;
  }
}

function hasBoundedCipherShape(envelope: EncryptedEnvelopeV1): boolean {
  return (
    envelope.version === 1 &&
    envelope.algorithm === 'AES-GCM-256' &&
    envelope.kdf === undefined &&
    isCanonicalBase64(envelope.ivBase64, 12) &&
    isCanonicalBase64(envelope.ciphertextBase64, undefined, true) &&
    isCanonicalBase64(envelope.authTagBase64, 16)
  );
}

function isCurrentEntityEnvelope(
  envelope: EncryptedEnvelopeV1,
  expectedKeyId: string,
): boolean {
  return (
    hasBoundedCipherShape(envelope) &&
    envelope.keyId === expectedKeyId &&
    envelope.aadBase64 === bytesToBase64(entityEnvelopeAad(expectedKeyId)) &&
    hasOnlyEnvelopeKeys(envelope, [
      'version',
      'algorithm',
      'keyId',
      'ivBase64',
      'ciphertextBase64',
      'authTagBase64',
      'aadBase64',
    ])
  );
}

function isBoundedLegacyEntityEnvelope(envelope: EncryptedEnvelopeV1): boolean {
  return (
    hasBoundedCipherShape(envelope) &&
    envelope.keyId === '' &&
    envelope.aadBase64 === undefined &&
    hasOnlyEnvelopeKeys(envelope, [
      'version',
      'algorithm',
      'keyId',
      'ivBase64',
      'ciphertextBase64',
      'authTagBase64',
    ])
  );
}

/**
 * Decrypt an entity envelope with a raw AEK.
 *
 * Current envelopes must name the exact AEK-derived identity and authenticate
 * that identity as AAD. The only legacy exception is the frozen defect-era
 * shape that had an empty keyId, a separate authentication tag, and no AAD.
 * AES-GCM authentication still has to succeed before plaintext is returned.
 */
export async function decryptKeyringEntityEnvelope(
  envelope: EncryptedEnvelopeV1,
  aek: Uint8Array,
): Promise<Uint8Array> {
  const expectedKeyId = entityEnvelopeKeyId(aek);
  if (isCurrentEntityEnvelope(envelope, expectedKeyId)) {
    return aesGcmDecrypt(envelope, aek);
  }

  if (isBoundedLegacyEntityEnvelope(envelope)) {
    return aesGcmDecrypt(envelope, aek);
  }

  throw new Error('Keyring entity envelope does not match the active key');
}

export interface KeyringMaterial {
  wrappedAek: WrappedAccountKeyV1;
  recoveryBlob: EncryptedRecoveryBlobV1;
}

export interface CreateKeyringOptions {
  password?: string;
  accountId?: string;
  argon2Params?: Partial<Argon2Params>;
}

export const MIN_MASTER_PASSWORD_LENGTH = 12;

export function assertValidNewMasterPassword(password: string): void {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new Error(
      `Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`,
    );
  }
}

function argon2KdfDescriptor(
  salt: Uint8Array,
  params: Argon2Params,
): KdfDescriptor {
  return {
    algorithm: 'ARGON2ID',
    saltBase64: bytesToBase64(salt),
    memoryKb: params.memoryKb,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
  };
}

function kdfToArgon2Params(kdf: KdfDescriptor): Argon2Params {
  return {
    memoryKb: kdf.memoryKb ?? DEFAULT_ARGON2_PARAMS.memoryKb,
    iterations: kdf.iterations ?? DEFAULT_ARGON2_PARAMS.iterations,
    parallelism: kdf.parallelism ?? DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: kdf.hashLength ?? DEFAULT_ARGON2_PARAMS.hashLength,
  };
}

function randomId(prefix: string): string {
  return `${prefix}${bytesToBase64(randomBytes(9))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')}`;
}

function resolveArgon2Params(partial?: Partial<Argon2Params>): Argon2Params {
  return assertArgon2UnlockParams({
    memoryKb: partial?.memoryKb ?? DEFAULT_ARGON2_PARAMS.memoryKb,
    iterations: partial?.iterations ?? DEFAULT_ARGON2_PARAMS.iterations,
    parallelism: partial?.parallelism ?? DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: partial?.hashLength ?? DEFAULT_ARGON2_PARAMS.hashLength,
  });
}

/**
 * In-memory keyring implementing zero-knowledge account encryption.
 *
 * The AEK encrypts entities and device private keys; the AEK itself is wrapped
 * under a master key derived from the user's password via Argon2id. Plaintext
 * key material lives only in memory and is cleared on `lock()`. Persistence of
 * an auto-unlock AEK is the host's job via `SecureAekStore`.
 */
export class Keyring {
  private aek: AccountKey | null = null;
  private masterKey: Uint8Array | null = null;
  private material: KeyringMaterial | null = null;
  private deviceKeyRecords: DeviceKeyRecordV1[] = [];
  private identityPublicKeyBase64 = '';
  private wrappedIdentityPrivateKey: EncryptedEnvelopeV1 | null = null;
  private identitySigningPublicKeyBase64 = '';
  private wrappedIdentitySigningPrivateKey: EncryptedEnvelopeV1 | null = null;
  private identityPublicKeySignatureBase64 = '';
  private accountId = '';
  private argon2Params: Argon2Params = DEFAULT_ARGON2_PARAMS;

  /** Create a fresh, already-unlocked keyring. */
  static async createKeyring(
    options: CreateKeyringOptions = {},
  ): Promise<Keyring> {
    if (options.password !== undefined) {
      assertValidNewMasterPassword(options.password);
    }

    const keyring = new Keyring();
    keyring.accountId = options.accountId ?? randomId('acc_');
    keyring.argon2Params = resolveArgon2Params(options.argon2Params);

    keyring.aek = await generateAek();

    const keypair = await keyring.generateDeviceKeyRecord();
    keyring.deviceKeyRecords = [keypair];

    const identity = await generateAccountIdentity();
    await keyring.adoptGeneratedIdentity(identity);
    wipeIdentitySecrets(identity);

    if (options.password !== undefined) {
      await keyring.wrapWithPassword(options.password);
    }

    return keyring;
  }

  private async adoptGeneratedIdentity(
    identity: GeneratedAccountIdentity,
  ): Promise<void> {
    const aek = this.requireAek();
    this.identityPublicKeyBase64 = identity.document.x25519PublicKeyBase64;
    this.identitySigningPublicKeyBase64 =
      identity.document.ed25519PublicKeyBase64;
    this.identityPublicKeySignatureBase64 = identity.document.signatureBase64;
    this.wrappedIdentityPrivateKey = await aesGcmEncrypt(
      identity.x25519.privateKey,
      aek,
      { keyId: IDENTITY_PRIVATE_KEY_ID },
    );
    this.wrappedIdentitySigningPrivateKey = await aesGcmEncrypt(
      identity.ed25519.privateKey,
      aek,
      { keyId: IDENTITY_SIGNING_PRIVATE_KEY_ID },
    );
  }

  private async wrapWithPassword(password: string): Promise<void> {
    const salt = generateSalt();
    this.masterKey = await deriveUnlockMasterKey(
      password,
      salt,
      this.argon2Params,
    );

    const wrappedAek = await wrapAekWithMasterKey(
      this.requireAek(),
      this.masterKey,
      argon2KdfDescriptor(salt, this.argon2Params),
    );

    this.material = {
      wrappedAek,
      recoveryBlob: this.buildCurrentRecoveryBlob(wrappedAek),
    };
  }

  private buildCurrentRecoveryBlob(
    wrappedAek: WrappedAccountKeyV1,
  ): EncryptedRecoveryBlobV1 {
    return buildRecoveryBlob({
      accountId: this.accountId,
      wrappedAek,
      deviceKeys: this.deviceKeyRecords,
      identityPublicKeyBase64: this.identityPublicKeyBase64 || undefined,
      wrappedIdentityPrivateKey: this.wrappedIdentityPrivateKey ?? undefined,
      identitySigningPublicKeyBase64:
        this.identitySigningPublicKeyBase64 || undefined,
      wrappedIdentitySigningPrivateKey:
        this.wrappedIdentitySigningPrivateKey ?? undefined,
      identityPublicKeySignatureBase64:
        this.identityPublicKeySignatureBase64 || undefined,
    });
  }

  private restoreIdentityFromMaterial(material: KeyringMaterial): void {
    this.identityPublicKeyBase64 =
      material.recoveryBlob.account.identityPublicKeyBase64 ?? '';
    this.wrappedIdentityPrivateKey =
      material.recoveryBlob.account.wrappedIdentityPrivateKey ?? null;
    this.identitySigningPublicKeyBase64 =
      material.recoveryBlob.account.identitySigningPublicKeyBase64 ?? '';
    this.wrappedIdentitySigningPrivateKey =
      material.recoveryBlob.account.wrappedIdentitySigningPrivateKey ?? null;
    this.identityPublicKeySignatureBase64 =
      material.recoveryBlob.account.identityPublicKeySignatureBase64 ?? '';
  }

  /**
   * Bind claimed identity public keys to the AEK by opening the wrapped
   * private halves. A swapped recovery-blob identity that is internally
   * signed still fails here unless it was encrypted under this AEK.
   */
  private async assertIdentityMatchesAek(): Promise<void> {
    const aek = this.requireAek();

    if (this.identityPublicKeyBase64 && !this.wrappedIdentityPrivateKey) {
      throw new Error(
        'Keyring.unlock: identity public key is missing its AEK wrap',
      );
    }
    if (
      this.identitySigningPublicKeyBase64 &&
      !this.wrappedIdentitySigningPrivateKey
    ) {
      throw new Error(
        'Keyring.unlock: signing public key is missing its AEK wrap',
      );
    }

    if (this.wrappedIdentityPrivateKey) {
      const privateKey = await aesGcmDecrypt(
        this.wrappedIdentityPrivateKey,
        aek,
      );
      try {
        const derived = publicKeyToBase64(
          importDevicePrivateKey(privateKey).publicKey,
        );
        if (
          this.identityPublicKeyBase64 &&
          derived !== this.identityPublicKeyBase64
        ) {
          throw new Error(
            'Keyring.unlock: identity public key does not match the AEK-wrapped private key',
          );
        }
        this.identityPublicKeyBase64 = derived;
      } finally {
        wipe(privateKey);
      }
    }

    if (this.wrappedIdentitySigningPrivateKey) {
      const privateKey = await aesGcmDecrypt(
        this.wrappedIdentitySigningPrivateKey,
        aek,
      );
      try {
        const seed =
          privateKey.length === 64 ? privateKey.subarray(0, 32) : privateKey;
        const derived = bytesToBase64(ed25519.getPublicKey(seed));
        if (
          this.identitySigningPublicKeyBase64 &&
          derived !== this.identitySigningPublicKeyBase64
        ) {
          throw new Error(
            'Keyring.unlock: signing public key does not match the AEK-wrapped private key',
          );
        }
        this.identitySigningPublicKeyBase64 = derived;
      } finally {
        wipe(privateKey);
      }
    }

    const document = this.getIdentityDocument();
    if (document && !verifyAccountIdentityDocument(document)) {
      throw new Error('Keyring.unlock: identity signature is invalid');
    }
  }

  private async generateDeviceKeyRecord(): Promise<DeviceKeyRecordV1> {
    const keypair: DeviceKeypair = await generateDeviceKeypair();
    const wrappedPrivateKey = await aesGcmEncrypt(
      keypair.privateKey,
      this.requireAek(),
      {
        keyId: 'device-private-key',
      },
    );
    wipe(keypair.privateKey);

    return {
      version: 1,
      deviceId: randomId('dev_'),
      publicKeyBase64: publicKeyToBase64(keypair.publicKey),
      wrappedPrivateKey,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Unlock from persisted material using the master password. Throws when the
   * password cannot reproduce the AEK (failed verifier or integrity check).
   */
  async unlock(password: string, material: KeyringMaterial): Promise<void> {
    const params = assertArgon2UnlockParams(
      kdfToArgon2Params(material.wrappedAek.kdf),
    );
    const salt = base64ToBytes(material.wrappedAek.kdf.saltBase64);
    const masterKey = await deriveUnlockMasterKey(password, salt, params);

    let aek: AccountKey;
    try {
      aek = await unwrapAek(material.wrappedAek, masterKey);
    } catch (err) {
      wipe(masterKey);
      throw err;
    }

    const ok = await verifyAekVerifier(
      material.wrappedAek.verifierEnvelope,
      aek,
      material.wrappedAek.kdf,
    );
    if (!ok) {
      wipe(masterKey);
      wipe(aek);
      throw new Error('Keyring.unlock: incorrect password');
    }

    this.lock();
    this.aek = aek;
    this.masterKey = masterKey;
    this.material = material;
    this.accountId = material.recoveryBlob.account.accountId;
    this.deviceKeyRecords = material.recoveryBlob.account.deviceKeys;
    this.restoreIdentityFromMaterial(material);
    this.argon2Params = params;
    try {
      await this.assertIdentityMatchesAek();
    } catch (err) {
      this.lock();
      throw err;
    }
  }

  /** Unlock directly from a raw AEK, e.g. from a biometric vault. */
  async autoUnlock(rawAek: Uint8Array): Promise<void> {
    this.lock();
    this.aek = asAccountKey(new Uint8Array(rawAek));
    this.masterKey = null;
    this.material = null;
  }

  /**
   * Unlock from a raw AEK while retaining the persisted material (biometric
   * unlock). Unlike `autoUnlock`, the recovery blob and device keys stay
   * available so sync and password change keep working.
   */
  async unlockWithAek(
    rawAek: Uint8Array,
    material: KeyringMaterial,
  ): Promise<void> {
    const aek = asAccountKey(new Uint8Array(rawAek));
    const ok = await verifyAekVerifier(
      material.wrappedAek.verifierEnvelope,
      aek,
      material.wrappedAek.kdf,
    );
    if (!ok) {
      wipe(aek);
      throw new Error('Keyring.unlockWithAek: AEK does not match material');
    }

    this.lock();
    this.aek = aek;
    this.masterKey = null;
    this.material = material;
    this.accountId = material.recoveryBlob.account.accountId;
    this.deviceKeyRecords = material.recoveryBlob.account.deviceKeys;
    this.restoreIdentityFromMaterial(material);
    this.argon2Params = kdfToArgon2Params(material.wrappedAek.kdf);
    try {
      await this.assertIdentityMatchesAek();
    } catch (err) {
      this.lock();
      throw err;
    }
  }

  /** Export a copy of the raw AEK for a host `SecureAekStore`. Throws if locked. */
  exportAek(): AccountKey {
    return asAccountKey(new Uint8Array(this.requireAek()));
  }

  /**
   * Re-wrap the AEK under a new password. The old password is always
   * re-verified (even when the keyring is already unlocked) and the same AEK is
   * preserved, so previously encrypted entities remain decryptable.
   */
  async changeMasterPassword(
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    assertValidNewMasterPassword(newPassword);

    if (!this.material) {
      throw new Error('Keyring.changeMasterPassword: no wrapped material');
    }

    const oldParams = assertArgon2UnlockParams(
      kdfToArgon2Params(this.material.wrappedAek.kdf),
    );
    const oldSalt = base64ToBytes(this.material.wrappedAek.kdf.saltBase64);
    const oldMasterKey = await deriveUnlockMasterKey(
      oldPassword,
      oldSalt,
      oldParams,
    );

    let aek: AccountKey;
    try {
      aek = await unwrapAek(this.material.wrappedAek, oldMasterKey);
    } catch (err) {
      wipe(oldMasterKey);
      throw err;
    }

    const ok = await verifyAekVerifier(
      this.material.wrappedAek.verifierEnvelope,
      aek,
      this.material.wrappedAek.kdf,
    );
    if (!ok) {
      wipe(oldMasterKey);
      wipe(aek);
      throw new Error('Keyring.changeMasterPassword: incorrect old password');
    }

    const salt = generateSalt();
    const newMasterKey = await deriveUnlockMasterKey(
      newPassword,
      salt,
      this.argon2Params,
    );
    const wrappedAek = await wrapAekWithMasterKey(
      aek,
      newMasterKey,
      argon2KdfDescriptor(salt, this.argon2Params),
    );

    wipe(oldMasterKey);

    this.lock();
    this.aek = aek;
    this.masterKey = newMasterKey;
    this.material = {
      wrappedAek,
      recoveryBlob: this.buildCurrentRecoveryBlob(wrappedAek),
    };
  }

  lock(): void {
    wipe(this.aek);
    wipe(this.masterKey);
    this.aek = null;
    this.masterKey = null;
  }

  isUnlocked(): boolean {
    return this.aek !== null;
  }

  async encryptEntity(plaintext: Uint8Array): Promise<EncryptedEnvelopeV1> {
    const aek = this.requireAek();
    const keyId = entityEnvelopeKeyId(aek);
    return aesGcmEncrypt(plaintext, aek, {
      keyId,
      aad: entityEnvelopeAad(keyId),
    });
  }

  async decryptEntity(ciphertext: EncryptedEnvelopeV1): Promise<Uint8Array> {
    return decryptKeyringEntityEnvelope(ciphertext, this.requireAek());
  }

  /**
   * Deterministic HMAC-SHA256 lookup key. Used for meta-link `value_hash` so
   * the server stores a keyed fingerprint, not a rainbow-tableable URL hash.
   */
  hmacLookup(message: string): string {
    return hmacLookupFromAek(this.requireAek(), message);
  }

  getRecoveryBlob(): EncryptedRecoveryBlobV1 | null {
    return this.material?.recoveryBlob ?? null;
  }

  /** Expose the persisted material for storage and testing. */
  getMaterial(): KeyringMaterial | null {
    return this.material;
  }

  /** The account's X25519 identity public key (base64), or null if none. */
  getIdentityPublicKey(): string | null {
    return this.identityPublicKeyBase64 || null;
  }

  /** The AEK-encrypted account identity private key, or null if none. */
  getWrappedIdentityPrivateKey(): EncryptedEnvelopeV1 | null {
    return this.wrappedIdentityPrivateKey;
  }

  getIdentityDocument(): AccountIdentityDocument | null {
    if (
      !this.identityPublicKeyBase64 ||
      !this.identitySigningPublicKeyBase64 ||
      !this.identityPublicKeySignatureBase64
    ) {
      return null;
    }
    return {
      version: 1,
      x25519PublicKeyBase64: this.identityPublicKeyBase64,
      ed25519PublicKeyBase64: this.identitySigningPublicKeyBase64,
      signatureBase64: this.identityPublicKeySignatureBase64,
    };
  }

  private requireAek(): AccountKey {
    if (!this.aek) {
      throw new Error('Keyring is locked');
    }
    return this.aek;
  }
}
