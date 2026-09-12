import { describe, expect, it } from 'vitest';

import { generateAek, wrapAekWithMasterKey } from '../src/aek';
import { aesGcmEncrypt } from '../src/aes';
import {
  DEFAULT_ARGON2_PARAMS,
  deriveMasterKey,
  generateSalt,
} from '../src/argon2';
import { bytesToBase64 } from '../src/base64';
import { Keyring, MIN_MASTER_PASSWORD_LENGTH } from '../src/keyring';
import { buildRecoveryBlob } from '../src/recovery-blob';

const encode = (value: string) => new TextEncoder().encode(value);
const PASSWORD = 'correct-horse-battery';
const OLD_PASSWORD = 'old-password-value';
const NEW_PASSWORD = 'new-password-value';

describe('keyring', () => {
  it('creates an unlocked keyring with password material', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });

    expect(keyring.isUnlocked()).toBe(true);
    expect(keyring.getMaterial()).not.toBeNull();
    expect(keyring.getRecoveryBlob()).not.toBeNull();
    expect(keyring.getRecoveryBlob()?.account.deviceKeys).toHaveLength(1);
  });

  it('creates an unlocked keyring without a password', async () => {
    const keyring = await Keyring.createKeyring();

    expect(keyring.isUnlocked()).toBe(true);
    expect(keyring.getMaterial()).toBeNull();
    expect(keyring.getRecoveryBlob()).toBeNull();
  });

  it('rejects weak passwords for new keyrings', async () => {
    await expect(
      Keyring.createKeyring({
        password: 'x'.repeat(MIN_MASTER_PASSWORD_LENGTH - 1),
      }),
    ).rejects.toThrow(`at least ${MIN_MASTER_PASSWORD_LENGTH} characters`);
  });

  it('generates and persists an account identity keypair', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });

    const publicKey = keyring.getIdentityPublicKey();
    const wrapped = keyring.getWrappedIdentityPrivateKey();

    expect(publicKey).not.toBeNull();
    expect(publicKey).toHaveLength(44);
    expect(wrapped).not.toBeNull();
    expect(wrapped?.keyId).toBe('account-identity-private-key');

    const blob = keyring.getRecoveryBlob();
    expect(blob?.account.identityPublicKeyBase64).toBe(publicKey);
    expect(blob?.account.wrappedIdentityPrivateKey).toEqual(wrapped);
  });

  it('restores the identity keypair on unlock', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const material = keyring.getMaterial();
    const expected = keyring.getIdentityPublicKey();

    const fresh = new Keyring();
    await fresh.unlock(PASSWORD, material!);

    expect(fresh.getIdentityPublicKey()).toBe(expected);
    expect(fresh.getWrappedIdentityPrivateKey()).toEqual(
      keyring.getWrappedIdentityPrivateKey(),
    );
  });

  it('rejects a recovery blob whose identity public key does not match the AEK wrap', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const material = keyring.getMaterial()!;
    const other = await Keyring.createKeyring({ password: PASSWORD });
    const swapped = {
      wrappedAek: material.wrappedAek,
      recoveryBlob: buildRecoveryBlob({
        accountId: material.recoveryBlob.account.accountId,
        wrappedAek: material.wrappedAek,
        deviceKeys: material.recoveryBlob.account.deviceKeys,
        identityPublicKeyBase64: other.getIdentityPublicKey() ?? undefined,
        wrappedIdentityPrivateKey:
          material.recoveryBlob.account.wrappedIdentityPrivateKey,
        identitySigningPublicKeyBase64:
          material.recoveryBlob.account.identitySigningPublicKeyBase64,
        wrappedIdentitySigningPrivateKey:
          material.recoveryBlob.account.wrappedIdentitySigningPrivateKey,
        identityPublicKeySignatureBase64:
          material.recoveryBlob.account.identityPublicKeySignatureBase64,
      }),
    };

    const fresh = new Keyring();
    await expect(fresh.unlock(PASSWORD, swapped)).rejects.toThrow(
      'identity public key',
    );
  });

  it('rejects a recovery blob that claims an identity without AEK-wrapped keys', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const material = keyring.getMaterial()!;
    const stripped = {
      wrappedAek: material.wrappedAek,
      recoveryBlob: buildRecoveryBlob({
        accountId: material.recoveryBlob.account.accountId,
        wrappedAek: material.wrappedAek,
        deviceKeys: material.recoveryBlob.account.deviceKeys,
        identityPublicKeyBase64:
          material.recoveryBlob.account.identityPublicKeyBase64,
        identitySigningPublicKeyBase64:
          material.recoveryBlob.account.identitySigningPublicKeyBase64,
        identityPublicKeySignatureBase64:
          material.recoveryBlob.account.identityPublicKeySignatureBase64,
      }),
    };

    const fresh = new Keyring();
    await expect(fresh.unlock(PASSWORD, stripped)).rejects.toThrow(
      'missing its AEK wrap',
    );
  });

  it('encrypts and decrypts entities', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const plaintext = encode('entity secret');

    const ciphertext = await keyring.encryptEntity(plaintext);
    expect(ciphertext.keyId).toMatch(/^aek_v1_[0-9a-f]{32}$/);
    expect(ciphertext.aadBase64).toBeTruthy();
    expect(await keyring.decryptEntity(ciphertext)).toEqual(plaintext);
  });

  it('keeps the entity key identity stable for the same AEK', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const material = keyring.getMaterial()!;
    const first = await keyring.encryptEntity(encode('first'));

    const restored = new Keyring();
    await restored.unlock(PASSWORD, material);
    const second = await restored.encryptEntity(encode('second'));
    const other = await Keyring.createKeyring();
    const isolated = await other.encryptEntity(encode('other'));

    expect(second.keyId).toBe(first.keyId);
    expect(isolated.keyId).not.toBe(first.keyId);
  });

  it('decrypts only the exact authenticated empty-keyId legacy shape', async () => {
    const keyring = await Keyring.createKeyring();
    const plaintext = encode('legacy entity');
    const source = await aesGcmEncrypt(plaintext, keyring.exportAek(), {
      keyId: 'legacy-source',
    });
    const legacy = JSON.parse(
      JSON.stringify({ ...source, keyId: '' }),
    ) as typeof source;

    expect(await keyring.decryptEntity(legacy)).toEqual(plaintext);
    await expect(
      keyring.decryptEntity({ ...legacy, aadBase64: 'AA==' }),
    ).rejects.toThrow();
    await expect(
      keyring.decryptEntity({ ...legacy, authTagBase64: undefined }),
    ).rejects.toThrow();
    await expect(
      keyring.decryptEntity({ ...legacy, version: 2 as never }),
    ).rejects.toThrow();
  });

  it('authenticates the current key identity and envelope headers', async () => {
    const keyring = await Keyring.createKeyring();
    const envelope = await keyring.encryptEntity(encode('bound headers'));

    await expect(
      keyring.decryptEntity({ ...envelope, keyId: `aek_v1_${'0'.repeat(32)}` }),
    ).rejects.toThrow();
    await expect(
      keyring.decryptEntity({ ...envelope, aadBase64: 'AA==' }),
    ).rejects.toThrow();
    await expect(
      keyring.decryptEntity({ ...envelope, algorithm: 'invalid' as never }),
    ).rejects.toThrow();
  });

  it('round-trips an empty entity payload', async () => {
    const keyring = await Keyring.createKeyring();
    const envelope = await keyring.encryptEntity(new Uint8Array());

    expect(envelope.ciphertextBase64).toBe('');
    expect(await keyring.decryptEntity(envelope)).toEqual(new Uint8Array());
  });

  it('locks and blocks entity operations', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const ciphertext = await keyring.encryptEntity(encode('x'));

    keyring.lock();
    expect(keyring.isUnlocked()).toBe(false);
    await expect(keyring.decryptEntity(ciphertext)).rejects.toThrow();
  });

  it('unlocks from persisted material', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const material = keyring.getMaterial();
    const ciphertext = await keyring.encryptEntity(encode('x'));

    const fresh = new Keyring();
    await fresh.unlock(PASSWORD, material!);

    expect(fresh.isUnlocked()).toBe(true);
    expect(await fresh.decryptEntity(ciphertext)).toEqual(encode('x'));
  });

  it('still unlocks existing material created with a weak password', async () => {
    const source = await Keyring.createKeyring({ password: PASSWORD });
    const sourceMaterial = source.getMaterial()!;
    const account = sourceMaterial.recoveryBlob.account;
    const salt = generateSalt();
    const weakPassword = 'weak';
    const masterKey = await deriveMasterKey(
      weakPassword,
      salt,
      DEFAULT_ARGON2_PARAMS,
    );
    const wrappedAek = await wrapAekWithMasterKey(
      source.exportAek(),
      masterKey,
      {
        algorithm: 'ARGON2ID',
        saltBase64: bytesToBase64(salt),
        ...DEFAULT_ARGON2_PARAMS,
      },
    );
    const legacyMaterial = {
      wrappedAek,
      recoveryBlob: buildRecoveryBlob({
        accountId: account.accountId,
        wrappedAek,
        deviceKeys: account.deviceKeys,
        identityPublicKeyBase64: account.identityPublicKeyBase64,
        wrappedIdentityPrivateKey: account.wrappedIdentityPrivateKey,
      }),
    };

    const fresh = new Keyring();
    await fresh.unlock(weakPassword, legacyMaterial);

    expect(fresh.isUnlocked()).toBe(true);
  });

  it('rejects a wrong password on unlock', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const fresh = new Keyring();

    await expect(
      fresh.unlock('wrong', keyring.getMaterial()!),
    ).rejects.toThrow();
  });

  it('auto-unlocks from a raw AEK', async () => {
    const aek = await generateAek();
    const keyring = new Keyring();

    await keyring.autoUnlock(aek);

    expect(keyring.isUnlocked()).toBe(true);
    const ciphertext = await keyring.encryptEntity(encode('x'));
    expect(await keyring.decryptEntity(ciphertext)).toEqual(encode('x'));
  });

  it('exportAek returns a defensive copy of the AEK', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const ciphertext = await keyring.encryptEntity(encode('x'));

    const copy = keyring.exportAek();
    copy.fill(0);

    expect(await keyring.decryptEntity(ciphertext)).toEqual(encode('x'));
  });

  it('exportAek throws when locked', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    keyring.lock();

    expect(() => keyring.exportAek()).toThrow();
  });

  it('unlockWithAek restores material and decrypts entities', async () => {
    const keyring = await Keyring.createKeyring({
      password: PASSWORD,
      accountId: 'acct_biometric',
    });
    const material = keyring.getMaterial()!;
    const aek = keyring.exportAek();
    const ciphertext = await keyring.encryptEntity(encode('secret'));
    const identityKey = keyring.getIdentityPublicKey();
    const wrappedIdentity = keyring.getWrappedIdentityPrivateKey();

    const fresh = new Keyring();
    await fresh.unlockWithAek(aek, material);

    expect(fresh.isUnlocked()).toBe(true);
    expect(fresh.getIdentityPublicKey()).toBe(identityKey);
    expect(fresh.getWrappedIdentityPrivateKey()).toEqual(wrappedIdentity);
    expect(fresh.getMaterial()).not.toBeNull();
    expect(fresh.getRecoveryBlob()).not.toBeNull();
    expect(await fresh.decryptEntity(ciphertext)).toEqual(encode('secret'));
  });

  it('unlockWithAek rejects an AEK that does not match the verifier', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const material = keyring.getMaterial()!;
    const other = await Keyring.createKeyring({ password: PASSWORD });

    const fresh = new Keyring();
    await expect(
      fresh.unlockWithAek(other.exportAek(), material),
    ).rejects.toThrow('does not match material');
  });

  it('changes the password while preserving encrypted data', async () => {
    const keyring = await Keyring.createKeyring({
      password: OLD_PASSWORD,
      accountId: 'acct_test',
    });
    const plaintext = encode('survives rotation');
    const ciphertext = await keyring.encryptEntity(plaintext);
    const identityKey = keyring.getIdentityPublicKey();
    const wrappedIdentity = keyring.getWrappedIdentityPrivateKey();

    await keyring.changeMasterPassword(OLD_PASSWORD, NEW_PASSWORD);
    const afterPasswordChange = await keyring.encryptEntity(
      encode('same account key'),
    );

    const updated = keyring.getMaterial()!;
    const stale = new Keyring();
    await expect(stale.unlock(OLD_PASSWORD, updated)).rejects.toThrow();

    const fresh = new Keyring();
    await fresh.unlock(NEW_PASSWORD, updated);
    expect(await fresh.decryptEntity(ciphertext)).toEqual(plaintext);
    expect(afterPasswordChange.keyId).toBe(ciphertext.keyId);
    expect(updated.recoveryBlob.account.identityPublicKeyBase64).toBe(
      identityKey,
    );
    expect(fresh.getIdentityPublicKey()).toBe(identityKey);
    expect(fresh.getWrappedIdentityPrivateKey()).toEqual(wrappedIdentity);
  });

  it('rejects a weak replacement without changing material', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    const before = keyring.getMaterial();

    await expect(
      keyring.changeMasterPassword(PASSWORD, 'too-short'),
    ).rejects.toThrow(`at least ${MIN_MASTER_PASSWORD_LENGTH} characters`);
    expect(keyring.getMaterial()).toEqual(before);
  });

  it('rejects a wrong old password', async () => {
    const keyring = await Keyring.createKeyring({ password: PASSWORD });
    await expect(
      keyring.changeMasterPassword('not-real', NEW_PASSWORD),
    ).rejects.toThrow();
  });

  it('hmacLookup is stable for the same AEK and differs across keyrings', async () => {
    const a = await Keyring.createKeyring({ password: PASSWORD });
    const b = await Keyring.createKeyring({ password: PASSWORD });
    const first = a.hmacLookup('https://example.com');

    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(a.hmacLookup('https://example.com')).toBe(first);
    expect(b.hmacLookup('https://example.com')).not.toBe(first);
  });
});
