import { describe, expect, it } from 'vitest';

import { aesGcmDecrypt, aesGcmEncrypt, randomBytes } from '../src/aes';
import {
  generateDeviceKeypair,
  importDevicePrivateKey,
  privateKeyFromBase64,
  privateKeyToBase64,
  publicKeyFromBase64,
  publicKeyToBase64,
} from '../src/device-keys';
import {
  deriveSharedWrappingKey,
  unwrapKeyForRecipient,
  wrapKeyForRecipient,
} from '../src/ecdh';

describe('device keys', () => {
  it('generates a 32-byte X25519 keypair', async () => {
    const { privateKey, publicKey } = await generateDeviceKeypair();

    expect(privateKey).toHaveLength(32);
    expect(publicKey).toHaveLength(32);
  });

  it('re-derives the public key from an imported private key', async () => {
    const { privateKey, publicKey } = await generateDeviceKeypair();
    const imported = importDevicePrivateKey(privateKey);

    expect(imported.publicKey).toEqual(publicKey);
  });

  it('rejects a wrong-size private key', () => {
    expect(() => importDevicePrivateKey(new Uint8Array(31))).toThrow();
  });

  it('re-derives the public key from an AEK-wrapped private key (identity self-heal path)', async () => {
    const aek = randomBytes(32);
    const { privateKey, publicKey } = await generateDeviceKeypair();

    const wrapped = await aesGcmEncrypt(privateKey, aek, {
      keyId: 'account-identity-private-key',
    });
    const decrypted = await aesGcmDecrypt(wrapped, aek);

    expect(importDevicePrivateKey(decrypted).publicKey).toEqual(publicKey);
  });

  it('base64 round-trips public and private keys', () => {
    const privateKey = randomBytes(32);
    const publicKey = randomBytes(32);

    expect(publicKeyFromBase64(publicKeyToBase64(publicKey))).toEqual(
      publicKey,
    );
    expect(privateKeyFromBase64(privateKeyToBase64(privateKey))).toEqual(
      privateKey,
    );
  });
});

describe('ecdh', () => {
  it('agrees on a symmetric shared wrapping key', async () => {
    const alice = await generateDeviceKeypair();
    const bob = await generateDeviceKeypair();

    const ab = await deriveSharedWrappingKey(alice.privateKey, bob.publicKey);
    const ba = await deriveSharedWrappingKey(bob.privateKey, alice.publicKey);

    expect(ab).toHaveLength(32);
    expect(ab).toEqual(ba);
  });

  it('wrapKeyForRecipient / unwrapKeyForRecipient round-trip', async () => {
    const alice = await generateDeviceKeypair();
    const bob = await generateDeviceKeypair();
    const entityKey = randomBytes(32);

    const wrapped = await wrapKeyForRecipient(
      entityKey,
      alice.privateKey,
      bob.publicKey,
    );
    const unwrapped = await unwrapKeyForRecipient(
      wrapped,
      bob.privateKey,
      alice.publicKey,
    );

    expect(unwrapped).toEqual(entityKey);
  });
});
