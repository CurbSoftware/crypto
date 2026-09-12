import { describe, expect, it } from 'vitest';

import { randomBytes } from '../src/aes';
import { generateDeviceKeypair, publicKeyToBase64 } from '../src/device-keys';
import {
  deriveSharedWrappingKeyV2,
  unwrapKeyForRecipient,
  wrapKeyForRecipient,
} from '../src/ecdh';
import {
  generateAccountIdentity,
  verifyAccountIdentityDocument,
  wrapKeyForVerifiedIdentity,
} from '../src/identity';

describe('identity', () => {
  it('signs the X25519 public key and verifies', async () => {
    const identity = await generateAccountIdentity();
    expect(verifyAccountIdentityDocument(identity.document)).toBe(true);
    expect(identity.document.x25519PublicKeyBase64).toHaveLength(44);
  });

  it('rejects a swapped X25519 public key', async () => {
    const identity = await generateAccountIdentity();
    const other = await generateDeviceKeypair();
    const tampered = {
      ...identity.document,
      x25519PublicKeyBase64: publicKeyToBase64(other.publicKey),
    };
    expect(verifyAccountIdentityDocument(tampered)).toBe(false);
  });

  it('wraps only after the identity document verifies', async () => {
    const grantor = await generateDeviceKeypair();
    const identity = await generateAccountIdentity();
    const entityKey = randomBytes(32);
    const context = { purpose: 'grant', grantId: 'g1' };

    const wrapped = await wrapKeyForVerifiedIdentity(
      entityKey,
      grantor.privateKey,
      grantor.publicKey,
      identity.document,
      context,
    );
    const unwrapped = await unwrapKeyForRecipient(
      wrapped,
      identity.x25519.privateKey,
      grantor.publicKey,
      context,
      identity.x25519.publicKey,
    );
    expect(unwrapped).toEqual(entityKey);

    const tampered = {
      ...identity.document,
      x25519PublicKeyBase64: publicKeyToBase64(
        (await generateDeviceKeypair()).publicKey,
      ),
    };
    await expect(
      wrapKeyForVerifiedIdentity(
        entityKey,
        grantor.privateKey,
        grantor.publicKey,
        tampered,
        context,
      ),
    ).rejects.toThrow('signature is invalid');
  });
});

describe('ecdh v2', () => {
  it('binds the wrap to purpose and public keys', async () => {
    const alice = await generateDeviceKeypair();
    const bob = await generateDeviceKeypair();
    const entityKey = randomBytes(32);
    const context = { purpose: 'grant', grantId: 'g1', entityId: 'e1' };

    const wrapped = await wrapKeyForRecipient(
      entityKey,
      alice.privateKey,
      bob.publicKey,
      context,
      alice.publicKey,
    );
    const unwrapped = await unwrapKeyForRecipient(
      wrapped,
      bob.privateKey,
      alice.publicKey,
      context,
      bob.publicKey,
    );
    expect(unwrapped).toEqual(entityKey);

    await expect(
      unwrapKeyForRecipient(
        wrapped,
        bob.privateKey,
        alice.publicKey,
        { purpose: 'other' },
        bob.publicKey,
      ),
    ).rejects.toThrow();
  });

  it('agrees on the v2 wrapping key', async () => {
    const alice = await generateDeviceKeypair();
    const bob = await generateDeviceKeypair();
    const context = { purpose: 'room', entityId: 'room-1' };
    const ab = deriveSharedWrappingKeyV2(
      alice.privateKey,
      bob.publicKey,
      alice.publicKey,
      context,
    );
    const ba = deriveSharedWrappingKeyV2(
      bob.privateKey,
      alice.publicKey,
      bob.publicKey,
      context,
    );
    expect(ab).toEqual(ba);
  });
});
