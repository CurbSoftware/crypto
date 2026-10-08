import { describe, expect, it } from 'vitest';

import { generateAek } from '../src/aek';
import { aesGcmDecrypt } from '../src/aes';
import { base64ToBytes, bytesToBase64 } from '../src/base64';
import {
  DOMAIN_PROTOCOL_VERSION,
  DOMAIN_SCOPES,
  createDomainKeySet,
  decryptDomainEnvelope,
  domainResourceAad,
  encryptDomainEnvelope,
  hmacDomainLookup,
  openDomainEnvelope,
  unwrapDomainKeySet,
} from '../src/domain-keys';
import { hmacLookup } from '../src/lookup';
import { Keyring, openEntityEnvelope } from '../src/keyring';
import { parseRecoveryBlob } from '../src/recovery-blob';
import { bytesToHex, wipe } from '../src/wipe';
import vectors from '../vectors/domain-v1.json';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

const encode = (value: string) => new TextEncoder().encode(value);

const binding = {
  accountId: 'acct_1',
  scope: 'curbpage' as const,
  entityId: 'bookmark_1',
  entityKind: 'bookmark',
};

describe('domain keys', () => {
  it('matches the published domain vector', async () => {
    const envelope = await encryptDomainEnvelope(
      hexToBytes(vectors.plaintextHex),
      hexToBytes(vectors.domainKeyHex),
      hexToBytes(vectors.aekHex),
      {
        accountId: vectors.accountId,
        scope: 'curbpage',
        entityId: vectors.entityId,
        entityKind: vectors.entityKind,
        epoch: vectors.epoch,
      },
      { iv: hexToBytes(vectors.ivHex), engine: 'noble' },
    );

    expect(bytesToHex(base64ToBytes(envelope.ciphertextBase64))).toBe(
      vectors.ciphertextHex,
    );
    expect(bytesToHex(base64ToBytes(envelope.authTagBase64))).toBe(
      vectors.tagHex,
    );
    expect(bytesToHex(base64ToBytes(envelope.wrappedKeyBase64))).toBe(
      vectors.wrappedKeyHex,
    );
    expect(envelope.keyId).toBe(vectors.keyId);
    expect(
      bytesToHex(
        domainResourceAad({
          accountId: vectors.accountId,
          scope: 'curbpage',
          entityId: vectors.entityId,
          entityKind: vectors.entityKind,
          epoch: vectors.epoch,
        }),
      ),
    ).toBe(vectors.aadHex);
    expect(
      vectors.aadHex.includes(Buffer.from('revision').toString('hex')),
    ).toBe(false);
    expect(
      await decryptDomainEnvelope(envelope, hexToBytes(vectors.domainKeyHex)),
    ).toEqual(hexToBytes(vectors.plaintextHex));
  });

  it('wraps independent scope keys with the supplied AEK', async () => {
    const aek = await generateAek();
    const before = bytesToHex(aek);
    const { set, secrets } = await createDomainKeySet(aek);

    expect(bytesToHex(aek)).toBe(before);
    expect(set.version).toBe(1);
    expect(set.keys.map((key) => key.scope)).toEqual([...DOMAIN_SCOPES]);
    expect(new Set(secrets.map((secret) => bytesToHex(secret.key))).size).toBe(
      DOMAIN_SCOPES.length,
    );
    for (const secret of secrets) {
      expect(secret.key).toHaveLength(32);
      expect(secret.epoch).toBe(1);
    }

    const opened = await unwrapDomainKeySet(set, aek);
    expect(opened.map((secret) => secret.keyId)).toEqual(
      secrets.map((secret) => secret.keyId),
    );
    for (let i = 0; i < opened.length; i += 1) {
      expect(opened[i]?.key).toEqual(secrets[i]?.key);
      wipe(opened[i]?.key);
      wipe(secrets[i]?.key);
    }

    const other = await generateAek();
    await expect(unwrapDomainKeySet(set, other)).rejects.toThrow();
    wipe(aek);
    wipe(other);
  });

  it('seals a version 3 envelope bound to the resource, not a server revision', async () => {
    const aek = await generateAek();
    const { secrets } = await createDomainKeySet(aek);
    const secret = secrets[0];
    if (!secret) throw new Error('missing curbpage key');

    const aad = new TextDecoder().decode(domainResourceAad(binding));
    expect(aad).toBe(
      `curbapps/domain-envelope/v1\0${binding.accountId}\0${binding.scope}\0${binding.entityId}\0${binding.entityKind}\0${1}\0${DOMAIN_PROTOCOL_VERSION}`,
    );
    expect(aad.includes('revision')).toBe(false);

    const envelope = await encryptDomainEnvelope(
      encode('domain secret'),
      secret.key,
      aek,
      binding,
      { engine: 'noble' },
    );
    expect(envelope.version).toBe(3);
    expect(envelope.algorithm).toBe('AES-GCM-256');
    expect(envelope.protocolVersion).toBe(1);
    expect(envelope.epoch).toBe(1);
    expect(envelope.keyId.startsWith('dk_v1_')).toBe(true);
    expect(await decryptDomainEnvelope(envelope, secret.key)).toEqual(
      encode('domain secret'),
    );
    await expect(decryptDomainEnvelope(envelope, aek)).rejects.toThrow();
    await expect(
      aesGcmDecrypt(
        {
          version: 1,
          algorithm: 'AES-GCM-256',
          keyId: envelope.keyId,
          ivBase64: envelope.ivBase64,
          ciphertextBase64: envelope.ciphertextBase64,
          authTagBase64: envelope.authTagBase64,
          aadBase64: envelope.aadBase64,
        },
        aek,
        { engine: 'noble' },
      ),
    ).rejects.toThrow();
    expect(await openDomainEnvelope(envelope, aek)).toEqual(
      encode('domain secret'),
    );

    await expect(
      decryptDomainEnvelope({ ...envelope, scope: 'curbplace' }, secret.key),
    ).rejects.toThrow();
    const swappedAad = bytesToBase64(
      domainResourceAad({ ...binding, entityId: 'bookmark_2' }),
    );
    await expect(
      decryptDomainEnvelope({ ...envelope, aadBase64: swappedAad }, secret.key),
    ).rejects.toThrow();

    for (const secret of secrets) wipe(secret.key);
    wipe(aek);
  });

  it('separates lookup digests by scope', async () => {
    const key = (await generateAek()).slice();
    const page = hmacDomainLookup(key, 'curbpage', 'https://example.com');
    const place = hmacDomainLookup(key, 'curbplace', 'https://example.com');
    expect(page).toMatch(/^[0-9a-f]{64}$/);
    expect(page).not.toBe(place);
    expect(hmacDomainLookup(key, 'curbpage', 'https://example.com')).toBe(page);
    expect(page).not.toBe(hmacLookup(key, 'https://example.com'));
    wipe(key);
  });

  it('keeps version 1 envelopes and recovery blobs readable', async () => {
    const keyring = await Keyring.createKeyring();
    const oldPlaintext = encode('still the aek');
    const oldEnvelope = await keyring.encryptEntity(oldPlaintext);
    expect(oldEnvelope.version).toBe(1);

    const domainEnvelope = await keyring.encryptDomainEntity(
      encode('scope key'),
      binding,
    );
    expect(domainEnvelope.version).toBe(3);
    expect(await keyring.decryptEntity(oldEnvelope)).toEqual(oldPlaintext);
    expect(await keyring.decryptEntity(domainEnvelope)).toEqual(
      encode('scope key'),
    );

    const peer = new Keyring();
    await peer.autoUnlock(keyring.exportAek());
    expect(await peer.decryptEntity(oldEnvelope)).toEqual(oldPlaintext);
    expect(await peer.decryptEntity(domainEnvelope)).toEqual(
      encode('scope key'),
    );
    expect(peer.getWrappedDomainKeys()).toBeNull();

    const stranger = new Keyring();
    await stranger.autoUnlock(await generateAek());
    await expect(stranger.decryptEntity(domainEnvelope)).rejects.toThrow();
  });

  it('restores domain keys from material without changing the recovery blob', async () => {
    const password = 'correct-horse';
    const keyring = await Keyring.createKeyring({ password });
    const oldEnvelope = await keyring.encryptEntity(encode('legacy row'));
    const domainEnvelope = await keyring.encryptDomainEntity(
      encode('new row'),
      {
        ...binding,
        scope: 'shared-vault',
        entityKind: 'vault_entry',
      },
    );
    const material = keyring.getMaterial();
    const blob = keyring.getRecoveryBlob();
    if (!material || !blob) throw new Error('missing material');

    expect(blob.version).toBe(1);
    expect(JSON.stringify(blob)).not.toContain('wrappedDomainKeys');
    expect(JSON.stringify(blob)).not.toContain('dk_v1_');
    expect(parseRecoveryBlob(JSON.stringify(blob)).version).toBe(1);
    expect(material.wrappedDomainKeys?.keys).toHaveLength(5);

    const restored = new Keyring();
    await restored.unlock(password, material);
    expect(await restored.decryptEntity(oldEnvelope)).toEqual(
      encode('legacy row'),
    );
    expect(await restored.decryptEntity(domainEnvelope)).toEqual(
      encode('new row'),
    );
    expect(
      restored.getWrappedDomainKeys()?.keys.map((key) => key.keyId),
    ).toEqual(material.wrappedDomainKeys?.keys.map((key) => key.keyId));

    const { wrappedDomainKeys: _ignored, ...legacyMaterial } = material;
    const legacyReader = new Keyring();
    await legacyReader.unlock(password, legacyMaterial);
    expect(await legacyReader.decryptEntity(oldEnvelope)).toEqual(
      encode('legacy row'),
    );
    expect(
      await openEntityEnvelope(domainEnvelope, legacyReader.exportAek()),
    ).toEqual(encode('new row'));

    await keyring.changeMasterPassword(password, 'correct-horse-2');
    const rotated = new Keyring();
    await rotated.unlock('correct-horse-2', keyring.getMaterial()!);
    expect(await rotated.decryptEntity(oldEnvelope)).toEqual(
      encode('legacy row'),
    );
    expect(await rotated.decryptEntity(domainEnvelope)).toEqual(
      encode('new row'),
    );
    expect(JSON.stringify(rotated.getRecoveryBlob())).not.toContain(
      'wrappedDomainKeys',
    );
  });
});
