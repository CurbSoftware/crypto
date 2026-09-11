import { describe, expect, it } from 'vitest';

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesKwUnwrap,
  aesKwWrap,
  randomBytes,
} from '../src/aes';
import { base64ToBytes, bytesToBase64 } from '../src/base64';
import type { EncryptedEnvelopeV1 } from '../src/envelope';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

describe('aesGcmEncrypt / aesGcmDecrypt', () => {
  const key = randomBytes(32);
  const plaintext = new TextEncoder().encode('attack at dawn');

  it('round-trips via WebCrypto', async () => {
    const env = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'webcrypto',
    });
    expect(env.algorithm).toBe('AES-GCM-256');

    const out = await aesGcmDecrypt(env, key, { engine: 'webcrypto' });
    expect(out).toEqual(plaintext);
  });

  it('round-trips via the noble fallback', async () => {
    const env = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'noble',
    });
    const out = await aesGcmDecrypt(env, key, { engine: 'noble' });
    expect(out).toEqual(plaintext);
  });

  it('rejects missing and empty key identities for new envelopes', async () => {
    await expect(aesGcmEncrypt(plaintext, key, { keyId: '' })).rejects.toThrow(
      'non-empty opaque identifier',
    );
    await expect(aesGcmEncrypt(plaintext, key, {} as never)).rejects.toThrow(
      'non-empty opaque identifier',
    );
  });

  it('is interoperable across engines', async () => {
    const envWeb = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'webcrypto',
    });
    const envNoble = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'noble',
    });

    expect(await aesGcmDecrypt(envWeb, key, { engine: 'noble' })).toEqual(
      plaintext,
    );
    expect(await aesGcmDecrypt(envNoble, key, { engine: 'webcrypto' })).toEqual(
      plaintext,
    );
  });

  it('splits the 16-byte tag identically in both engines', async () => {
    const iv = randomBytes(12);
    const envWeb = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'webcrypto',
      iv,
    });
    const envNoble = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'noble',
      iv,
    });

    // Same key + IV + plaintext must yield identical ciphertext and tag.
    expect(envWeb.ciphertextBase64).toBe(envNoble.ciphertextBase64);
    expect(envWeb.authTagBase64).toBe(envNoble.authTagBase64);
  });

  it('rejects tampered ciphertext', async () => {
    const env = await aesGcmEncrypt(plaintext, key, {
      keyId: 'test-key',
      engine: 'noble',
    });
    const tampered: EncryptedEnvelopeV1 = {
      ...env,
      ciphertextBase64: bytesToBase64(randomBytes(16)),
    };

    await expect(
      aesGcmDecrypt(tampered, key, { engine: 'noble' }),
    ).rejects.toThrow();
  });
});

describe('aesKwWrap / aesKwUnwrap (RFC 3394)', () => {
  it('matches the RFC 3394 section 4.1 test vector', async () => {
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    const keyData = hexToBytes('00112233445566778899AABBCCDDEEFF');
    const expected = '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5';

    const wrapped = await aesKwWrap(keyData, kek);
    expect(bytesToHex(wrapped)).toBe(expected);
    expect(await aesKwUnwrap(wrapped, kek)).toEqual(keyData);
  });

  it('round-trips a 32-byte key', async () => {
    const kek = randomBytes(32);
    const keyData = randomBytes(32);

    const wrapped = await aesKwWrap(keyData, kek);
    expect(wrapped).toHaveLength(40);
    expect(await aesKwUnwrap(wrapped, kek)).toEqual(keyData);
  });

  it('rejects a wrapped key under the wrong KEK', async () => {
    const kek = randomBytes(32);
    const wrongKek = randomBytes(32);
    const wrapped = await aesKwWrap(randomBytes(32), kek);

    await expect(aesKwUnwrap(wrapped, wrongKek)).rejects.toThrow();
  });
});

describe('legacy envelope compatibility', () => {
  it('decrypts base64 JSON {iv, data} envelopes', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('legacy secret');
    const iv = randomBytes(12);

    // Produce ciphertext + tag, then reshape into the legacy layout where
    // data = ciphertext || tag and the whole object is base64 JSON.
    const modern = await aesGcmEncrypt(plaintext, key, {
      keyId: 'legacy-source',
      iv,
    });
    const ciphertext = base64ToBytes(modern.ciphertextBase64);
    const tag = base64ToBytes(modern.authTagBase64 ?? '');

    const legacyJson = JSON.stringify({
      iv: Array.from(iv),
      data: Array.from(concat(ciphertext, tag)),
    });
    const legacyB64 = bytesToBase64(new TextEncoder().encode(legacyJson));

    const decoded = JSON.parse(
      new TextDecoder().decode(base64ToBytes(legacyB64)),
    ) as { iv: number[]; data: number[] };

    const env: EncryptedEnvelopeV1 = {
      version: 1,
      algorithm: 'AES-GCM-256',
      keyId: '',
      ivBase64: bytesToBase64(Uint8Array.from(decoded.iv)),
      ciphertextBase64: bytesToBase64(Uint8Array.from(decoded.data)),
      // No authTagBase64: aesGcmDecrypt splits the trailing tag itself.
    };

    expect(await aesGcmDecrypt(env, key)).toEqual(plaintext);
  });
});
