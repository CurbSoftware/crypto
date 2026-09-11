import { describe, expect, it } from 'vitest';

import { aesGcmDecrypt, aesGcmEncrypt, aesKwWrap } from '../src/aes';
import { deriveMasterKey } from '../src/argon2';
import { base64ToBytes, bytesToBase64 } from '../src/base64';
import { bytesToHex } from '../src/wipe';
import vectors from '../vectors/v1.json';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('published vectors', () => {
  it('matches Argon2id', async () => {
    const v = vectors.argon2id;
    const mk = await deriveMasterKey(v.password, hexToBytes(v.saltHex), {
      iterations: v.t,
      memoryKb: v.m,
      parallelism: v.p,
      hashLength: v.dkLen,
    });
    expect(bytesToHex(mk)).toBe(v.masterKeyHex);
  });

  it('matches AES-GCM', async () => {
    const v = vectors.aesGcm;
    const env = await aesGcmEncrypt(
      hexToBytes(v.plaintextHex),
      hexToBytes(v.keyHex),
      {
        keyId: 'vector',
        iv: hexToBytes(v.ivHex),
        aad: hexToBytes(v.aadHex),
        engine: 'noble',
      },
    );
    expect(bytesToHex(base64ToBytes(env.ciphertextBase64))).toBe(
      v.ciphertextHex,
    );
    expect(bytesToHex(base64ToBytes(env.authTagBase64 ?? ''))).toBe(v.tagHex);
    expect(
      bytesToHex(
        await aesGcmDecrypt(env, hexToBytes(v.keyHex), { engine: 'noble' }),
      ),
    ).toBe(v.plaintextHex);
    expect(bytesToBase64(hexToBytes(v.ivHex))).toBe(env.ivBase64);
  });

  it('matches AES-KW', async () => {
    const v = vectors.aesKw;
    const wrapped = await aesKwWrap(hexToBytes(v.keyHex), hexToBytes(v.kekHex));
    expect(bytesToHex(wrapped)).toBe(v.wrappedHex);
  });
});
