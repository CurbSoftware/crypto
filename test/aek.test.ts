import { describe, expect, it } from 'vitest';

import {
  buildAekVerifier,
  generateAek,
  unwrapAek,
  verifyAekVerifier,
  wrapAekWithMasterKey,
} from '../src/aek';
import { deriveMasterKey, generateSalt } from '../src/argon2';
import { bytesToBase64 } from '../src/base64';

describe('aek', () => {
  it('generates a 32-byte AEK', async () => {
    expect(await generateAek()).toHaveLength(32);
  });

  it('wrap / unwrap round-trips', async () => {
    const aek = await generateAek();
    const salt = generateSalt();
    const masterKey = await deriveMasterKey('password', salt);

    const wrapped = await wrapAekWithMasterKey(aek, masterKey, {
      algorithm: 'ARGON2ID',
      saltBase64: bytesToBase64(salt),
      memoryKb: 19456,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
    });

    expect(wrapped.version).toBe(1);
    expect(wrapped.algorithm).toBe('AES-KW-256');
    expect(await unwrapAek(wrapped, masterKey)).toEqual(aek);
  });

  it('wrap without a KDF generates a fresh descriptor', async () => {
    const aek = await generateAek();
    const masterKey = await generateAek();

    const wrapped = await wrapAekWithMasterKey(aek, masterKey);
    expect(wrapped.kdf.algorithm).toBe('ARGON2ID');
    expect(wrapped.kdf.saltBase64).toBeTruthy();
  });

  it('verifier build/verify round-trips and rejects a wrong key', async () => {
    const aek = await generateAek();
    const other = await generateAek();
    const verifier = await buildAekVerifier(aek);

    expect(await verifyAekVerifier(verifier, aek)).toBe(true);
    expect(await verifyAekVerifier(verifier, other)).toBe(false);
  });
});
