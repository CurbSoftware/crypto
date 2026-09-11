import { describe, expect, it } from 'vitest';

import {
  DEFAULT_ARGON2_PARAMS,
  deriveMasterKey,
  generateSalt,
} from '../src/argon2';

describe('argon2', () => {
  it('exposes the OWASP floor default params', () => {
    expect(DEFAULT_ARGON2_PARAMS).toEqual({
      memoryKb: 19456,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
    });
  });

  it('derives a stable master key from password + salt', async () => {
    const salt = generateSalt();
    const a = await deriveMasterKey('correct horse', salt);
    const b = await deriveMasterKey('correct horse', salt);

    expect(a).toHaveLength(32);
    expect(a).toEqual(b);
  });

  it('produces different keys for different passwords', async () => {
    const salt = generateSalt();
    const a = await deriveMasterKey('password-a', salt);
    const b = await deriveMasterKey('password-b', salt);

    expect(a).not.toEqual(b);
  });

  it('completes within 5 seconds at default cost', async () => {
    const salt = generateSalt();
    const start = Date.now();
    await deriveMasterKey('benchmark-password', salt);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(5000);
  });

  it('honors valid custom params', async () => {
    const salt = generateSalt();
    const derived = await deriveMasterKey('pw', salt, {
      memoryKb: 8,
      iterations: 1,
      parallelism: 1,
      hashLength: 32,
    });

    expect(derived).toHaveLength(32);
  });

  it('rejects a non-32-byte hash length', async () => {
    const salt = generateSalt();
    await expect(
      deriveMasterKey('pw', salt, { hashLength: 64 }),
    ).rejects.toThrow('hashLength');
  });

  it('rejects absurd memory cost', async () => {
    const salt = generateSalt();
    await expect(
      deriveMasterKey('pw', salt, { memoryKb: 4000000 }),
    ).rejects.toThrow('memoryKb');
  });
});
