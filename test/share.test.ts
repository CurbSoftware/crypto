import { describe, expect, it } from 'vitest';

import { bytesToBase64 } from '../src/base64';
import {
  SHARE_PBKDF2_ITERATIONS,
  buildEncryptedShare,
  deriveShareKek,
  encryptSharePayload,
  generateShareKey,
  generateShareSalt,
  openEncryptedShare,
  wrapShareKey,
} from '../src/share';

const PASSWORD = 'share-password-ok';

describe('share', () => {
  it('round-trips a password-protected share with Argon2id', async () => {
    const built = await buildEncryptedShare({
      plaintext: '{"title":"n"}',
      password: PASSWORD,
    });
    expect(built.passwordProtected).toBe(true);
    expect(built.kdf?.algorithm).toBe('ARGON2ID');
    expect(built.shareKeyBase64Url).toBeNull();

    const opened = await openEncryptedShare({
      ciphertext: built.ciphertext,
      passwordProtected: true,
      saltBase64: built.saltBase64,
      wrappedShareKeyBase64: built.wrappedShareKeyBase64,
      kdf: built.kdf,
      password: PASSWORD,
    });
    expect(opened).toBe('{"title":"n"}');
  });

  it('round-trips a passwordless share', async () => {
    const built = await buildEncryptedShare({ plaintext: 'open sesame' });
    expect(built.passwordProtected).toBe(false);
    const opened = await openEncryptedShare({
      ciphertext: built.ciphertext,
      passwordProtected: false,
      saltBase64: null,
      shareKeyBase64Url: built.shareKeyBase64Url ?? undefined,
    });
    expect(opened).toBe('open sesame');
  });

  it('opens a legacy PBKDF2-wrapped share', async () => {
    const shareKey = generateShareKey();
    const salt = generateShareSalt();
    const kdf = {
      algorithm: 'PBKDF2-SHA256' as const,
      iterations: SHARE_PBKDF2_ITERATIONS,
      saltBase64: bytesToBase64(salt),
    };
    const kek = await deriveShareKek(PASSWORD, salt, kdf);
    const wrappedShareKeyBase64 = await wrapShareKey(shareKey, kek);
    const ciphertext = await encryptSharePayload('legacy share', shareKey);

    const opened = await openEncryptedShare({
      ciphertext,
      passwordProtected: true,
      saltBase64: kdf.saltBase64,
      wrappedShareKeyBase64,
      kdf,
      password: PASSWORD,
    });
    expect(opened).toBe('legacy share');
  });

  it('rejects oversized PBKDF2 iteration counts', async () => {
    await expect(
      deriveShareKek(PASSWORD, generateShareSalt(), {
        algorithm: 'PBKDF2-SHA256',
        iterations: 1_000_001,
        saltBase64: 'AAAAAAAAAAAAAAAAAAAAAA==',
      }),
    ).rejects.toThrow('out of range');
  });
});
