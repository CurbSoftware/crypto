import { describe, expect, it } from 'vitest';

import { buildEncryptedShare, openEncryptedShare } from '../src/share';

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
});
