import { describe, expect, it } from 'vitest';

import {
  generatePaperRecoveryKey,
  unwrapAekWithPaperKey,
  wrapAekWithPaperKey,
} from '../src/paper-recovery';
import { Keyring } from '../src/keyring';
import { serializeRecoveryBlob } from '../src/recovery-blob';
import { bytesToHex, wipe } from '../src/wipe';

describe('paper recovery', () => {
  it('unwraps the same AEK and leaves the master-password blob untouched', async () => {
    const password = 'correct horse battery';
    const keyring = await Keyring.createKeyring({
      password,
      accountId: 'acct_paper',
    });
    const before = serializeRecoveryBlob(keyring.getRecoveryBlob()!);
    const material = keyring.getMaterial()!;
    const { paperKey, wrap } = await keyring.createPaperRecovery();
    const after = serializeRecoveryBlob(keyring.getRecoveryBlob()!);

    expect(after).toBe(before);
    expect(JSON.stringify(wrap)).not.toContain(bytesToHex(paperKey));
    expect(paperKey).toHaveLength(32);

    const restored = new Keyring();
    await restored.unlockWithPaper(paperKey, wrap, material);
    const plaintext = new TextEncoder().encode('still here');
    const envelope = await keyring.encryptEntity(plaintext);
    expect(await restored.decryptEntity(envelope)).toEqual(plaintext);

    const passwordKeyring = new Keyring();
    await passwordKeyring.unlock(password, material);
    expect(await passwordKeyring.decryptEntity(envelope)).toEqual(plaintext);

    const wrong = generatePaperRecoveryKey();
    const rejected = new Keyring();
    await expect(
      rejected.unlockWithPaper(wrong, wrap, material),
    ).rejects.toThrow();

    wipe(paperKey);
    wipe(wrong);
    keyring.lock();
    restored.lock();
    passwordKeyring.lock();
  });

  it('refuses a paper wrap that was not made for this key', async () => {
    const paperKey = generatePaperRecoveryKey();
    const other = generatePaperRecoveryKey();
    const wrap = await wrapAekWithPaperKey(
      new Uint8Array(32).fill(7),
      paperKey,
    );
    await expect(unwrapAekWithPaperKey(other, wrap)).rejects.toThrow();
    wipe(paperKey);
    wipe(other);
  });
});
