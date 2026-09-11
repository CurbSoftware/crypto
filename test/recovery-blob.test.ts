import { describe, expect, it } from 'vitest';

import { generateAek, wrapAekWithMasterKey } from '../src/aek';
import { aesGcmEncrypt } from '../src/aes';
import { deriveMasterKey, generateSalt } from '../src/argon2';
import { bytesToBase64 } from '../src/base64';
import { generateDeviceKeypair, publicKeyToBase64 } from '../src/device-keys';
import type { DeviceKeyRecordV1 } from '../src/envelope';
import {
  buildRecoveryBlob,
  parseRecoveryBlob,
  serializeRecoveryBlob,
} from '../src/recovery-blob';

describe('recovery blob', () => {
  it('build / serialize / parse round-trips', async () => {
    const aek = await generateAek();
    const salt = generateSalt();
    const masterKey = await deriveMasterKey('password', salt);
    const wrappedAek = await wrapAekWithMasterKey(aek, masterKey, {
      algorithm: 'ARGON2ID',
      saltBase64: bytesToBase64(salt),
      memoryKb: 19456,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
    });

    const keypair = await generateDeviceKeypair();
    const deviceKey: DeviceKeyRecordV1 = {
      version: 1,
      deviceId: 'dev_1',
      publicKeyBase64: publicKeyToBase64(keypair.publicKey),
      wrappedPrivateKey: await aesGcmEncrypt(keypair.privateKey, aek, {
        keyId: 'device-private-key',
      }),
      createdAt: new Date().toISOString(),
    };

    const blob = buildRecoveryBlob({
      accountId: 'acct_1',
      wrappedAek,
      deviceKeys: [deviceKey],
    });

    const parsed = parseRecoveryBlob(serializeRecoveryBlob(blob));

    expect(parsed).toEqual(blob);
    expect(parsed.version).toBe(1);
    expect(parsed.account.version).toBe(1);
    expect(parsed.account.accountId).toBe('acct_1');
    expect(parsed.account.wrappedAek).toEqual(wrappedAek);
    expect(parsed.account.deviceKeys).toHaveLength(1);
  });

  it('rejects unsupported or malformed input', () => {
    expect(() => parseRecoveryBlob('{}')).toThrow();
    expect(() => parseRecoveryBlob(JSON.stringify({ version: 2 }))).toThrow();
    expect(() =>
      parseRecoveryBlob(
        JSON.stringify({ version: 1, account: { version: 2 } }),
      ),
    ).toThrow();
  });
});
