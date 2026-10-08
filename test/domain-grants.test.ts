import { describe, expect, it } from 'vitest';

import { generateAek } from '../src/aek';
import { base64ToBytes, bytesToBase64 } from '../src/base64';
import { generateDeviceKeypair } from '../src/device-keys';
import {
  createDomainKeySet,
  openAuthorizedDomainKeys,
  sealAuthorizedDomainKeys,
} from '../src/domain-keys';
import { Keyring } from '../src/keyring';
import { bytesToHex, wipe } from '../src/wipe';

describe('authorized domain grants', () => {
  it('delivers only the requested scope keys', async () => {
    const aek = await generateAek();
    const { secrets } = await createDomainKeySet(aek);
    const sender = await generateDeviceKeypair();
    const recipient = await generateDeviceKeypair();
    const page = secrets.find((secret) => secret.scope === 'curbpage');
    const tube = secrets.find((secret) => secret.scope === 'curbtube');
    if (!page || !tube) throw new Error('missing scope key');

    const grant = await sealAuthorizedDomainKeys({
      secrets,
      scopes: ['curbpage', 'shared-vault'],
      senderPrivateKey: sender.privateKey,
      senderPublicKey: sender.publicKey,
      recipientPublicKey: recipient.publicKey,
      deviceId: 'device-page',
    });

    const serialized = JSON.stringify(grant);
    expect(serialized).not.toContain(bytesToHex(page.key));
    expect(serialized).not.toContain(bytesToBase64(page.key));
    expect(grant.wraps.map((wrap) => wrap.scope).sort()).toEqual([
      'curbpage',
      'shared-vault',
    ]);

    const opened = await openAuthorizedDomainKeys({
      grant,
      recipientPrivateKey: recipient.privateKey,
      recipientPublicKey: recipient.publicKey,
      senderPublicKey: sender.publicKey,
    });
    expect(opened.map((secret) => secret.scope).sort()).toEqual([
      'curbpage',
      'shared-vault',
    ]);
    const openedPage = opened.find((secret) => secret.scope === 'curbpage');
    expect(openedPage && bytesToHex(openedPage.key)).toBe(bytesToHex(page.key));

    const wrong = await generateDeviceKeypair();
    await expect(
      openAuthorizedDomainKeys({
        grant,
        recipientPrivateKey: wrong.privateKey,
        recipientPublicKey: wrong.publicKey,
        senderPublicKey: sender.publicKey,
      }),
    ).rejects.toThrow();

    for (const secret of [...secrets, ...opened]) wipe(secret.key);
    wipe(aek);
    wipe(sender.privateKey);
    wipe(recipient.privateKey);
    wipe(wrong.privateKey);
  });

  it('lets a granted client read one scope while the AEK still reads all', async () => {
    const keyring = await Keyring.createKeyring({
      password: 'correct horse battery',
      accountId: 'acct_grant',
    });
    const page = await keyring.encryptDomainEntity(
      new TextEncoder().encode('page body'),
      {
        accountId: 'acct_grant',
        scope: 'curbpage',
        entityId: 'bookmark_1',
        entityKind: 'bookmark',
      },
    );
    const tube = await keyring.encryptDomainEntity(
      new TextEncoder().encode('tube body'),
      {
        accountId: 'acct_grant',
        scope: 'curbtube',
        entityId: 'video_1',
        entityKind: 'watch_room',
      },
    );
    const recipient = await generateDeviceKeypair();
    const grant = await keyring.sealAuthorizedDomainGrant({
      scopes: ['curbpage', 'shared-vault'],
      recipientPublicKey: recipient.publicKey,
      deviceId: 'device-page',
    });
    const opened = await openAuthorizedDomainKeys({
      grant,
      recipientPrivateKey: recipient.privateKey,
      recipientPublicKey: recipient.publicKey,
      senderPublicKey: base64ToBytes(keyring.getIdentityPublicKey() ?? ''),
    });

    const reader = new Keyring();
    reader.importGrantedDomainKeys(opened);
    expect(new TextDecoder().decode(await reader.decryptEntity(page))).toBe(
      'page body',
    );
    await expect(reader.decryptEntity(tube)).rejects.toThrow();
    expect(new TextDecoder().decode(await keyring.decryptEntity(page))).toBe(
      'page body',
    );
    expect(new TextDecoder().decode(await keyring.decryptEntity(tube))).toBe(
      'tube body',
    );

    wipe(recipient.privateKey);
    for (const secret of opened) wipe(secret.key);
    keyring.lock();
  });
});
