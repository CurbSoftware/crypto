import { asAccountKey, type AccountKey } from './opaque';
import { base64ToBytes, bytesToBase64 } from './base64';

/**
 * Host-owned persistence for an auto-unlock Account Encryption Key.
 *
 * This package never writes `autoUnlockAekBase64` itself. Extensions typically
 * store the encoded key in `browser.storage.local` (readable to anyone with
 * the browser profile). Mobile should use the OS keychain. The web dashboard
 * should keep the AEK in memory after a recovery-blob unlock.
 */
export interface SecureAekStore {
  save(aek: AccountKey): Promise<void>;
  load(): Promise<AccountKey | null>;
  clear(): Promise<void>;
}

export function encodeAekForStore(aek: AccountKey): string {
  return bytesToBase64(aek);
}

export function decodeAekFromStore(value: string): AccountKey {
  return asAccountKey(base64ToBytes(value));
}

export function createMemoryAekStore(): SecureAekStore {
  let stored: AccountKey | null = null;
  return {
    async save(aek) {
      stored = asAccountKey(new Uint8Array(aek));
    },
    async load() {
      return stored ? asAccountKey(new Uint8Array(stored)) : null;
    },
    async clear() {
      stored?.fill(0);
      stored = null;
    },
  };
}
