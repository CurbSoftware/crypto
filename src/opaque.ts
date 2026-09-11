const MASTER_KEY_BRAND = Symbol('MasterKey');
const ACCOUNT_KEY_BRAND = Symbol('AccountKey');
const ROOM_KEY_BRAND = Symbol('RoomKey');
const SHARE_KEY_BRAND = Symbol('ShareKey');

export type MasterKey = Uint8Array & {
  readonly [MASTER_KEY_BRAND]: 'MasterKey';
};
export type AccountKey = Uint8Array & {
  readonly [ACCOUNT_KEY_BRAND]: 'AccountKey';
};
export type RoomKey = Uint8Array & { readonly [ROOM_KEY_BRAND]: 'RoomKey' };
export type ShareKey = Uint8Array & { readonly [SHARE_KEY_BRAND]: 'ShareKey' };

const KEY_BYTES = 32;

function assertKeyBytes(bytes: Uint8Array, label: string): void {
  if (bytes.length !== KEY_BYTES) {
    throw new Error(`${label} must be ${KEY_BYTES} bytes`);
  }
}

export function asMasterKey(bytes: Uint8Array): MasterKey {
  assertKeyBytes(bytes, 'MasterKey');
  return bytes as MasterKey;
}

export function asAccountKey(bytes: Uint8Array): AccountKey {
  assertKeyBytes(bytes, 'AccountKey');
  return bytes as AccountKey;
}

export function asRoomKey(bytes: Uint8Array): RoomKey {
  assertKeyBytes(bytes, 'RoomKey');
  return bytes as RoomKey;
}

export function asShareKey(bytes: Uint8Array): ShareKey {
  assertKeyBytes(bytes, 'ShareKey');
  return bytes as ShareKey;
}
