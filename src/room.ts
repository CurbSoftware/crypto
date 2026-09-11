import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { aesGcmDecrypt, aesGcmEncrypt, randomBytes } from './aes';
import { base64ToBytes, bytesToBase64 } from './base64';
import {
  generateDeviceKeypair,
  publicKeyFromBase64,
  publicKeyToBase64,
} from './device-keys';
import {
  unwrapKeyForRecipient,
  wrapKeyForRecipient,
  type EcdhWrapContext,
} from './ecdh';
import type { EncryptedEnvelopeV1 } from './envelope';
import { asRoomKey, type RoomKey } from './opaque';
import { constantTimeEqual, wipe } from './wipe';

const ROOM_KEY_BYTES = 32;
const ROOM_CONTENT_ALGORITHM = 'CURBROOM-AES-GCM-256';
const WRAPPED_KEY_ALGORITHM = 'ECDH-P256-AES-GCM-256';
const WRAPPED_KEY_ALGORITHM_V2 = 'ECDH-X25519-AES-KW-256';
const KEY_VERIFIER_CONTEXT = 'curbapps/watch-room/key-verifier/v1';
const ROOM_CONTENT_KEY_ID = 'room-content';

export interface RoomEcdhKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBase64: string;
}

export interface RoomX25519KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyBase64: string;
}

interface RoomContentEnvelope {
  version: 1;
  algorithm: typeof ROOM_CONTENT_ALGORITHM;
  ivBase64: string;
  ciphertextBase64: string;
}

interface WrappedRoomKeyEnvelope {
  version: 1;
  algorithm: typeof WRAPPED_KEY_ALGORITHM;
  ivBase64: string;
  ciphertextBase64: string;
}

interface WrappedRoomKeyEnvelopeV2 {
  version: 2;
  algorithm: typeof WRAPPED_KEY_ALGORITHM_V2;
  wrappedKeyBase64: string;
  senderPublicKeyBase64: string;
}

function parseEnvelope<T extends { version: number; algorithm: string }>(
  serialized: string,
  algorithm: string,
): T {
  const parsed = JSON.parse(serialized) as Partial<T>;
  if (parsed.algorithm !== algorithm) {
    throw new Error('Unsupported room encryption envelope');
  }
  return parsed as T;
}

async function importRoomKey(
  roomKey: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  if (roomKey.byteLength !== ROOM_KEY_BYTES) {
    throw new Error('Room key must be 32 bytes');
  }
  return crypto.subtle.importKey(
    'raw',
    new Uint8Array(roomKey),
    { name: 'AES-GCM' },
    false,
    usages,
  );
}

export function generateRoomKey(): RoomKey {
  return asRoomKey(randomBytes(ROOM_KEY_BYTES));
}

export async function encryptRoomContent(
  roomKey: Uint8Array,
  plaintext: string,
): Promise<string> {
  const envelope = await aesGcmEncrypt(
    new TextEncoder().encode(plaintext),
    roomKey,
    { keyId: ROOM_CONTENT_KEY_ID },
  );
  return JSON.stringify(envelope);
}

export async function decryptRoomContent(
  roomKey: Uint8Array | null,
  serialized: string | undefined,
): Promise<string | undefined> {
  if (!roomKey || !serialized) return undefined;
  try {
    const parsed = JSON.parse(serialized) as {
      version?: unknown;
      algorithm?: unknown;
    };
    if (parsed.algorithm === 'AES-GCM-256' && parsed.version === 1) {
      const bytes = await aesGcmDecrypt(parsed as EncryptedEnvelopeV1, roomKey);
      return new TextDecoder().decode(bytes);
    }

    const envelope = parseEnvelope<RoomContentEnvelope>(
      serialized,
      ROOM_CONTENT_ALGORITHM,
    );
    const key = await importRoomKey(roomKey, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(base64ToBytes(envelope.ivBase64)) },
      key,
      new Uint8Array(base64ToBytes(envelope.ciphertextBase64)),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return undefined;
  }
}

export async function generateRoomEcdhKeyPair(): Promise<RoomEcdhKeyPair> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );
  const publicKey = await crypto.subtle.exportKey('spki', pair.publicKey);
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicKeyBase64: bytesToBase64(new Uint8Array(publicKey)),
  };
}

export async function generateRoomX25519KeyPair(): Promise<RoomX25519KeyPair> {
  const pair = await generateDeviceKeypair();
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicKeyBase64: publicKeyToBase64(pair.publicKey),
  };
}

export async function deriveRoomHandshakeKey(
  privateKey: CryptoKey,
  peerPublicKeyBase64: string,
): Promise<CryptoKey> {
  const peerPublicKey = await crypto.subtle.importKey(
    'spki',
    new Uint8Array(base64ToBytes(peerPublicKeyBase64)),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPublicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapRoomKey(
  roomKey: Uint8Array,
  handshakeKey: CryptoKey,
): Promise<string> {
  if (roomKey.byteLength !== ROOM_KEY_BYTES) {
    throw new Error('Room key must be 32 bytes');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    handshakeKey,
    new Uint8Array(roomKey),
  );
  const envelope: WrappedRoomKeyEnvelope = {
    version: 1,
    algorithm: WRAPPED_KEY_ALGORITHM,
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(ciphertext)),
  };
  return JSON.stringify(envelope);
}

export async function unwrapRoomKey(
  serialized: string,
  handshakeKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> {
  const envelope = parseEnvelope<WrappedRoomKeyEnvelope>(
    serialized,
    WRAPPED_KEY_ALGORITHM,
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64ToBytes(envelope.ivBase64)) },
    handshakeKey,
    new Uint8Array(base64ToBytes(envelope.ciphertextBase64)),
  );
  const roomKey = new Uint8Array(plaintext);
  if (roomKey.byteLength !== ROOM_KEY_BYTES) {
    throw new Error('Wrapped room key has an invalid length');
  }
  return roomKey;
}

export async function wrapRoomKeyForPeer(
  roomKey: Uint8Array,
  myPriv: Uint8Array,
  myPub: Uint8Array,
  theirPub: Uint8Array,
  context: EcdhWrapContext,
): Promise<string> {
  const wrapped = await wrapKeyForRecipient(
    roomKey,
    myPriv,
    theirPub,
    context,
    myPub,
  );
  const envelope: WrappedRoomKeyEnvelopeV2 = {
    version: 2,
    algorithm: WRAPPED_KEY_ALGORITHM_V2,
    wrappedKeyBase64: bytesToBase64(wrapped),
    senderPublicKeyBase64: publicKeyToBase64(myPub),
  };
  return JSON.stringify(envelope);
}

export async function unwrapRoomKeyFromPeer(
  serialized: string,
  myPriv: Uint8Array,
  myPub: Uint8Array,
  context: EcdhWrapContext,
): Promise<RoomKey> {
  const envelope = JSON.parse(serialized) as WrappedRoomKeyEnvelopeV2;
  if (
    envelope.version !== 2 ||
    envelope.algorithm !== WRAPPED_KEY_ALGORITHM_V2
  ) {
    throw new Error('Unsupported room key wrap');
  }
  const senderPub = publicKeyFromBase64(envelope.senderPublicKeyBase64);
  const unwrapped = await unwrapKeyForRecipient(
    base64ToBytes(envelope.wrappedKeyBase64),
    myPriv,
    senderPub,
    context,
    myPub,
  );
  return asRoomKey(unwrapped);
}

export async function buildRoomKeyVerifier(
  roomKey: Uint8Array,
): Promise<string> {
  if (roomKey.byteLength !== ROOM_KEY_BYTES) {
    throw new Error('Room key must be 32 bytes');
  }
  const signature = hmac(
    sha256,
    roomKey,
    new TextEncoder().encode(KEY_VERIFIER_CONTEXT),
  );
  return bytesToBase64(signature);
}

export async function verifyRoomKey(
  roomKey: Uint8Array,
  expectedVerifier: string,
): Promise<boolean> {
  const actual = await buildRoomKeyVerifier(roomKey);
  const a = new TextEncoder().encode(actual);
  const b = new TextEncoder().encode(expectedVerifier);
  const ok = constantTimeEqual(a, b);
  wipe(a);
  wipe(b);
  return ok;
}

export function roomKeyToBase64(roomKey: Uint8Array): string {
  if (roomKey.byteLength !== ROOM_KEY_BYTES) {
    throw new Error('Room key must be 32 bytes');
  }
  return bytesToBase64(roomKey);
}

export function roomKeyFromBase64(value: string): RoomKey {
  const roomKey = base64ToBytes(value);
  return asRoomKey(roomKey);
}
