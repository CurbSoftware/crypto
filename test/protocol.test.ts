import { describe, expect, it } from 'vitest';

import { randomBytes } from '../src/aes';
import {
  decryptPasswordPayload,
  encryptPasswordPayload,
} from '../src/password-payload';
import { decryptChunked, encryptChunked } from '../src/stream';
import { xchachaDecrypt, xchachaEncrypt } from '../src/xchacha';
import {
  generateRoomX25519KeyPair,
  generateRoomKey,
  unwrapRoomKeyFromPeer,
  wrapRoomKeyForPeer,
  encryptRoomContent,
  decryptRoomContent,
} from '../src/room';

describe('xchacha', () => {
  it('round-trips', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('stream me');
    const envelope = await xchachaEncrypt(plaintext, key, { keyId: 'blob' });
    expect(envelope.version).toBe(2);
    expect(await xchachaDecrypt(envelope, key)).toEqual(plaintext);
  });
});

describe('stream', () => {
  it('chunks and reassembles with bound AAD', async () => {
    const key = randomBytes(32);
    const context = new TextEncoder().encode('acct|object-1');
    const plaintext = randomBytes(1500);
    const sealed = await encryptChunked(plaintext, key, {
      context,
      chunkSize: 512,
    });
    expect(sealed.chunks.length).toBe(3);
    expect(await decryptChunked(sealed, key, context)).toEqual(plaintext);
  });
});

describe('password payload', () => {
  it('encrypts with Argon2id and decrypts', async () => {
    const ciphertext = await encryptPasswordPayload(
      'project secret',
      'payload-password-ok',
    );
    expect(ciphertext.startsWith('{')).toBe(true);
    expect(JSON.parse(ciphertext).alg).toBe('argon2id-aes-gcm-256');
    expect(
      await decryptPasswordPayload(ciphertext, 'payload-password-ok'),
    ).toBe('project secret');
  });

  it('opens a legacy CryptoUtils envelope', async () => {
    const password = 'legacy-password';
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode('old note'),
    );
    const legacy = btoa(
      JSON.stringify({
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
      }),
    );
    expect(await decryptPasswordPayload(legacy, password)).toBe('old note');
  });
});

describe('room x25519 wrap', () => {
  it('wraps a room key to a peer', async () => {
    const host = await generateRoomX25519KeyPair();
    const guest = await generateRoomX25519KeyPair();
    const roomKey = generateRoomKey();
    const context = { purpose: 'watch-room', entityId: 'ABCD12' };
    const wrapped = await wrapRoomKeyForPeer(
      roomKey,
      host.privateKey,
      host.publicKey,
      guest.publicKey,
      context,
    );
    const unwrapped = await unwrapRoomKeyFromPeer(
      wrapped,
      guest.privateKey,
      guest.publicKey,
      context,
    );
    expect(unwrapped).toEqual(roomKey);
  });

  it('encrypts room content as an AES-GCM envelope', async () => {
    const roomKey = generateRoomKey();
    const encrypted = await encryptRoomContent(roomKey, 'https://v.test');
    expect(JSON.parse(encrypted).algorithm).toBe('AES-GCM-256');
    expect(await decryptRoomContent(roomKey, encrypted)).toBe('https://v.test');
  });
});
