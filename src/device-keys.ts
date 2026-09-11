import { x25519 } from '@noble/curves/ed25519.js';

import { base64ToBytes, bytesToBase64 } from './base64';

const DEVICE_KEY_BYTES = 32;

export interface DeviceKeypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export async function generateDeviceKeypair(): Promise<DeviceKeypair> {
  const { secretKey, publicKey } = x25519.keygen();
  return { privateKey: secretKey, publicKey };
}

/**
 * Reconstruct a device keypair from its raw 32-byte private key,
 * deriving the public key.
 */
export function importDevicePrivateKey(bytes: Uint8Array): DeviceKeypair {
  if (bytes.length !== DEVICE_KEY_BYTES) {
    throw new Error('device private key must be 32 bytes');
  }
  return { privateKey: bytes, publicKey: x25519.getPublicKey(bytes) };
}

export function publicKeyToBase64(publicKey: Uint8Array): string {
  return bytesToBase64(publicKey);
}

export function publicKeyFromBase64(base64: string): Uint8Array {
  return base64ToBytes(base64);
}

export function privateKeyToBase64(privateKey: Uint8Array): string {
  return bytesToBase64(privateKey);
}

export function privateKeyFromBase64(base64: string): Uint8Array {
  return base64ToBytes(base64);
}
