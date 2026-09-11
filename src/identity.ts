import { ed25519 } from '@noble/curves/ed25519.js';

import { base64ToBytes, bytesToBase64 } from './base64';
import {
  type DeviceKeypair,
  generateDeviceKeypair,
  publicKeyToBase64,
} from './device-keys';
import { wipe } from './wipe';

const IDENTITY_SIGN_PREFIX = new TextEncoder().encode('curbapps/identity/v1\0');

export interface SigningKeypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface AccountIdentityDocument {
  version: 1;
  x25519PublicKeyBase64: string;
  ed25519PublicKeyBase64: string;
  signatureBase64: string;
}

export interface GeneratedAccountIdentity {
  x25519: DeviceKeypair;
  ed25519: SigningKeypair;
  document: AccountIdentityDocument;
}

function identitySignMessage(x25519PublicKey: Uint8Array): Uint8Array {
  const message = new Uint8Array(
    IDENTITY_SIGN_PREFIX.length + x25519PublicKey.length,
  );
  message.set(IDENTITY_SIGN_PREFIX, 0);
  message.set(x25519PublicKey, IDENTITY_SIGN_PREFIX.length);
  return message;
}

export function generateSigningKeypair(): SigningKeypair {
  const { secretKey, publicKey } = ed25519.keygen();
  return { privateKey: secretKey, publicKey };
}

export function createAccountIdentityDocument(
  x25519PublicKey: Uint8Array,
  signing: SigningKeypair,
): AccountIdentityDocument {
  const signature = ed25519.sign(
    identitySignMessage(x25519PublicKey),
    signing.privateKey,
  );
  return {
    version: 1,
    x25519PublicKeyBase64: publicKeyToBase64(x25519PublicKey),
    ed25519PublicKeyBase64: bytesToBase64(signing.publicKey),
    signatureBase64: bytesToBase64(signature),
  };
}

export async function generateAccountIdentity(): Promise<GeneratedAccountIdentity> {
  const x25519 = await generateDeviceKeypair();
  const signing = generateSigningKeypair();
  const document = createAccountIdentityDocument(x25519.publicKey, signing);
  return { x25519, ed25519: signing, document };
}

export function verifyAccountIdentityDocument(
  document: AccountIdentityDocument,
): boolean {
  try {
    if (document.version !== 1) return false;
    const x25519PublicKey = base64ToBytes(document.x25519PublicKeyBase64);
    const ed25519PublicKey = base64ToBytes(document.ed25519PublicKeyBase64);
    const signature = base64ToBytes(document.signatureBase64);
    if (
      x25519PublicKey.length !== 32 ||
      ed25519PublicKey.length !== 32 ||
      signature.length !== 64
    ) {
      return false;
    }
    return ed25519.verify(
      signature,
      identitySignMessage(x25519PublicKey),
      ed25519PublicKey,
    );
  } catch {
    return false;
  }
}

export function serializeAccountIdentityDocument(
  document: AccountIdentityDocument,
): string {
  return JSON.stringify({
    v: 1,
    x25519: document.x25519PublicKeyBase64,
    ed25519: document.ed25519PublicKeyBase64,
    sig: document.signatureBase64,
  });
}

export function parseAccountIdentityDocument(
  raw: string,
): AccountIdentityDocument | null {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('{')) return null;
  try {
    const parsed = JSON.parse(trimmed) as {
      v?: unknown;
      x25519?: unknown;
      ed25519?: unknown;
      sig?: unknown;
    };
    if (
      parsed.v !== 1 ||
      typeof parsed.x25519 !== 'string' ||
      typeof parsed.ed25519 !== 'string' ||
      typeof parsed.sig !== 'string'
    ) {
      return null;
    }
    const document: AccountIdentityDocument = {
      version: 1,
      x25519PublicKeyBase64: parsed.x25519,
      ed25519PublicKeyBase64: parsed.ed25519,
      signatureBase64: parsed.sig,
    };
    return verifyAccountIdentityDocument(document) ? document : null;
  } catch {
    return null;
  }
}

export function wipeIdentitySecrets(identity: GeneratedAccountIdentity): void {
  wipe(identity.x25519.privateKey);
  wipe(identity.ed25519.privateKey);
}
