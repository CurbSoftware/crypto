import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { aesKwUnwrap, aesKwWrap } from './aes';
import { wipe } from './wipe';

const ECDH_INFO_V1 = new TextEncoder().encode('curbapps-ecdh-wrap-v1');
const ECDH_INFO_V2_PREFIX = new TextEncoder().encode('curbapps/ecdh-wrap/v2\0');
const WRAPPING_KEY_BYTES = 32;

export interface EcdhWrapContext {
  purpose: string;
  grantId?: string;
  entityId?: string;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeContext(context: EcdhWrapContext): Uint8Array {
  return new TextEncoder().encode(
    `${context.purpose}\0${context.grantId ?? ''}\0${context.entityId ?? ''}`,
  );
}

/**
 * Derive a 32-byte symmetric wrapping key (KEK) from an X25519 shared secret
 * using HKDF-SHA256 with a fixed application-specific info string (legacy).
 */
export function deriveSharedWrappingKey(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
): Uint8Array {
  const sharedSecret = x25519.getSharedSecret(myPriv, theirPub);
  try {
    return hkdf(
      sha256,
      sharedSecret,
      undefined,
      ECDH_INFO_V1,
      WRAPPING_KEY_BYTES,
    );
  } finally {
    wipe(sharedSecret);
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/**
 * Derive a wrapping key bound to both public keys, a purpose, and optional ids.
 * Public keys are ordered lexicographically so both peers derive the same KEK.
 */
export function deriveSharedWrappingKeyV2(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
  myPub: Uint8Array,
  context: EcdhWrapContext,
): Uint8Array {
  const sharedSecret = x25519.getSharedSecret(myPriv, theirPub);
  const first = compareBytes(myPub, theirPub) <= 0 ? myPub : theirPub;
  const second = compareBytes(myPub, theirPub) <= 0 ? theirPub : myPub;
  const info = concatBytes(
    ECDH_INFO_V2_PREFIX,
    first,
    second,
    encodeContext(context),
  );
  try {
    return hkdf(sha256, sharedSecret, undefined, info, WRAPPING_KEY_BYTES);
  } finally {
    wipe(sharedSecret);
    wipe(info);
  }
}

/**
 * Wrap `rawKey` (e.g. a per-entity key) for delivery to another device,
 * using AES-KW under the ECDH-derived KEK.
 *
 * Pass `context` (and `myPub`) to use the transcript-bound v2 wrap. Omitting
 * them keeps the legacy v1 info string for already-issued grants.
 */
export async function wrapKeyForRecipient(
  rawKey: Uint8Array,
  myPriv: Uint8Array,
  theirPub: Uint8Array,
  context?: EcdhWrapContext,
  myPub?: Uint8Array,
): Promise<Uint8Array> {
  const kek =
    context && myPub
      ? deriveSharedWrappingKeyV2(myPriv, theirPub, myPub, context)
      : deriveSharedWrappingKey(myPriv, theirPub);
  try {
    return aesKwWrap(rawKey, kek);
  } finally {
    wipe(kek);
  }
}

/**
 * Unwrap a key that was wrapped for this device via `wrapKeyForRecipient`.
 */
export async function unwrapKeyForRecipient(
  wrapped: Uint8Array,
  myPriv: Uint8Array,
  theirPub: Uint8Array,
  context?: EcdhWrapContext,
  myPub?: Uint8Array,
): Promise<Uint8Array> {
  const kek =
    context && myPub
      ? deriveSharedWrappingKeyV2(myPriv, theirPub, myPub, context)
      : deriveSharedWrappingKey(myPriv, theirPub);
  try {
    return aesKwUnwrap(wrapped, kek);
  } finally {
    wipe(kek);
  }
}
