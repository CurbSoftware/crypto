import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { bytesToHex, wipe } from './wipe';

const LOOKUP_INFO = new TextEncoder().encode('curbapps/lookup/v1');

/**
 * Deterministic HMAC-SHA256 lookup digest.
 *
 * The AEK is HKDF-expanded first so lookup material is not the encryption key.
 */
export function hmacLookup(aek: Uint8Array, message: string): string {
  const lookupKey = hkdf(sha256, aek, undefined, LOOKUP_INFO, 32);
  const digest = hmac(sha256, lookupKey, new TextEncoder().encode(message));
  wipe(lookupKey);
  return bytesToHex(digest);
}
