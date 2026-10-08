import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  type AesGcmEngine,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesKwUnwrap,
  aesKwWrap,
  randomBytes,
} from './aes';
import { base64ToBytes, bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV1, EncryptedEnvelopeV3 } from './envelope';
import { bytesToHex, wipe } from './wipe';

export const DOMAIN_SCOPES = [
  'curbpage',
  'curbplace',
  'curbtube',
  'curbmetrics',
  'shared-vault',
] as const;

export type DomainScope = (typeof DOMAIN_SCOPES)[number];

/** Domain envelope protocol. This is not a server row revision. */
export const DOMAIN_PROTOCOL_VERSION = 1;

const DOMAIN_KEY_EPOCH = 1;
const DOMAIN_KEY_ID_PREFIX = 'dk_v1_';
const AAD_PREFIX = 'curbapps/domain-envelope/v1\0';
const KEY_ID_INFO_PREFIX = 'curbapps/domain-key-id/v1\0';
const LOOKUP_INFO_PREFIX = 'curbapps/lookup/domain/v1\0';

export interface DomainResourceBinding {
  accountId: string;
  scope: DomainScope;
  entityId: string;
  entityKind: string;
  /**
   * Client key epoch stored with the domain key. Omit to use the key's epoch.
   * This is not the server row revision, which does not exist at encrypt time.
   */
  epoch?: number;
}

export interface WrappedDomainKeyV1 {
  version: 1;
  algorithm: 'AES-KW-256';
  scope: DomainScope;
  epoch: number;
  keyId: string;
  wrappedKeyBase64: string;
}

export interface DomainKeySetV1 {
  version: 1;
  keys: WrappedDomainKeyV1[];
}

export interface DomainKeySecret {
  scope: DomainScope;
  epoch: number;
  keyId: string;
  key: Uint8Array;
}

export function isDomainScope(value: string): value is DomainScope {
  return (DOMAIN_SCOPES as readonly string[]).includes(value);
}

function assertLabel(value: string, label: string, max: number): void {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > max ||
    value.includes('\0')
  ) {
    throw new Error(`Domain binding ${label} is invalid`);
  }
}

export function assertDomainEpoch(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > 1_000_000) {
    throw new Error('Domain key epoch is invalid');
  }
  return epoch;
}

export function domainResourceAad(binding: DomainResourceBinding): Uint8Array {
  assertLabel(binding.accountId, 'accountId', 128);
  assertLabel(binding.entityId, 'entityId', 128);
  assertLabel(binding.entityKind, 'entityKind', 64);
  if (!isDomainScope(binding.scope)) {
    throw new Error('Domain binding scope is invalid');
  }
  const epoch = assertDomainEpoch(binding.epoch ?? DOMAIN_KEY_EPOCH);
  return new TextEncoder().encode(
    `${AAD_PREFIX}${binding.accountId}\0${binding.scope}\0${binding.entityId}\0${binding.entityKind}\0${epoch}\0${DOMAIN_PROTOCOL_VERSION}`,
  );
}

export function domainKeyId(
  domainKey: Uint8Array,
  scope: DomainScope,
  epoch: number,
): string {
  const info = new TextEncoder().encode(
    `${KEY_ID_INFO_PREFIX}${scope}\0${assertDomainEpoch(epoch)}`,
  );
  const identity = hkdf(sha256, domainKey, undefined, info, 16);
  try {
    return `${DOMAIN_KEY_ID_PREFIX}${bytesToHex(identity)}`;
  } finally {
    wipe(identity);
  }
}

function copyKey(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

export async function createDomainKeySet(aek: Uint8Array): Promise<{
  set: DomainKeySetV1;
  secrets: DomainKeySecret[];
}> {
  if (aek.length !== 32) {
    throw new Error('AEK must be 32 bytes');
  }

  const secrets: DomainKeySecret[] = [];
  const keys: WrappedDomainKeyV1[] = [];
  for (const scope of DOMAIN_SCOPES) {
    const key = randomBytes(32);
    const epoch = DOMAIN_KEY_EPOCH;
    const keyId = domainKeyId(key, scope, epoch);
    const wrapped = await aesKwWrap(key, aek);
    keys.push({
      version: 1,
      algorithm: 'AES-KW-256',
      scope,
      epoch,
      keyId,
      wrappedKeyBase64: bytesToBase64(wrapped),
    });
    secrets.push({ scope, epoch, keyId, key });
  }

  return { set: { version: 1, keys }, secrets };
}

function assertWrappedKey(value: WrappedDomainKeyV1, seen: Set<string>): void {
  if (
    value.version !== 1 ||
    value.algorithm !== 'AES-KW-256' ||
    !isDomainScope(value.scope) ||
    seen.has(value.scope)
  ) {
    throw new Error('Domain key set is invalid');
  }
  assertDomainEpoch(value.epoch);
  if (!value.keyId.startsWith(DOMAIN_KEY_ID_PREFIX)) {
    throw new Error('Domain key set is invalid');
  }
  const wrapped = base64ToBytes(value.wrappedKeyBase64);
  if (
    wrapped.length !== 40 ||
    bytesToBase64(wrapped) !== value.wrappedKeyBase64
  ) {
    throw new Error('Domain key set is invalid');
  }
  seen.add(value.scope);
}

export function assertDomainKeySet(set: DomainKeySetV1): void {
  if (
    set.version !== 1 ||
    !Array.isArray(set.keys) ||
    set.keys.length !== DOMAIN_SCOPES.length
  ) {
    throw new Error('Domain key set is invalid');
  }
  const seen = new Set<string>();
  for (const key of set.keys) {
    assertWrappedKey(key, seen);
  }
  if (seen.size !== DOMAIN_SCOPES.length) {
    throw new Error('Domain key set is invalid');
  }
}

export async function unwrapDomainKeySet(
  set: DomainKeySetV1,
  aek: Uint8Array,
): Promise<DomainKeySecret[]> {
  assertDomainKeySet(set);
  const secrets: DomainKeySecret[] = [];
  try {
    for (const wrappedKey of set.keys) {
      const raw = await aesKwUnwrap(
        base64ToBytes(wrappedKey.wrappedKeyBase64),
        aek,
      );
      const key = copyKey(raw);
      raw.fill(0);
      const keyId = domainKeyId(key, wrappedKey.scope, wrappedKey.epoch);
      if (keyId !== wrappedKey.keyId) {
        wipe(key);
        throw new Error('Domain key id does not match the AEK wrap');
      }
      secrets.push({
        scope: wrappedKey.scope,
        epoch: wrappedKey.epoch,
        keyId,
        key,
      });
    }
    return secrets;
  } catch (error) {
    for (const secret of secrets) wipe(secret.key);
    throw error;
  }
}

export interface DomainEncryptOptions {
  iv?: Uint8Array;
  engine?: AesGcmEngine;
}

export async function encryptDomainEnvelope(
  plaintext: Uint8Array,
  domainKey: Uint8Array,
  aek: Uint8Array,
  binding: DomainResourceBinding,
  options: DomainEncryptOptions = {},
): Promise<EncryptedEnvelopeV3> {
  if (domainKey.length !== 32) {
    throw new Error('Domain key must be 32 bytes');
  }
  const epoch = assertDomainEpoch(binding.epoch ?? DOMAIN_KEY_EPOCH);
  const keyId = domainKeyId(domainKey, binding.scope, epoch);
  const aad = domainResourceAad({ ...binding, epoch });
  const sealed = await aesGcmEncrypt(plaintext, domainKey, {
    keyId,
    aad,
    iv: options.iv,
    engine: options.engine,
  });
  if (!sealed.authTagBase64 || !sealed.aadBase64) {
    throw new Error('Domain envelope is missing its authentication tag');
  }
  const wrapped = await aesKwWrap(domainKey, aek);
  return {
    version: 3,
    algorithm: 'AES-GCM-256',
    keyId,
    scope: binding.scope,
    epoch,
    protocolVersion: DOMAIN_PROTOCOL_VERSION,
    ivBase64: sealed.ivBase64,
    ciphertextBase64: sealed.ciphertextBase64,
    authTagBase64: sealed.authTagBase64,
    aadBase64: sealed.aadBase64,
    wrappedKeyBase64: bytesToBase64(wrapped),
  };
}

function asLegacyEnvelope(envelope: EncryptedEnvelopeV3): EncryptedEnvelopeV1 {
  return {
    version: 1,
    algorithm: 'AES-GCM-256',
    keyId: envelope.keyId,
    ivBase64: envelope.ivBase64,
    ciphertextBase64: envelope.ciphertextBase64,
    authTagBase64: envelope.authTagBase64,
    aadBase64: envelope.aadBase64,
  };
}

function assertDomainEnvelope(
  envelope: EncryptedEnvelopeV3,
): DomainResourceBinding {
  if (
    envelope.version !== 3 ||
    envelope.algorithm !== 'AES-GCM-256' ||
    envelope.protocolVersion !== DOMAIN_PROTOCOL_VERSION ||
    !isDomainScope(envelope.scope)
  ) {
    throw new Error('Domain envelope does not match this protocol');
  }
  const epoch = assertDomainEpoch(envelope.epoch);
  const text = new TextDecoder().decode(base64ToBytes(envelope.aadBase64));
  const parts = text.split('\0');
  if (
    parts.length !== 7 ||
    parts[0] !== 'curbapps/domain-envelope/v1' ||
    parts[2] !== envelope.scope ||
    parts[5] !== String(epoch) ||
    parts[6] !== String(DOMAIN_PROTOCOL_VERSION)
  ) {
    throw new Error('Domain envelope AAD does not match its headers');
  }
  const accountId = parts[1];
  const entityId = parts[3];
  const entityKind = parts[4];
  if (
    accountId === undefined ||
    entityId === undefined ||
    entityKind === undefined
  ) {
    throw new Error('Domain envelope AAD does not match its headers');
  }
  const binding: DomainResourceBinding = {
    accountId,
    scope: envelope.scope,
    entityId,
    entityKind,
    epoch,
  };
  if (envelope.aadBase64 !== bytesToBase64(domainResourceAad(binding))) {
    throw new Error('Domain envelope AAD does not match its headers');
  }
  return binding;
}

export async function decryptDomainEnvelope(
  envelope: EncryptedEnvelopeV3,
  domainKey: Uint8Array,
): Promise<Uint8Array> {
  const binding = assertDomainEnvelope(envelope);
  const keyId = domainKeyId(
    domainKey,
    binding.scope,
    binding.epoch ?? DOMAIN_KEY_EPOCH,
  );
  if (keyId !== envelope.keyId) {
    throw new Error('Domain envelope does not match the supplied key');
  }
  return aesGcmDecrypt(asLegacyEnvelope(envelope), domainKey);
}

/**
 * Open a domain envelope. Uses a supplied domain key when its id matches, and
 * otherwise unwraps the AEK-wrapped copy carried on the envelope.
 */
export async function openDomainEnvelope(
  envelope: EncryptedEnvelopeV3,
  aek: Uint8Array,
  domainKeys?: ReadonlyMap<string, Uint8Array>,
): Promise<Uint8Array> {
  const supplied = domainKeys?.get(envelope.keyId);
  if (supplied) {
    return decryptDomainEnvelope(envelope, supplied);
  }

  const raw = await aesKwUnwrap(base64ToBytes(envelope.wrappedKeyBase64), aek);
  const key = copyKey(raw);
  raw.fill(0);
  try {
    return await decryptDomainEnvelope(envelope, key);
  } finally {
    wipe(key);
  }
}

/**
 * HKDF-SHA256 then HMAC-SHA256, separated from {@link hmacLookup} by scope.
 * The same domain key produces a different digest in each scope.
 */
export function hmacDomainLookup(
  domainKey: Uint8Array,
  scope: DomainScope,
  message: string,
): string {
  if (!isDomainScope(scope)) {
    throw new Error('Domain lookup scope is invalid');
  }
  const info = new TextEncoder().encode(`${LOOKUP_INFO_PREFIX}${scope}`);
  const lookupKey = hkdf(sha256, domainKey, undefined, info, 32);
  try {
    return bytesToHex(
      hmac(sha256, lookupKey, new TextEncoder().encode(message)),
    );
  } finally {
    wipe(lookupKey);
  }
}
