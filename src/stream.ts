import { randomBytes } from './aes';
import { bytesToBase64 } from './base64';
import type { EncryptedEnvelopeV2 } from './envelope';
import { xchachaDecrypt, xchachaEncrypt } from './xchacha';

const STREAM_PREFIX = new TextEncoder().encode('curbapps/stream/v2\0');

export interface ChunkedCiphertext {
  version: 2;
  algorithm: 'XCHACHA20-POLY1305';
  chunkSize: number;
  chunks: EncryptedEnvelopeV2[];
}

function encodeU32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, value, false);
  return bytes;
}

function streamAad(
  context: Uint8Array,
  index: number,
  isLast: boolean,
): Uint8Array {
  const flag = new Uint8Array([isLast ? 1 : 0]);
  const out = new Uint8Array(STREAM_PREFIX.length + context.length + 4 + 1);
  out.set(STREAM_PREFIX, 0);
  out.set(context, STREAM_PREFIX.length);
  out.set(encodeU32(index), STREAM_PREFIX.length + context.length);
  out.set(flag, STREAM_PREFIX.length + context.length + 4);
  return out;
}

export async function encryptChunked(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  options: { context: Uint8Array; chunkSize?: number; keyId?: string },
): Promise<ChunkedCiphertext> {
  const chunkSize = options.chunkSize ?? 64 * 1024;
  if (chunkSize < 1) {
    throw new Error('chunkSize must be at least 1');
  }
  const keyId = options.keyId ?? 'attachment-chunk';
  const chunks: EncryptedEnvelopeV2[] = [];
  if (plaintext.length === 0) {
    chunks.push(
      await xchachaEncrypt(plaintext, keyBytes, {
        keyId,
        aad: streamAad(options.context, 0, true),
      }),
    );
    return {
      version: 2,
      algorithm: 'XCHACHA20-POLY1305',
      chunkSize,
      chunks,
    };
  }

  const total = Math.ceil(plaintext.length / chunkSize);
  for (let index = 0; index < total; index++) {
    const start = index * chunkSize;
    const end = Math.min(plaintext.length, start + chunkSize);
    chunks.push(
      await xchachaEncrypt(plaintext.subarray(start, end), keyBytes, {
        keyId,
        aad: streamAad(options.context, index, index === total - 1),
      }),
    );
  }
  return {
    version: 2,
    algorithm: 'XCHACHA20-POLY1305',
    chunkSize,
    chunks,
  };
}

export async function decryptChunked(
  ciphertext: ChunkedCiphertext,
  keyBytes: Uint8Array,
  context: Uint8Array,
): Promise<Uint8Array> {
  if (ciphertext.version !== 2 || ciphertext.chunks.length === 0) {
    throw new Error('Invalid chunked ciphertext');
  }
  const parts: Uint8Array[] = [];
  for (let index = 0; index < ciphertext.chunks.length; index++) {
    const isLast = index === ciphertext.chunks.length - 1;
    const chunk = ciphertext.chunks[index];
    if (!chunk) {
      throw new Error('Missing ciphertext chunk');
    }
    const expectedAad = bytesToBase64(streamAad(context, index, isLast));
    if (chunk.aadBase64 !== expectedAad) {
      throw new Error('Chunk AAD mismatch');
    }
    parts.push(await xchachaDecrypt(chunk, keyBytes));
  }
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function randomStreamContext(bytes = 16): Uint8Array {
  return randomBytes(bytes);
}
