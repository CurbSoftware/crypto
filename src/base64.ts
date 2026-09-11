/**
 * Platform-independent base64 codec over `Uint8Array`.
 *
 * `btoa`/`atob` are not available on every target this package ships to
 * (notably React Native / Hermes), so we provide a small dependency-free
 * implementation that produces the standard RFC 4648 alphabet with padding.
 */

const B64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const B64_DECODE = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++) {
    table[B64_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

const B64_PAD = 61; // '='

function decodeChar(code: number): number {
  if (code >= 0 && code < 128) {
    const value = B64_DECODE[code];
    if (value !== undefined && value >= 0) {
      return value;
    }
  }
  throw new Error('base64ToBytes: invalid character');
}

export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;

    out += B64_ALPHABET.charAt((n >>> 18) & 63);
    out += B64_ALPHABET.charAt((n >>> 12) & 63);
    out += i + 1 < bytes.length ? B64_ALPHABET.charAt((n >>> 6) & 63) : '=';
    out += i + 2 < bytes.length ? B64_ALPHABET.charAt(n & 63) : '=';
  }
  return out;
}

export function base64ToBytes(base64: string): Uint8Array {
  const input = base64.replace(/\s+/g, '');
  if (input.length === 0) {
    return new Uint8Array(0);
  }
  if (input.length % 4 !== 0) {
    throw new Error('base64ToBytes: input length must be a multiple of 4');
  }

  // Determine trailing padding and reject '=' anywhere else.
  let padding = 0;
  if (input.charCodeAt(input.length - 1) === B64_PAD) {
    padding = 1;
    if (input.charCodeAt(input.length - 2) === B64_PAD) {
      padding = 2;
    }
  }
  for (let i = 0; i < input.length - padding; i++) {
    if (input.charCodeAt(i) === B64_PAD) {
      throw new Error('base64ToBytes: invalid padding placement');
    }
  }

  const outputLength = (input.length / 4) * 3 - padding;
  const out = new Uint8Array(outputLength);

  let outPos = 0;
  let lastC1 = 0;
  let lastC2 = 0;
  for (let i = 0; i < input.length; i += 4) {
    const c0 = decodeChar(input.charCodeAt(i));
    const c1 = decodeChar(input.charCodeAt(i + 1));
    const c2Code = input.charCodeAt(i + 2);
    const c3Code = input.charCodeAt(i + 3);
    const c2 = c2Code === B64_PAD ? 0 : decodeChar(c2Code);
    const c3 = c3Code === B64_PAD ? 0 : decodeChar(c3Code);
    const n = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;

    lastC1 = c1;
    lastC2 = c2;

    if (outPos < out.length) {
      out[outPos++] = (n >>> 16) & 0xff;
    }
    if (outPos < out.length) {
      out[outPos++] = (n >>> 8) & 0xff;
    }
    if (outPos < out.length) {
      out[outPos++] = n & 0xff;
    }
  }

  // Reject non-canonical padding: the unused low bits must be zero.
  if (padding === 2 && (lastC1 & 0x0f) !== 0) {
    throw new Error('base64ToBytes: non-canonical padding');
  }
  if (padding === 1 && (lastC2 & 0x03) !== 0) {
    throw new Error('base64ToBytes: non-canonical padding');
  }

  return out;
}
