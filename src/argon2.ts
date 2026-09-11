import { argon2id } from '@noble/hashes/argon2.js';

import { randomBytes } from './aes';

export interface Argon2Params {
  /** Memory cost in kibibytes. */
  memoryKb: number;
  /** Time cost (number of iterations). */
  iterations: number;
  /** Degree of parallelism. */
  parallelism: number;
  /** Output key length in bytes. */
  hashLength: number;
}

/**
 * OWASP password storage cheat sheet floor for Argon2id:
 * m=19 MiB (19456 KiB), t=2, p=1, 32-byte output.
 *
 * New keyrings use these values. Unlock rejects anything weaker so a swapped
 * recovery blob cannot downgrade the stretch.
 */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memoryKb: 19456,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
};

export const ARGON2_UNLOCK_FLOOR: Argon2Params = DEFAULT_ARGON2_PARAMS;

export function generateSalt(bytes = 16): Uint8Array {
  return randomBytes(bytes);
}

/** Upper bounds that keep a malicious persisted KDF descriptor from causing OOM or an unbounded hang during unlock. */
const MAX_MEMORY_KIB = 1 << 20; // 1 GiB
const MAX_ITERATIONS = 100;
const MAX_PARALLELISM = 16;
const MASTER_KEY_BYTES = 32;
const STRUCTURAL_MIN_MEMORY_KIB = 8;

/**
 * Validate Argon2id parameters. Enforces a 32-byte output (the master key is
 * used as an AES-256 key) and bounds on cost so a corrupted recovery blob
 * cannot trigger an out-of-memory or multi-minute hang during unlock.
 */
export function assertValidArgon2Params(params: Argon2Params): Argon2Params {
  if (
    !Number.isInteger(params.memoryKb) ||
    params.memoryKb < STRUCTURAL_MIN_MEMORY_KIB ||
    params.memoryKb > MAX_MEMORY_KIB
  ) {
    throw new Error(
      `argon2: memoryKb must be an integer in [${STRUCTURAL_MIN_MEMORY_KIB}, ${MAX_MEMORY_KIB}]`,
    );
  }
  if (
    !Number.isInteger(params.iterations) ||
    params.iterations < 1 ||
    params.iterations > MAX_ITERATIONS
  ) {
    throw new Error(
      `argon2: iterations must be an integer in [1, ${MAX_ITERATIONS}]`,
    );
  }
  if (
    !Number.isInteger(params.parallelism) ||
    params.parallelism < 1 ||
    params.parallelism > MAX_PARALLELISM
  ) {
    throw new Error(
      `argon2: parallelism must be an integer in [1, ${MAX_PARALLELISM}]`,
    );
  }
  if (params.hashLength !== MASTER_KEY_BYTES) {
    throw new Error(
      `argon2: hashLength must be ${MASTER_KEY_BYTES} bytes for a master key`,
    );
  }
  return params;
}

/**
 * Reject KDF descriptors weaker than the published floor. Used on unlock and
 * on any wrap that will be persisted as account recovery material.
 */
export function assertArgon2UnlockParams(params: Argon2Params): Argon2Params {
  const valid = assertValidArgon2Params(params);
  if (
    valid.memoryKb < ARGON2_UNLOCK_FLOOR.memoryKb ||
    valid.iterations < ARGON2_UNLOCK_FLOOR.iterations ||
    valid.parallelism < ARGON2_UNLOCK_FLOOR.parallelism
  ) {
    throw new Error(
      `argon2: parameters are below the unlock floor (m>=${ARGON2_UNLOCK_FLOOR.memoryKb}, t>=${ARGON2_UNLOCK_FLOOR.iterations}, p>=${ARGON2_UNLOCK_FLOOR.parallelism})`,
    );
  }
  return valid;
}

export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params?: Partial<Argon2Params>,
): Promise<Uint8Array> {
  const merged = assertValidArgon2Params({
    memoryKb: params?.memoryKb ?? DEFAULT_ARGON2_PARAMS.memoryKb,
    iterations: params?.iterations ?? DEFAULT_ARGON2_PARAMS.iterations,
    parallelism: params?.parallelism ?? DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: params?.hashLength ?? DEFAULT_ARGON2_PARAMS.hashLength,
  });

  return argon2id(password, salt, {
    t: merged.iterations,
    m: merged.memoryKb,
    p: merged.parallelism,
    dkLen: merged.hashLength,
  });
}

export async function deriveUnlockMasterKey(
  password: string,
  salt: Uint8Array,
  params?: Partial<Argon2Params>,
): Promise<Uint8Array> {
  const merged = assertArgon2UnlockParams({
    memoryKb: params?.memoryKb ?? DEFAULT_ARGON2_PARAMS.memoryKb,
    iterations: params?.iterations ?? DEFAULT_ARGON2_PARAMS.iterations,
    parallelism: params?.parallelism ?? DEFAULT_ARGON2_PARAMS.parallelism,
    hashLength: params?.hashLength ?? DEFAULT_ARGON2_PARAMS.hashLength,
  });
  return deriveMasterKey(password, salt, merged);
}
