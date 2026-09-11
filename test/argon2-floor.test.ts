import { describe, expect, it } from 'vitest';

import {
  ARGON2_UNLOCK_FLOOR,
  deriveUnlockMasterKey,
  generateSalt,
} from '../src/argon2';

describe('argon2 unlock floor', () => {
  it('rejects a downgraded memory cost', async () => {
    const salt = generateSalt();
    await expect(
      deriveUnlockMasterKey('pw', salt, {
        memoryKb: 8,
        iterations: ARGON2_UNLOCK_FLOOR.iterations,
        parallelism: 1,
        hashLength: 32,
      }),
    ).rejects.toThrow('unlock floor');
  });
});
