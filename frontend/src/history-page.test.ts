import { afterEach, describe, expect, it, vi } from 'vitest';
import { runWithHistoryCleanup } from '../e2e/history-page';

afterEach(() => { vi.restoreAllMocks(); });
describe('held-history test failure preservation', () => {
  it.each([
    ['success', false, false, false], ['body failure', true, false, false],
    ['cleanup failure', false, true, false], ['both failures', true, true, false],
    ['both failures and diagnostic failure', true, true, true]
  ] as const)('%s retains the correct result and always attempts cleanup', async (_name, bodyFails, cleanupFails, warningFails) => {
    const primary = new Error('Synthetic primary assertion failure');
    const secondary = new Error('Synthetic owned cleanup failure');
    const body = vi.fn(async () => { if (bodyFails) throw primary; });
    const release = vi.fn();
    const cleanup = vi.fn(async () => { release(); if (cleanupFails) throw secondary; });
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {
      if (warningFails) throw new Error('Synthetic diagnostic failure');
    });
    const result = runWithHistoryCleanup(body, cleanup);
    if (bodyFails) await expect(result).rejects.toBe(primary);
    else if (cleanupFails) await expect(result).rejects.toBe(secondary);
    else await expect(result).resolves.toBeUndefined();
    expect(body).toHaveBeenCalledExactlyOnceWith();
    expect(cleanup).toHaveBeenCalledExactlyOnceWith();
    expect(release).toHaveBeenCalledExactlyOnceWith();
    if (bodyFails && cleanupFails) expect(warning).toHaveBeenCalledExactlyOnceWith(
      'Owned history cleanup also failed; the original test failure is preserved.');
    else expect(warning).not.toHaveBeenCalled();
  });
  it('preserves falsy thrown values instead of treating them as success', async () => {
    for (const primary of [undefined, null, false, 0, '']) {
      const cleanup = vi.fn(async () => undefined);
      await expect(runWithHistoryCleanup(async () => { throw primary; }, cleanup)).rejects.toBe(primary);
      expect(cleanup).toHaveBeenCalledExactlyOnceWith();
    }
  });
});
