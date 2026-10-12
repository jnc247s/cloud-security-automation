import { expect, type Page, type Request } from '@playwright/test';
import { isPage, type ScanPage } from '../src/api';

// A secondary cleanup failure must not replace the original failed assertion.
// Cleanup failure alone still fails; neither path can turn a failure into success.
export async function runWithHistoryCleanup(body: () => Promise<void>, cleanup: () => Promise<void>): Promise<void> {
  let bodyFailed = false;
  let primaryError: unknown;
  try { await body(); }
  catch (error) { bodyFailed = true; primaryError = error; }
  let cleanupFailed = false;
  let cleanupError: unknown;
  try { await cleanup(); }
  catch (error) { cleanupFailed = true; cleanupError = error; }
  if (bodyFailed) {
    if (cleanupFailed) {
      try { console.warn('Owned history cleanup also failed; the original test failure is preserved.'); }
      catch { /* Diagnostic failure must not replace the already-failed body either. */ }
    }
    throw primaryError;
  }
  if (cleanupFailed) throw cleanupError;
}

// A pagination response is not a settled UI. Keep subsequent native interactions
// after the exact current page is rendered, not across its asynchronous relayout.
export async function turnHistoryPage(page: Page, direction: 'Next page' | 'Previous page', offset: number): Promise<ScanPage> {
  const origin = new URL(page.url()).origin;
  const started = new Set<Request>();
  function record(request: Request) {
    const url = new URL(request.url());
    if (request.method() === 'GET' && url.origin === origin
      && url.pathname === '/dashboard/api/scans'
      && url.search === `?limit=25&offset=${offset}`) started.add(request);
  }
  page.on('request', record);
  const received = page.waitForResponse(response => started.has(response.request()));
  try {
    const [, response] = await Promise.all([
      page.getByRole('button', { name: direction, exact: true }).click(), received
    ]);
    expect(response.status()).toBe(200);
    const value: unknown = await response.json();
    if (!isPage(value)) throw new Error('The current scan-history response is unsupported.');
    expect(value.limit).toBe(25);
    expect(value.offset).toBe(offset);
    expect(value.items.length).toBeLessThanOrEqual(25);
    const history = page.getByRole('region', { name: 'Scan history', exact: true });
    await expect(history.locator('.scans li')).toHaveCount(value.items.length);
    await expect(history.locator('.scans .mono')).toHaveText(value.items.map(scan => scan.scan_id));
    await expect(history.getByText('Loading scan history…', { exact: true })).toHaveCount(0);
    return value;
  } finally { page.off('request', record); }
}
