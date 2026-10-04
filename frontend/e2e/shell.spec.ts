import { test, expect, type Page } from '@playwright/test';

async function login(page: Page, role = 'VIEWER', subject = 'test-reader') {
  await page.goto('/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: /Controlled local issuer/ })).toBeVisible();
  await page.getByLabel('Test role').selectOption(role);
  await page.getByLabel('Test subject').selectOption(subject);
  await page.getByRole('button', { name: 'Approve test login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}
async function openScan(page: Page, id: string) {
  await page.getByLabel('Open scan by UUID').fill(id);
  await page.getByRole('button', { name: 'Open scan', exact: true }).click();
}

for (const role of ['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN']) {
  test(`${role}: real signed login → bearer API → PostgreSQL → exact scan`, async ({ page, context }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await login(page, role);
    await expect(page.getByText(`test-reader · ${role}`)).toBeVisible();
    const id = '11111111-1111-1111-1111-111111111111';
    await openScan(page, id);
    await expect(page.locator('dd').filter({ hasText: /^AVAILABLE$/ })).toBeVisible();
    await expect(page.locator('dd').filter({ hasText: /^COMPLETED$/ })).toBeVisible();
    await expect(page.getByText('test-network / 1.0.0')).toBeVisible();
    await page.reload();
    await expect(page.locator('dd').filter({ hasText: /^AVAILABLE$/ })).toBeVisible();
    expect(page.url()).not.toContain('code=');
    expect(page.url()).not.toContain('access_token');
    expect((await context.request.get('/api/v1/scans')).status()).toBe(401);
    expect((await context.request.post('/dashboard/api/scans', { data: {} })).status()).toBe(405);
    const status = await (await context.request.get('/dashboard/session')).json();
    expect(status).not.toHaveProperty('access_token');
    const cookies = await context.cookies();
    const session = cookies.find(cookie => cookie.name === 'cloudsec_session')!;
    expect(session.httpOnly).toBe(true); expect(session.sameSite).toBe('Strict');
    expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })))
      .toEqual({ local: 0, session: 0 });
    expect((await context.request.post('/dashboard/auth/logout', { headers: { Origin: 'http://attacker.test', 'X-CSRF-Token': status.csrf_token } })).status()).toBe(403);
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await expect(page.getByText(id)).toHaveCount(0);
    expect((await context.request.get('/dashboard/api/scans')).status()).toBe(401);
    expect(errors).toEqual([]);
  });
}

test('bounded pages, partial/running/failed lifecycle, navigation and missing scan', async ({ page }) => {
  await login(page);
  await expect(page.getByRole('button', { name: 'Next page' })).toBeEnabled();
  await page.getByRole('button', { name: 'Next page' }).click();
  await expect(page.getByRole('button', { name: 'Previous page' })).toBeEnabled();
  await openScan(page, '22222222-2222-2222-2222-222222222222');
  await expect(page.locator('dd').filter({ hasText: /^PARTIAL$/ })).toBeVisible();
  await expect(page.getByText(/Collection has gaps or failures/)).toBeVisible();
  await openScan(page, '11111111-1111-1111-1111-111111111111');
  await expect(page.locator('dd').filter({ hasText: /^COMPLETED$/ })).toBeVisible();
  await page.goBack();
  await expect(page.locator('dd').filter({ hasText: /^PARTIAL$/ })).toBeVisible();
  await openScan(page, '99999999-9999-9999-9999-999999999999');
  await expect(page.getByRole('alert')).toHaveText(/unavailable or no longer exists/);
  await openScan(page, 'latest');
  await expect(page.getByRole('alert')).toHaveText(/valid scan UUID/);
  await page.getByRole('button', { name: 'Previous page' }).click();
  const session = await (await page.request.get('/dashboard/session')).json();
  const scans = await (await page.request.get('/dashboard/api/scans?limit=100',
    { headers: { 'X-Dashboard-Context': session.session_context } })).json();
  for (const status of ['RUNNING', 'FAILED']) {
    const scan = scans.items.find((s: { status: string }) => s.status === status);
    await openScan(page, scan.scan_id);
    await expect(page.locator('dd').filter({ hasText: new RegExp(`^${status}$`) })).toBeVisible();
    await expect(page.getByText(status === 'RUNNING' ? /counts are unavailable, not zero/ : /not a passing assessment/)).toBeVisible();
  }
});

test('expiry clears context, keyboard controls and mobile layout', async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  await page.getByLabel('Open scan by UUID').focus();
  await page.keyboard.type('11111111-1111-1111-1111-111111111111');
  await page.keyboard.press('Enter');
  await expect(page.locator('dd').filter({ hasText: /^AVAILABLE$/ })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.getByRole('button', { name: 'Next page' })).toBeEnabled();
  await expect(page.getByRole('button', { name: /Open assessment/ })).toBeVisible();
  const beforeExpiry = await (await context.request.get('/dashboard/session')).json();
  expect(beforeExpiry.authenticated).toBe(true);
  // Dispatch the refresh while authenticated; expire before its real BFF read is forwarded.
  // A concurrent 401 may correctly unmount the button, so never click after forcing expiry.
  let completeExpiry!: () => void;
  let failExpiry!: (error: unknown) => void;
  const expiryCompleted = new Promise<void>((resolve, reject) => { completeExpiry = resolve; failExpiry = reject; });
  await page.route('**/dashboard/api/scans?*', async route => {
    try {
      expect((await context.request.post('http://127.0.0.1:9012/expire-dashboard-sessions')).status()).toBe(200);
      completeExpiry();
    } catch (error) { failExpiry(error); throw error; }
    await route.continue();
  }, { times: 1 });
  const denied = page.waitForResponse(response => response.request().method() === 'GET'
    && response.url().includes('/dashboard/api/') && response.status() === 401);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  // Parallel reads may detect server expiry before the expiry POST response reaches this client.
  await expiryCompleted;
  expect((await denied).status()).toBe(401);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.getByText('test-network / 1.0.0')).toHaveCount(0);
  expect((await context.request.get('/dashboard/api/scans',
    { headers: { 'X-Dashboard-Context': beforeExpiry.session_context } })).status()).toBe(401);
  expect((await context.request.get('/api/v1/scans')).status()).toBe(401);
});

test('two tabs clear immediately on logout and cannot read under a replacement identity', async ({ page, context }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page, 'VIEWER', 'test-reader-A');
  const oldSession = await (await context.request.get('/dashboard/session')).json();
  await openScan(page, '11111111-1111-1111-1111-111111111111');
  await expect(page.locator('dd').filter({ hasText: /^AVAILABLE$/ })).toBeVisible();
  const other = await context.newPage();
  other.on('pageerror', error => errors.push(error.message));
  await other.goto('/dashboard/');
  await expect(other.getByText('test-reader-A · VIEWER')).toBeVisible();
  // Opening a tab with the same session must not reset the existing selected report.
  await expect(page.getByText('test-network / 1.0.0')).toBeVisible();
  let releaseLogout!: () => void;
  const logoutGate = new Promise<void>(resolve => { releaseLogout = resolve; });
  await other.route('**/dashboard/auth/logout', async route => { await logoutGate; await route.continue(); });
  await other.getByRole('button', { name: 'Sign out' }).click();
  // Both tabs clear while the logout HTTP request is still deliberately blocked.
  await expect(page.getByText('test-reader-A · VIEWER')).toHaveCount(0);
  await expect(page.getByText('test-network / 1.0.0')).toHaveCount(0);
  await expect(other.getByText('test-reader-A · VIEWER')).toHaveCount(0);
  releaseLogout();
  await expect(other.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await login(other, 'VIEWER', 'test-reader-B');
  await expect(page.getByText('test-reader-B · VIEWER')).toBeVisible();
  await expect(page.getByText('test-reader-A · VIEWER')).toHaveCount(0);
  const mismatch = await context.request.get('/dashboard/api/scans',
    { headers: { 'X-Dashboard-Context': oldSession.session_context } });
  expect(mismatch.status()).toBe(401); expect(await mismatch.json()).not.toHaveProperty('items');
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByText('test-network / 1.0.0')).toBeVisible();
  await expect(page.getByText('test-reader-B · VIEWER')).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })))
    .toEqual({ local: 0, session: 0 });
  expect(errors).toEqual([]);
});
