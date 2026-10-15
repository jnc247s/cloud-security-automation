import { expect, test, type Page } from '@playwright/test';
import { executionPage, proposalPage, verificationPage } from '../src/remediation-api';
import { runWithHistoryCleanup, turnHistoryPage } from './history-page';

async function login(page: Page, role = 'VIEWER') {
  await page.goto('/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Test role').selectOption(role);
  await page.getByRole('button', { name: 'Approve test login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}
async function read(page: Page, path: string) {
  const session = await (await page.request.get('/dashboard/session')).json();
  const response = await page.request.get('/dashboard/api/' + path, { headers: { 'X-Dashboard-Context': session.session_context } });
  expect(response.status()).toBe(200); return response.json();
}
for (const role of ['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN']) {
  test(`${role}: signed remediation history → real bearer API → PostgreSQL → separate verdicts`, async ({ page }) => {
    const errors: string[] = [], writes: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('request', r => { if (new URL(r.url()).pathname.startsWith('/dashboard/api/') && r.method() !== 'GET') writes.push(r.url()); });
    await login(page, role);
    const proposals: unknown = await read(page, 'remediations?limit=25');
    expect(proposalPage(proposals)).toBe(true);
    if (!proposalPage(proposals) || !proposals.items.length) throw new Error('Expected real seeded proposal history');
    const p = proposals.items[0];
    await page.getByLabel('Open scan by UUID').fill(p.content.baseline.scan_id);
    await page.getByRole('button', { name: 'Open scan', exact: true }).click();
    await page.getByRole('button', { name: `Open assessment ${p.content.baseline.assessment_id}`, exact: true }).click();
    await page.getByRole('button', { name: 'Remediation history for this finding', exact: true }).click();
    await page.getByRole('button', { name: `Open proposal ${p.content.proposal_id}`, exact: true }).click();
    const history = page.getByRole('region', { name: 'Remediation history', exact: true });
    await expect(history.getByText('Historical approval').locator('xpath=following-sibling::dd[1]')).toHaveText('APPROVED');
    await expect(history.getByText('Current proposal blockers').locator('xpath=following-sibling::dd[1]')).not.toHaveText('None reported at this read');
    const executions: unknown = await read(page, `remediation-executions?proposal_id=${p.content.proposal_id}&limit=25`);
    if (!executionPage(executions) || !executions.items.length) throw new Error('Expected real worker journal');
    const e = executions.items[0];
    await history.getByRole('button', { name: `Open execution ${e.content.execution_id}`, exact: true }).click();
    await expect(history.getByText('Execution phase').locator('xpath=following-sibling::dd[1]')).toHaveText('ACKNOWLEDGED');
    const verifications: unknown = await read(page, `remediation-verifications?execution_id=${e.content.execution_id}&limit=25`);
    if (!verificationPage(verifications) || !verifications.items.length) throw new Error('Expected immutable verification receipt');
    const v = verifications.items[0];
    await history.getByRole('button', { name: `Open verification ${v.content.verification_id}`, exact: true }).click();
    await expect(history.getByText('Verification verdict').locator('xpath=following-sibling::dd[1]')).toHaveText('VERIFIED');
    await expect(history.getByText('Verification technical result').locator('xpath=following-sibling::dd[1]')).toHaveText('PASS');
    await expect(history.getByText(/does not prove worker causation/)).toBeVisible();
    expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
    expect(writes).toEqual([]); expect(errors).toEqual([]);
    await page.getByRole('button', { name: 'Back to scan selection', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(history).toHaveCount(0); await expect(page.getByLabel('Open scan by UUID')).toBeFocused();
    expect(new URL(page.url()).searchParams.has('scan')).toBe(false);
    await page.goBack(); await expect(page.getByLabel('Open scan by UUID')).toHaveValue(p.content.baseline.scan_id);
    await expect(page.getByRole('heading', { name: 'Exact-scan investigation' })).toBeVisible();
  });
}
for (const mobile of [false, true]) {
  test(`${mobile ? 'mobile' : 'desktop'} native pointer retains Open scan position across history relayout`, async ({ page }) => {
    if (mobile) await page.setViewportSize({ width: 390, height: 844 });
    await login(page); await turnHistoryPage(page, 'Next page', 25);
    const input = page.getByLabel('Open scan by UUID'), open = page.getByRole('button', { name: 'Open scan', exact: true });
    const target = '22222222-2222-2222-2222-222222222222';
    await input.fill(target); await open.scrollIntoViewIfNeeded();
    let release!: () => void;
    const gate = new Promise<void>(done => { release = done; });
    const pattern = '**/dashboard/api/scans?limit=25&offset=0';
    let held = false;
    await page.route(pattern, async route => { const response = await route.fetch(); held = true; await gate; await route.fulfill({ response }); }, { times: 1 });
    await runWithHistoryCleanup(async () => {
      await page.getByRole('button', { name: 'Previous page', exact: true }).click();
      await expect.poll(() => held).toBe(true);
      await open.scrollIntoViewIfNeeded();
      const before = await open.boundingBox(); if (!before) throw new Error('Missing native target');
      await page.mouse.move(before.x + before.width / 2, before.y + before.height / 2);
      await page.mouse.down();
      release();
      await expect(page.getByRole('region', { name: 'Scan history', exact: true }).locator('.scans li')).toHaveCount(25);
      const after = await open.boundingBox(); if (!after) throw new Error('Lost native target');
      expect(after.x).toBeCloseTo(before.x, 2); expect(after.y).toBeCloseTo(before.y, 2);
      await page.mouse.up();
      await expect(page.locator('dd').filter({ hasText: /^PARTIAL$/ })).toBeVisible();
      await expect(input).toHaveValue(target); expect(new URL(page.url()).searchParams.get('scan')).toBe(target);
      await page.getByRole('button', { name: 'Back to scan selection', exact: true }).click();
      await expect(input).toBeFocused();
    }, async () => { release(); await page.mouse.up(); await page.unroute(pattern); });
  });
}
