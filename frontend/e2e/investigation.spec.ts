import { test, expect, type Page, type APIRequestContext } from '@playwright/test';

const oldScan = '11111111-1111-1111-1111-111111111111';
const newScan = '33333333-3333-3333-3333-333333333333';
const graphScan = '44444444-4444-4444-4444-444444444444';
const incompleteScan = '55555555-5555-5555-5555-555555555555';
async function login(page: Page, role = 'VIEWER') {
  await page.goto('/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Test role').selectOption(role);
  await page.getByRole('button', { name: 'Approve test login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}
async function open(page: Page, id: string) {
  await page.getByLabel('Open scan by UUID').fill(id);
  await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Exact-scan investigation' })).toBeVisible();
}
async function read(request: APIRequestContext, path: string) {
  const session = await (await request.get('/dashboard/session')).json();
  const response = await request.get('/dashboard/api/' + path, { headers: { 'X-Dashboard-Context': session.session_context } });
  expect(response.status()).toBe(200);
  return response.json();
}
async function oldDetail(page: Page) {
  await open(page, oldScan);
  await page.getByRole('button', { name: /Open assessment/ }).click();
  await expect(page.getByRole('heading', { name: 'Exact control definition' })).toBeVisible();
  await page.getByText('Observed tags', { exact: true }).click();
  await expect(page.getByText('historical-old', { exact: false })).toBeVisible();
}

for (const role of ['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN']) {
  test(role + ': exact old assessment → snapshot/control/evidence → current expired risk', async ({ page }) => {
    const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
    const requests: string[] = [];
    page.on('request', r => { if (/\/dashboard\/api\/(assessments|resources|controls|findings|exceptions)/.test(r.url())) requests.push(r.url()); });
    await login(page, role); await oldDetail(page);
    const detail = page.getByRole('region', { name: 'Historical assessment detail' });
    await expect(detail.getByText('FAIL', { exact: true })).toBeVisible();
    await expect(detail.getByText('newer-pass', { exact: false })).toHaveCount(0);
    await expect(detail.getByText(/Display truncated/)).toBeVisible();
    expect(await detail.locator('img, script').count()).toBe(0);
    expect(requests).toHaveLength(5); // one bounded page; four on-demand detail reads, no per-row fanout
    expect(requests.find(u => u.includes('/history?'))).toContain('scan_id=' + oldScan);
    await page.getByRole('button', { name: 'Current findings and exceptions' }).click();
    await page.getByRole('button', { name: /ACCEPTED_RISK —/ }).click();
    await expect(page.getByText('Expired at server reference time', { exact: true })).toBeVisible();
    await expect(page.getByText('ACTIVE', { exact: true })).toBeVisible();
    await expect(detail.getByText('FAIL', { exact: true })).toBeVisible();
    await expect(page.getByText(/Server retrieval reference:/)).toContainText(/\+00:00/);
    await open(page, newScan);
    await expect(page.getByRole('region', { name: 'Historical assessment detail' })).toHaveCount(0);
    await expect(page.getByText('Expired at server reference time')).toHaveCount(0);
    await expect(page.getByRole('cell', { name: 'PASS', exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  });
}

test('typed proofs, exact normalized source artifact and directional resolved endpoints', async ({ page }) => {
  await login(page); await open(page, graphScan);
  const rows = await read(page.request, 'assessments?scan_id=' + graphScan + '&limit=100');
  let citationRow: typeof rows.items[number] | undefined;
  let citation: { source_outcome_id: string; artifact_id: string; evidence_sha256: string } | undefined;
  for (const row of rows.items) {
    const detail = await read(page.request, 'assessments/' + row.assessment_id);
    const proof = detail.evidence.find((e: { payload: { source_proof?: { sources: unknown[] } } }) => e.payload.source_proof?.sources.length)?.payload.source_proof;
    if (proof) { citationRow = row; citation = proof.sources[0]; break; }
  }
  expect(citationRow).toBeTruthy(); expect(citation).toBeTruthy();
  await page.getByLabel('Assessment control UUID').fill(citationRow!.control_id);
  await page.getByRole('button', { name: 'Apply assessment filters' }).click();
  await page.getByRole('button', { name: 'Open assessment ' + citationRow!.assessment_id, exact: true }).click();
  await page.getByRole('button', { name: 'Open cited source ' + citation!.source_outcome_id, exact: true }).click();
  const source = page.getByRole('region', { name: 'Source outcome and artifact' });
  await expect(source.getByText(citation!.artifact_id, { exact: true })).toBeVisible();
  await expect(source.getByText(citation!.evidence_sha256, { exact: true })).toBeVisible();
  expect(await source.locator('a').count()).toBe(0);
  await page.getByRole('button', { name: 'Relationships', exact: true }).click();
  const edges = await read(page.request, 'relationships?scan_id=' + graphScan + '&resolution=RESOLVED&limit=100');
  const edge = edges.items[0]; expect(edge).toBeTruthy();
  await page.getByLabel('Relationship resolution').selectOption('RESOLVED');
  await page.getByRole('button', { name: 'Apply graph filters' }).click();
  await page.getByRole('button', { name: 'Open relationship ' + edge.observation_id, exact: true }).click();
  await page.getByRole('button', { name: 'Open exact source snapshot' }).click();
  const snapshot = page.getByRole('region', { name: 'Exact observed snapshot' });
  await expect(snapshot.getByText(edge.source.resource_snapshot_id, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Open exact target snapshot' }).click();
  await expect(snapshot.getByText(edge.target.resource_snapshot_id, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Open relationship source artifact' }).click();
  await expect(source.getByText(edge.source_outcome_id, { exact: true })).toBeVisible();
});

test('unresolved targets remain references; graphless historical evidence has no inferred links', async ({ page }) => {
  await login(page); await oldDetail(page);
  await expect(page.getByText(/Legacy or unsupported source-proof schema/)).toBeVisible();
  await expect(page.getByRole('button', { name: /Open cited/ })).toHaveCount(0);
  await open(page, incompleteScan);
  const edges = await read(page.request, 'relationships?scan_id=' + incompleteScan + '&limit=100');
  const edge = edges.items.find((e: { resolution: string }) => e.resolution !== 'RESOLVED');
  expect(edge).toBeTruthy();
  await page.getByRole('button', { name: 'Relationships', exact: true }).click();
  await page.getByLabel('Relationship resolution').selectOption(edge.resolution);
  await page.getByRole('button', { name: 'Apply graph filters' }).click();
  await page.getByRole('button', { name: 'Open relationship ' + edge.observation_id, exact: true }).click();
  await expect(page.getByText(/Unresolved target reference/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open exact target snapshot' })).toHaveCount(0);
});

test('wrong historical snapshot and stale successful detail fail closed after scan navigation', async ({ page }) => {
  await login(page);
  await page.route('**/dashboard/api/resources/*/history?*', async route => {
    const response = await route.fetch(); const data = await response.json();
    data.items[0].scan_id = newScan; data.items[0].name = 'WRONG NEWER SNAPSHOT';
    await route.fulfill({ response, json: data });
  });
  await open(page, oldScan); await page.getByRole('button', { name: /Open assessment/ }).click();
  await expect(page.getByRole('alert')).toContainText('does not match');
  await expect(page.getByText('WRONG NEWER SNAPSHOT')).toHaveCount(0);
  await page.unroute('**/dashboard/api/resources/*/history?*');
  await page.getByRole('button', { name: 'Close assessment detail' }).click();
  let release!: () => void; let started!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { started = resolve; });
  await page.route('**/dashboard/api/assessments/*', async route => {
    const response = await route.fetch(); started(); await gate;
    try { await route.fulfill({ response }); } catch { /* the accepted read may be aborted */ }
  });
  await page.getByRole('button', { name: /Open assessment/ }).click(); await ready;
  await open(page, newScan); release();
  await expect(page.getByRole('region', { name: 'Historical assessment detail' })).toHaveCount(0);
  await expect(page.getByText('historical-old', { exact: false })).toHaveCount(0);
  await expect(page.getByRole('cell', { name: 'PASS', exact: true })).toBeVisible();
});

test('mobile keyboard navigation, server-time unavailable and expiry clear sensitive detail', async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 }); await login(page);
  await page.getByLabel('Open scan by UUID').focus(); await page.keyboard.type(oldScan); await page.keyboard.press('Enter');
  await page.getByRole('button', { name: /Open assessment/ }).focus(); await page.keyboard.press('Enter');
  await page.getByText('Observed tags', { exact: true }).click();
  await expect(page.getByText('historical-old', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.route('**/dashboard/api/exceptions?*', async route => {
    const response = await route.fetch(); const headers = response.headers(); delete headers['x-dashboard-read-at'];
    await route.fulfill({ response, headers });
  });
  await page.getByRole('button', { name: 'Current findings and exceptions' }).click();
  await page.getByRole('button', { name: /ACCEPTED_RISK —/ }).click();
  await expect(page.getByText('Eligibility unavailable', { exact: true })).toBeVisible();
  await expect(page.getByText('ACTIVE', { exact: true })).toBeVisible();
  await context.request.post('http://127.0.0.1:9012/expire-dashboard-sessions');
  await page.getByRole('button', { name: 'Refresh current handling' }).click();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.getByText('historical-old', { exact: false })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Historical assessment detail' })).toHaveCount(0);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('two-tab logout clears an investigation before the logout request finishes', async ({ page, context }) => {
  await login(page); await oldDetail(page);
  const other = await context.newPage(); await other.goto('/dashboard/');
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  await other.route('**/dashboard/auth/logout', async route => { await gate; await route.continue(); });
  await other.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('region', { name: 'Historical assessment detail' })).toHaveCount(0);
  await expect(page.getByText('historical-old', { exact: false })).toHaveCount(0);
  release(); await expect(other.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
});
