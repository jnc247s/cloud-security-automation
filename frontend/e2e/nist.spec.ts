import { test, expect, type Page, type Locator } from '@playwright/test';
import type { NistReport, Reference } from '../src/nist-api';

const oldScan = '11111111-1111-1111-1111-111111111111';
const newScan = '33333333-3333-3333-3333-333333333333';
const fullScan = '44444444-4444-4444-4444-444444444444';
const historicalScan = '88888888-8888-8888-8888-888888888888';
async function login(page: Page, role = 'VIEWER') {
  await page.goto('/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Test role').selectOption(role);
  await page.getByRole('button', { name: 'Approve test login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}
const panel = (page: Page) => page.getByRole('region', { name: 'NIST technical context', exact: true });
async function open(page: Page, scan: string): Promise<NistReport> {
  const loaded = page.waitForResponse(r => r.url().endsWith(`/scans/${scan}/technical-posture`) && r.request().method() === 'GET');
  await page.getByLabel('Open scan by UUID').fill(scan);
  await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  const response = await loaded; expect(response.status()).toBe(200);
  const report = await response.json() as NistReport;
  await expect(panel(page).getByRole('heading', { name: 'Exact catalog and profile coverage' })).toBeVisible();
  if (report.availability === 'AVAILABLE') await expect(page.getByRole('table', { name: `Historical technical assessments for ${scan}` })).toBeVisible();
  return report;
}
async function counts(where: Locator, expected: NistReport['assessment_counts']) {
  if (expected === null) { await expect(where.getByText('Assessment counts unavailable — not zero.', { exact: true }).first()).toBeVisible(); return; }
  for (const [label, key] of [['PASS', 'pass_count'], ['FAIL', 'fail_count'], ['INSUFFICIENT_EVIDENCE', 'insufficient_evidence_count'], ['NOT_APPLICABLE', 'not_applicable_count']] as const) {
    await expect(where.getByText(label + ' assessments', { exact: true }).first().locator('xpath=following-sibling::dd[1]')).toHaveText(String(expected[key]));
  }
}
async function expand(where: Locator, r: Reference) {
  const label = `${r.level.toUpperCase()} ${r.reference_key} — ${r.title}`;
  const summary = where.locator('summary').filter({ hasText: label });
  await summary.click();
  return summary.locator('..');
}

for (const role of ['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN']) {
  test(role + ': exact NIST counts, release hierarchy, mapping provenance and zero expansion reads', async ({ page }) => {
    const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
    await login(page, role); const report = await open(page, fullScan); const view = panel(page);
    await counts(view, report.assessment_counts);
    expect(report.controls).toHaveLength(26);
    await expect(view.getByLabel('Select exact framework release')).toHaveValue('');
    const release = report.frameworks.find(f => f.references.some(r => r.mapped_control_version_ids.length > 1))!;
    expect(release).toBeTruthy();
    const requests: string[] = [];
    page.on('request', r => { if (r.url().includes('/dashboard/api/')) requests.push(r.url()); });
    await view.getByLabel('Select exact framework release').selectOption(release.framework_id);
    const root = release.references.find(r => r.level === 'function' && r.mapped_control_version_ids.length > 1)!;
    const rootView = await expand(view, root);
    const unique = new Set(root.mapped_control_version_ids);
    const expected = { pass_count: 0, fail_count: 0, insufficient_evidence_count: 0, not_applicable_count: 0 };
    for (const c of report.controls) if (unique.has(c.control_version_id)) for (const key of Object.keys(expected) as (keyof typeof expected)[]) expected[key] += c.assessment_counts![key];
    await counts(rootView, expected);
    await rootView.locator('summary').filter({ hasText: `Contributing controls and mappings (${unique.size})` }).click();
    const mapping = report.controls.flatMap(c => c.framework_mappings).find(m => m.framework_id === release.framework_id && unique.has(m.control_version_id))!;
    await rootView.locator('summary').filter({ hasText: `Mapping ${mapping.reference_key} · ${mapping.mapping_id}` }).click();
    await expect(rootView.getByText(mapping.mapping_rationale, { exact: true })).toBeVisible();
    await expect(rootView.getByText(mapping.mapping_checksum, { exact: true })).toBeVisible();
    await expect(rootView.getByText(mapping.verified_at, { exact: true })).toBeVisible();
    expect(await view.locator('a, img, script').count()).toBe(0);
    expect(requests).toEqual([]); expect(errors).toEqual([]);
  });
}

test('older catalog after newer retention and repeated reference keys never select or merge releases implicitly', async ({ page }) => {
  await login(page); const latest = await open(page, fullScan);
  const historical = await open(page, historicalScan); const view = panel(page);
  expect(historical.catalog.version).toBe('0.3.0');
  expect(historical.frameworks.length).toBeLessThan(latest.frameworks.length);
  const [first, second] = historical.frameworks;
  const key = first.references.find(r => r.level === 'function')!.reference_key;
  expect(second.references.some(r => r.level === 'function' && r.reference_key === key)).toBe(true);
  await view.getByLabel('Select exact framework release').selectOption(first.framework_id);
  await expect(view.getByText(first.framework_id, { exact: true })).toBeVisible();
  await expand(view, first.references.find(r => r.level === 'function')!);
  await view.getByLabel('Select exact framework release').selectOption(second.framework_id);
  await expect(view.getByText(first.framework_id, { exact: true })).toHaveCount(0);
  await expect(view.locator('details[open]')).toHaveCount(0);
  await counts(view, historical.assessment_counts);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(panel(page).getByLabel('Select exact framework release')).toHaveValue('');
  await open(page, newScan); await page.goBack();
  await expect(panel(page).getByLabel('Select exact framework release')).toHaveValue('');
  await expect(panel(page).getByText('Catalog release').locator('xpath=following-sibling::dd[1]')).toContainText('0.3.0');
});

test('all four technical states, disabled definitions and expired current risk never become NIST outcomes', async ({ page }) => {
  await login(page);
  for (const [scan, key] of [[oldScan, 'fail_count'], [newScan, 'pass_count'], ['66666666-6666-6666-6666-666666666666', 'insufficient_evidence_count'],
    ['77777777-7777-7777-7777-777777777777', 'not_applicable_count']] as const) {
    const report = await open(page, scan); expect(report.assessment_counts![key]).toBe(1); await counts(panel(page), report.assessment_counts);
    await panel(page).getByText('Catalog control coverage', { exact: true }).click();
    await expect(panel(page).getByText(/Disabled, DISABLED; Mapped/).first()).toBeVisible();
    await expect(panel(page).getByText(/not the full CSF Core/)).toBeVisible();
  }
  const old = await open(page, oldScan);
  await page.getByRole('button', { name: /Open assessment/ }).click();
  await page.getByRole('button', { name: 'Current findings and exceptions', exact: true }).click();
  await page.getByRole('button', { name: /ACCEPTED_RISK —/ }).click();
  await expect(page.getByText('Expired at server reference time', { exact: true })).toBeVisible();
  await counts(panel(page), old.assessment_counts);
});

test('running/no-bundle definitions retain null; partial results retain counts and explicit gaps', async ({ page }) => {
  await login(page);
  const session = await (await page.request.get('/dashboard/session')).json();
  const scans = await (await page.request.get('/dashboard/api/scans?limit=100', { headers: { 'X-Dashboard-Context': session.session_context } })).json();
  for (const status of ['RUNNING', 'FAILED']) {
    const scan = scans.items.find((s: { status: string }) => s.status === status);
    expect(scan).toBeTruthy(); const report = await open(page, scan.scan_id);
    expect(report.assessment_counts).toBeNull(); await counts(panel(page), null);
    await expect(panel(page).getByText('PASS assessments', { exact: true })).toHaveCount(0);
  }
  const partial = await open(page, '22222222-2222-2222-2222-222222222222');
  expect(partial.scan.status).toBe('PARTIAL'); expect(partial.availability).toBe('AVAILABLE');
  await expect(page.getByText(/Collection has gaps or failures/)).toBeVisible();
  await counts(panel(page), partial.assessment_counts);
});

test('malformed graph fails closed without disabling investigation; wrong and stale scans never repopulate context', async ({ page }) => {
  await login(page);
  await page.route(`**/dashboard/api/scans/${oldScan}/technical-posture`, async route => {
    const response = await route.fetch(); const report = await response.json();
    report.frameworks[0].references[0].parent_reference_id = report.frameworks[0].references[0].framework_reference_id;
    await route.fulfill({ response, json: report });
  });
  await page.getByLabel('Open scan by UUID').fill(oldScan); await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  await expect(panel(page).getByRole('alert')).toContainText('unsupported or inconsistent');
  await expect(page.getByRole('cell', { name: 'FAIL', exact: true })).toBeVisible();
  await page.unroute(`**/dashboard/api/scans/${oldScan}/technical-posture`);
  await open(page, newScan);
  let started!: () => void, release!: () => void, finished!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; }); const delayed = new Promise<void>(resolve => { release = resolve; });
  const delivered = new Promise<void>(resolve => { finished = resolve; });
  await page.route(`**/dashboard/api/scans/${oldScan}/technical-posture`, async route => {
    const response = await route.fetch(); started(); await delayed;
    try { await route.fulfill({ response }); } finally { finished(); }
  });
  await page.getByLabel('Open scan by UUID').fill(oldScan); await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  await ready; await open(page, newScan); release(); await delivered;
  await expect(panel(page).getByText('FAIL assessments', { exact: true }).locator('xpath=following-sibling::dd[1]')).toHaveText('0');
  await expect(panel(page).getByLabel('Select exact framework release')).toHaveValue('');
  await page.unroute(`**/dashboard/api/scans/${oldScan}/technical-posture`);
  await page.route(`**/dashboard/api/scans/${oldScan}/technical-posture`, async route => {
    const response = await route.fetch(), report = await response.json(); report.scan.scan_id = newScan;
    await route.fulfill({ response, json: report });
  });
  await page.getByLabel('Open scan by UUID').fill(oldScan); await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('The report does not match the selected scan.');
  await expect(panel(page)).toHaveCount(0);
});

test('keyboard/mobile hierarchy is readable, no horizontal page overflow, logout clears context across tabs', async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 }); await login(page); const report = await open(page, oldScan);
  const view = panel(page), f = report.frameworks[0]; await view.getByLabel('Select exact framework release').selectOption(f.framework_id);
  const summary = view.locator('summary').filter({ hasText: 'FUNCTION ' }).first(); await summary.focus(); await page.keyboard.press('Enter');
  await expect(summary.locator('..')).toHaveAttribute('open', '');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const tab = await context.newPage(); await tab.goto('/dashboard/?scan=' + oldScan);
  await expect(panel(tab).getByLabel('Select exact framework release')).toBeVisible();
  await tab.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(panel(page)).toHaveCount(0); await expect(panel(tab)).toHaveCount(0);
  const direct = await page.request.get('/api/v1/scans/' + oldScan + '/technical-posture'); expect(direct.status()).toBe(401);
});

test('real session expiry clears expanded NIST context and rejects old-context reads', async ({ page, context }) => {
  await login(page); const report = await open(page, oldScan);
  const session = await (await page.request.get('/dashboard/session')).json();
  await panel(page).getByLabel('Select exact framework release').selectOption(report.frameworks[0].framework_id);
  await expand(panel(page), report.frameworks[0].references.find(r => r.level === 'function')!);
  let completed!: () => void, failed!: (reason: unknown) => void;
  const expired = new Promise<void>((resolve, reject) => { completed = resolve; failed = reject; });
  await page.route('**/dashboard/api/scans?limit=25&offset=0', async route => {
    try {
      const response = await context.request.post('http://127.0.0.1:9012/expire-dashboard-sessions');
      expect(response.status()).toBe(200); completed();
    } catch (error) { failed(error); throw error; }
    await route.continue();
  }, { times: 1 });
  const rejected = page.waitForResponse(r => r.url().includes('/dashboard/api/') && r.status() === 401);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expired; await rejected;
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(panel(page)).toHaveCount(0);
  const denied = await page.request.get('/dashboard/api/scans/' + oldScan + '/technical-posture', { headers: { 'X-Dashboard-Context': session.session_context } });
  expect(denied.status()).toBe(401);
});

test('hostile mapping/source text remains escaped and bounded without metadata navigation', async ({ page }) => {
  await login(page);
  const hostile = '<img src=x onerror=alert(1)>', source = 'javascript:alert(1)';
  await page.route(`**/dashboard/api/scans/${oldScan}/technical-posture`, async route => {
    const response = await route.fetch(), report = await response.json();
    report.frameworks[0].source = source;
    for (const c of report.controls) for (const m of c.framework_mappings) m.mapping_rationale = hostile + 'x'.repeat(10000);
    await route.fulfill({ response, json: report });
  });
  const report = await open(page, oldScan), view = panel(page), f = report.frameworks[0];
  await view.getByLabel('Select exact framework release').selectOption(f.framework_id);
  await expect(view.getByText(source, { exact: true })).toBeVisible();
  const root = f.references.find(r => r.level === 'function' && r.mapped_control_version_ids.length)!;
  const rootView = await expand(view, root);
  await rootView.locator('summary').filter({ hasText: `Contributing controls and mappings (${root.mapped_control_version_ids.length})` }).click();
  const mapping = report.controls.flatMap(c => c.framework_mappings).find(m => m.framework_id === f.framework_id
    && root.mapped_control_version_ids.includes(m.control_version_id))!;
  await rootView.locator('summary').filter({ hasText: `Mapping ${mapping.reference_key} · ${mapping.mapping_id}` }).click();
  await expect(rootView.getByText(hostile + 'x'.repeat(2048 - hostile.length) + '… [Display truncated]', { exact: true })).toBeVisible();
  expect(await view.locator('img, script, a').count()).toBe(0);
  expect(page.url()).toContain('/dashboard/');
});
