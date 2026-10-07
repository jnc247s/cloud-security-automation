import { test, expect, type Page, type Locator, type Request } from '@playwright/test';
import type { NistReport, Counts, NistControl } from '../src/nist-api';
import type { Assessment, AssessmentDetail, Citation, Relationship } from '../src/investigation-api';

const fullScan = '44444444-4444-4444-4444-444444444444';
const oldScan = '11111111-1111-1111-1111-111111111111';
// Frozen fixture truths from accepted Sprint 6 HTTP acceptance, not calculated from the report.
const fullCounts: Counts = { pass_count: 21, fail_count: 17, insufficient_evidence_count: 0, not_applicable_count: 1 };
const oldCounts: Counts = { pass_count: 0, fail_count: 1, insufficient_evidence_count: 0, not_applicable_count: 0 };
const nist = (page: Page) => page.getByRole('region', { name: 'NIST technical context', exact: true });
const historical = (page: Page) => page.getByRole('region', { name: 'Historical assessment detail', exact: true });

async function login(page: Page, role = 'VIEWER', subject = 'test-reader') {
  await page.goto('/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Test role').selectOption(role);
  await page.getByLabel('Test subject').selectOption(subject);
  await page.getByRole('button', { name: 'Approve test login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}
async function open(page: Page, scan: string): Promise<NistReport> {
  const loaded = page.waitForResponse(r => r.url().endsWith(`/scans/${scan}/technical-posture`) && r.request().method() === 'GET');
  await page.getByLabel('Open scan by UUID').fill(scan);
  await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  const response = await loaded;
  expect(response.status()).toBe(200);
  await expect(page.getByRole('table', { name: `Historical technical assessments for ${scan}` })).toBeVisible();
  return response.json();
}
async function counts(where: Locator, value: Counts) {
  for (const [label, key] of [['PASS', 'pass_count'], ['FAIL', 'fail_count'], ['INSUFFICIENT_EVIDENCE', 'insufficient_evidence_count'], ['NOT_APPLICABLE', 'not_applicable_count']] as const)
    await expect(where.getByText(label + ' assessments', { exact: true }).first().locator('xpath=following-sibling::dd[1]')).toHaveText(String(value[key]));
}
async function mapping(page: Page, report: NistReport, control: NistControl) {
  const m = control.framework_mappings[0];
  const release = report.frameworks.find(f => f.framework_id === m.framework_id)!;
  let root = release.references.find(r => r.framework_reference_id === m.framework_reference_id)!;
  for (let depth = 0; root.parent_reference_id && depth < 3; depth++)
    root = release.references.find(r => r.framework_reference_id === root.parent_reference_id)!;
  expect(root.level).toBe('function');
  await nist(page).getByLabel('Select exact framework release').selectOption(release.framework_id);
  const summary = nist(page).locator('summary').filter({ hasText: `FUNCTION ${root.reference_key} — ${root.title}` });
  await summary.click();
  const rootPanel = summary.locator('..');
  await rootPanel.locator('summary').filter({ hasText: `Contributing controls and mappings (${root.mapped_control_version_ids.length})` }).click();
  await rootPanel.locator('summary').filter({ hasText: `Mapping ${m.reference_key} · ${m.mapping_id}` }).click();
  await expect(rootPanel.getByText(m.mapping_checksum, { exact: true })).toBeVisible();
  await expect(rootPanel.getByText(m.mapping_rationale, { exact: true })).toBeVisible();
  await expect(nist(page).getByText(release.source_checksum, { exact: true })).toBeVisible();
}
async function oldHandling(page: Page) {
  const report = await open(page, oldScan);
  expect(report.assessment_counts).toEqual(oldCounts);
  await counts(nist(page), oldCounts);
  await page.getByRole('button', { name: /Open assessment/ }).click();
  await expect(historical(page).getByRole('heading', { name: 'Exact control definition' })).toBeVisible();
  await historical(page).getByText('Observed tags', { exact: true }).click();
  await expect(historical(page).getByText('historical-old', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Current findings and exceptions' }).click();
  await page.getByRole('button', { name: /ACCEPTED_RISK —/ }).click();
  await expect(page.getByText('Expired at server reference time', { exact: true })).toBeVisible();
  await expect(page.getByText('ACTIVE', { exact: true })).toBeVisible();
  await expect(historical(page).getByText('FAIL', { exact: true })).toBeVisible();
  await counts(nist(page), oldCounts);
  return report;
}
async function cleared(page: Page) {
  for (const name of ['NIST technical context', 'Exact-scan investigation', 'Historical assessment detail',
    'Current operational handling', 'Exact observed snapshot', 'Source outcome and artifact', 'Directional relationship'])
    await expect(page.getByRole('region', { name, exact: true })).toHaveCount(0);
  await expect(page.getByText('historical-old', { exact: false })).toHaveCount(0);
  await expect(page.getByText('Expired at server reference time', { exact: true })).toHaveCount(0);
}
async function storage(page: Page) {
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length,
    hasReadableSessionCookie: document.cookie.includes('cloudsec_session') })))
    .toEqual({ local: 0, session: 0, hasReadableSessionCookie: false });
  expect(page.url()).not.toMatch(/access_token|id_token|refresh_token|code=|state=/);
}

for (const role of ['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN']) {
  test(role + ': whole retained NIST → assessment/evidence → graph → current handling → logout story', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    const reads: string[] = [];
    page.on('request', r => {
      if (r.url().includes('/dashboard/api/')) {
        expect(r.method()).toBe('GET'); reads.push(r.url());
      }
    });
    await login(page, role);
    const report = await open(page, fullScan);
    expect(report.assessment_counts).toEqual(fullCounts);
    expect(report.catalog.content_checksum).toBe('a00217f5502ed4278d33a35013ca4494d8cd7e52bffe19daebb08fdab7c128d1');
    expect(report.controls).toHaveLength(26);
    await counts(nist(page), fullCounts);
    const control = report.controls.find(c => c.control_key === 'EC2-001')!;
    const beforeExpansion = reads.length;
    await mapping(page, report, control);
    expect(reads.length).toBe(beforeExpansion);

    const filtered = page.waitForResponse(r => r.url().includes('/dashboard/api/assessments?')
      && new URL(r.url()).searchParams.get('control_id') === control.control_id);
    await page.getByLabel('Assessment control UUID').fill(control.control_id);
    await page.getByRole('button', { name: 'Apply assessment filters' }).click();
    const row: Assessment = (await (await filtered).json()).items[0];
    const detailLoaded = page.waitForResponse(r => r.url().endsWith('/assessments/' + row.assessment_id));
    await page.getByRole('button', { name: 'Open assessment ' + row.assessment_id, exact: true }).click();
    const detail: AssessmentDetail = await (await detailLoaded).json();
    await expect(historical(page).getByText(control.definition_checksum, { exact: true })).toBeVisible();
    await expect(historical(page).getByText(detail.resource_snapshot_id, { exact: true })).toBeVisible();
    expect(reads.length - beforeExpansion).toBe(5); // filter page + detail/control/resource/exact history
    const evidence = detail.evidence.find(e => e.payload.source_proof)!;
    const citation = (evidence.payload.source_proof as { sources: Citation[] }).sources[0];
    await page.getByRole('button', { name: 'Open cited source ' + citation.source_outcome_id, exact: true }).click();
    const source = page.getByRole('region', { name: 'Source outcome and artifact' });
    await expect(source.getByText(citation.artifact_id, { exact: true })).toBeVisible();
    await expect(source.getByText(citation.evidence_sha256, { exact: true })).toBeVisible();
    await counts(nist(page), fullCounts);

    const edgesLoaded = page.waitForResponse(r => r.url().includes('/dashboard/api/relationships?'));
    await page.getByRole('button', { name: 'Relationships', exact: true }).click();
    const edge: Relationship = (await (await edgesLoaded).json()).items.find((e: Relationship) => e.resolution === 'RESOLVED');
    expect(edge).toBeTruthy();
    await page.getByRole('button', { name: 'Open relationship ' + edge.observation_id, exact: true }).click();
    await page.getByRole('button', { name: 'Open exact source snapshot' }).click();
    const snapshot = page.getByRole('region', { name: 'Exact observed snapshot' });
    await expect(snapshot.getByText(edge.source.resource_snapshot_id!, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Open exact target snapshot' }).click();
    await expect(snapshot.getByText(edge.target.resource_snapshot_id!, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Open relationship source artifact' }).click();
    await expect(source.getByText(edge.source_outcome_id, { exact: true })).toBeVisible();

    const old = await oldHandling(page);
    await mapping(page, old, old.controls.find(c => c.enabled)!);
    await counts(nist(page), oldCounts);
    expect(await page.locator('.nist-context, .investigation').locator('img, script, a').count()).toBe(0);
    for (const path of reads.filter(u => /\/(assessments|source-outcomes|relationships|history)\?/.test(u))) {
      const params = new URL(path).searchParams;
      expect(params.get('limit')).toBe('25');
      expect([oldScan, fullScan]).toContain(params.get('scan_id'));
    }
    await storage(page);
    expect((await page.request.get('/api/v1/scans')).status()).toBe(401);
    const loggedOut = page.waitForResponse(r => r.url().endsWith('/dashboard/auth/logout'));
    await page.getByRole('button', { name: 'Sign out' }).click();
    await cleared(page);
    expect((await loggedOut).status()).toBe(204);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  });
}

test('combined NIST and expired-risk panels clear across two tabs before logout completes and on replacement identity', async ({ page, context }) => {
  await login(page, 'VIEWER', 'test-reader-A');
  const report = await oldHandling(page);
  await mapping(page, report, report.controls.find(c => c.enabled)!);
  const before = await (await context.request.get('/dashboard/session')).json();
  const other = await context.newPage();
  await other.goto('/dashboard/');
  await oldHandling(other);
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const complete = other.waitForResponse(r => r.url().endsWith('/dashboard/auth/logout'));
  await other.route('**/dashboard/auth/logout', async route => { await gate; await route.continue(); });
  try {
    await other.getByRole('button', { name: 'Sign out' }).click();
    await cleared(page); await cleared(other);
  } finally { release(); }
  expect((await complete).status()).toBe(204);
  await expect(other.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  let resumeRead!: () => void;
  const newReadGate = new Promise<void>(resolve => { resumeRead = resolve; });
  const reloaded = page.waitForResponse(r => r.url().endsWith(`/scans/${oldScan}/technical-posture`));
  let replacementContext = '';
  await page.route(`**/dashboard/api/scans/${oldScan}/technical-posture`, async route => {
    replacementContext = route.request().headers()['x-dashboard-context'];
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    await newReadGate;
    await route.fulfill({ response });
  }, { times: 1 });
  try {
    await login(other, 'VIEWER', 'test-reader-B');
    await expect(page.getByText('test-reader-B · VIEWER')).toBeVisible();
    await cleared(page);
    expect((await context.request.get('/dashboard/api/scans', { headers: { 'X-Dashboard-Context': before.session_context } })).status()).toBe(401);
  } finally { resumeRead(); }
  expect((await reloaded).status()).toBe(200);
  const after = await (await context.request.get('/dashboard/session')).json();
  expect(replacementContext).toBe(after.session_context);
  expect(replacementContext).not.toBe(before.session_context);
  // A new authorized identity may reload this same organization's scan, but never old open details.
  await expect(nist(page).getByLabel('Select exact framework release')).toHaveValue('');
  await expect(historical(page)).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Current operational handling' })).toHaveCount(0);
  expect((await context.request.get('/dashboard/api/scans', { headers: { 'X-Dashboard-Context': before.session_context } })).status()).toBe(401);
  await storage(page); await other.close();
});

test('real server expiry returns 401 and clears all combined panels, not just report counts', async ({ page, context }) => {
  await login(page);
  const report = await oldHandling(page);
  await mapping(page, report, report.controls.find(c => c.enabled)!);
  // Record only boundary outcomes, never cookies, headers, identity or evidence payloads.
  const events: { event: string; boundary: string; status?: number; authenticated?: boolean }[] = [];
  const refreshRequests = new Set<Request>();
  let refreshing = false;
  function boundary(url: string) {
    const path = new URL(url).pathname;
    return path === '/dashboard/session' ? 'session'
      : path === '/dashboard/api/scans' ? 'history'
      : path.endsWith('/technical-posture') ? 'report'
      : path.startsWith('/dashboard/api/') ? 'other-read' : null;
  }
  page.on('request', request => {
    const name = boundary(request.url());
    if (name) events.push({ event: 'request', boundary: name });
    if (name && refreshing) refreshRequests.add(request);
  });
  page.on('requestfailed', request => {
    const name = boundary(request.url());
    if (name) events.push({ event: 'request-failed', boundary: name });
  });
  page.on('response', async response => {
    const name = boundary(response.url());
    if (!name) return;
    events.push({ event: 'response', boundary: name, status: response.status() });
    if (name === 'session') {
      try {
        const value: unknown = await response.json();
        if (typeof value === 'object' && value !== null && 'authenticated' in value
          && typeof value.authenticated === 'boolean')
          events.push({ event: 'session-state', boundary: name, authenticated: value.authenticated });
      } catch { events.push({ event: 'session-body-unavailable', boundary: name }); }
    }
  });
  let expired!: () => void; let fail!: (error: unknown) => void;
  const expiry = new Promise<void>((resolve, reject) => { expired = resolve; fail = reject; });
  await page.route('**/dashboard/api/scans?*', async route => {
    try {
      expect((await context.request.post('http://127.0.0.1:9012/expire-dashboard-sessions')).status()).toBe(200);
      expired();
    } catch (error) { fail(error); throw error; }
    await route.continue();
  }, { times: 1 });
  // A current sibling read may return 401 first and abort history. Accept either,
  // but never use a superseded read or cleared report as proof of session recovery.
  const denied = page.waitForResponse(r => refreshRequests.has(r.request())
    && r.url().includes('/dashboard/api/') && r.status() === 401);
  const recovered = page.waitForResponse(r => refreshRequests.has(r.request())
    && new URL(r.url()).pathname === '/dashboard/session');
  try {
    refreshing = true;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expiry;
    expect((await denied).status()).toBe(401);
    await cleared(page);
    const recovery = await recovered;
    expect(recovery.status()).toBe(200);
    expect((await recovery.json()).authenticated).toBe(false);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await storage(page);
  } finally {
    let buttons: { signIn: number; signOut: number; retry: number } | 'unavailable' = 'unavailable';
    try {
      buttons = {
        signIn: await page.getByRole('button', { name: 'Sign in', exact: true }).count(),
        signOut: await page.getByRole('button', { name: 'Sign out', exact: true }).count(),
        retry: await page.getByRole('button', { name: 'Retry sign-in check', exact: true }).count()
      };
    } catch { /* Optional diagnostics must never replace the primary assertion/page error. */ }
    console.info('Expiry boundary diagnostics:', JSON.stringify({ events: events.slice(-40), buttons }));
  }
});

for (const width of [1280, 390]) {
  test(`accessible names, landmarks, table semantics and keyboard-only controls at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await login(page);
    await expect(page.getByRole('banner')).toHaveCount(1);
    await expect(page.getByRole('main')).toHaveCount(1);
    await page.getByRole('link', { name: 'Skip to content' }).focus();
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeVisible();
    await page.keyboard.press('Enter');
    await page.getByLabel('Open scan by UUID').focus();
    await page.keyboard.type(oldScan);
    await page.keyboard.press('Enter');
    const table = page.getByRole('table', { name: `Historical technical assessments for ${oldScan}` });
    await expect(table).toBeVisible();
    await expect(table.getByRole('columnheader')).toHaveCount(4);
    expect(await table.locator('th').evaluateAll(nodes => nodes.every(n => n.getAttribute('scope') === 'col'))).toBe(true);
    await page.getByRole('combobox', { name: 'Technical result', exact: true }).focus();
    await page.keyboard.press('f');
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Assessment resource UUID')).toBeFocused();
    await page.keyboard.press('Tab'); await expect(page.getByLabel('Assessment control UUID')).toBeFocused();
    await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Apply assessment filters' })).toBeFocused();
    await page.keyboard.press('Enter');
    const assessment = page.getByRole('button', { name: /Open assessment/ });
    await assessment.focus(); await page.keyboard.press('Enter');
    await expect(historical(page).getByRole('heading', { name: 'Exact control definition' })).toBeVisible();
    const tags = historical(page).locator('summary').filter({ hasText: 'Observed tags' });
    await tags.focus(); await page.keyboard.press('Enter');
    await expect(historical(page).getByText('historical-old', { exact: false })).toBeVisible();
    const release = nist(page).getByLabel('Select exact framework release');
    await release.focus(); await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
    const disclosure = nist(page).locator('summary').filter({ hasText: /^FUNCTION / }).first();
    await disclosure.focus(); await page.keyboard.press('Enter');
    await expect(disclosure.locator('..')).toHaveAttribute('open', '');
    const outline = await disclosure.evaluate(node => getComputedStyle(node).outlineStyle);
    expect(outline).toBe('solid');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const names = await page.locator('input, select').evaluateAll(nodes => nodes.map(node =>
      (node as HTMLInputElement).labels?.length ?? 0));
    expect(names.length).toBeGreaterThan(0); expect(names.every(n => n > 0)).toBe(true);
    await page.getByRole('button', { name: 'Sign out' }).focus(); await page.keyboard.press('Enter');
    await cleared(page);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  });
}

test('loading and failure states are announced without retaining a stale NIST or investigation panel', async ({ page }) => {
  await login(page); await oldHandling(page);
  let release!: () => void; let started!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { started = resolve; });
  let requests = 0;
  await page.route(/\/dashboard\/api\/scans\/99999999-9999-9999-9999-999999999999(?:\/technical-posture)?$/, async route => {
    const response = await route.fetch(); expect(response.status()).toBe(404);
    if (++requests === 2) started();
    await gate;
    await route.fulfill({ response });
  });
  try {
    await page.getByLabel('Open scan by UUID').fill('99999999-9999-9999-9999-999999999999');
    await page.getByRole('button', { name: 'Open scan', exact: true }).click();
    await ready;
    await expect(page.getByRole('status').filter({ hasText: 'Loading selected scan' })).toBeVisible();
    await cleared(page);
  } finally { release(); }
  await expect(page.getByRole('alert')).toHaveText('This scan is unavailable or no longer exists.');
  await cleared(page);
});

test('rendered text and keyboard focus colors meet scoped contrast thresholds', async ({ page }) => {
  await login(page); await oldHandling(page);
  const ratios = await page.evaluate(() => {
    const luminance = (rgb: number[]) => rgb.map(v => {
      const c = v / 255; return c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4;
    }).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
    const components = (color: string) => color.match(/[\d.]+/g)!.map(Number);
    const background = (node: Element): number[] => {
      const color = components(getComputedStyle(node).backgroundColor);
      if (color.length < 4 || color[3] > 0) return color.slice(0, 3);
      return node.parentElement ? background(node.parentElement) : [255, 255, 255];
    };
    const contrast = (a: number[], b: number[]) => {
      const values = [luminance(a), luminance(b)].sort((x, y) => y - x);
      return (values[0] + .05) / (values[1] + .05);
    };
    return [...document.querySelectorAll('p, dt, dd, th, td, label, summary, button:not(:disabled)')]
      .filter(n => n.getClientRects().length > 0)
      .map(n => ({ tag: n.tagName, ratio: contrast(components(getComputedStyle(n).color), background(n)) }));
  });
  expect(ratios.length).toBeGreaterThan(25);
  expect(ratios.filter(r => r.ratio < 4.5)).toEqual([]);
  const button = page.getByRole('button', { name: 'Sign out' });
  await button.focus(); await page.keyboard.press('Tab'); await button.focus();
  expect(await button.evaluate(n => getComputedStyle(n).outlineColor)).toBe('rgb(147, 86, 0)');
  // The accepted solid 3px outline has >3:1 contrast against both white and #f4f6f8.
  const focusContrast = (background: number[]) => {
    const luminance = (rgb: number[]) => rgb.map(v => {
      const c = v / 255; return c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4;
    }).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
    return (luminance(background) + .05) / (luminance([147, 86, 0]) + .05);
  };
  expect(focusContrast([255, 255, 255])).toBeGreaterThanOrEqual(3);
  expect(focusContrast([244, 246, 248])).toBeGreaterThanOrEqual(3);
});
