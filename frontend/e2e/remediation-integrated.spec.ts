import type { Browser, Locator, Page, Request } from '@playwright/test';
import { isExecution, isProposal, isVerification, proposalPage, executionPage, verificationPage, type Proposal, type Verification } from '../src/remediation-api';
import { isPreparedOperation, samePrepared } from '../src/remediation-operations';
import { test, expect, integratedOrigin as origin, scenarioExpected, type IntegratedFixture, type ScenarioName } from './integrated-fixture';
import { runWithHistoryCleanup } from './history-page';
import { CapacityOwner } from './integrated-capacity';

async function login(page: Page, identity: string) {
  await page.goto(origin + '/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Test identity').selectOption(identity);
  await page.getByRole('button', { name: 'Approve test login', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
}
async function read(page: Page, route: string): Promise<unknown> {
  const session = await (await page.request.get(origin + '/dashboard/session')).json();
  expect(session.features).toEqual({ remediation: true }); expect(session).not.toHaveProperty('access_token');
  const response = await page.request.get(origin + '/dashboard/api/' + route,
    { headers: { 'X-Dashboard-Context': session.session_context } });
  expect(response.status()).toBe(200); return response.json();
}
async function finding(page: Page, scan: string, assessment: string) {
  // Settle the actual initial history before native interaction, as the retained pagination
  // helper does. Also observe both exact selection reads; a missing report must not masquerade
  // as a missing assessment button until the entire testcase budget expires.
  await expect(page.getByText('Loading scan history…', { exact: true })).toHaveCount(0);
  await page.getByLabel('Open scan by UUID').fill(scan);
  await expect(page.getByLabel('Open scan by UUID')).toHaveValue(scan);
  const detail = page.waitForResponse(response => response.url() === origin + `/dashboard/api/scans/${scan}` && response.request().method() === 'GET');
  const posture = page.waitForResponse(response => response.url() === origin + `/dashboard/api/scans/${scan}/technical-posture` && response.request().method() === 'GET');
  await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  await expect.poll(() => new URL(page.url()).searchParams.get('scan')).toBe(scan);
  expect((await detail).status()).toBe(200); expect((await posture).status()).toBe(200);
  await expect(page.getByRole('button', { name: `Open assessment ${assessment}`, exact: true })).toBeVisible();
  await page.getByRole('button', { name: `Open assessment ${assessment}`, exact: true }).click();
  await page.getByRole('button', { name: 'Remediation history for this finding', exact: true }).click();
}
const hostileReason = 'Reviewed exact target <img src=x onerror=alert(1)> without executing this text.';
async function prepare(page: Page, title: string, kind: string, keyboard = false): Promise<Locator> {
  await page.getByRole('textbox', { name: new RegExp('^' + title + ' reason') }).fill(keyboard ? hostileReason : 'Reviewed exact native target, retained policy and independent authority.');
  const button = page.getByRole('button', { name: title, exact: true });
  const prepared = page.waitForResponse(response => response.url() === origin + '/dashboard/api/remediation-operations'
    && response.request().method() === 'POST');
  if (keyboard) { await button.focus(); await button.press('Enter'); } else await button.click();
  const response = await prepared;
  expect(response.status()).toBe(201);
  const operation: unknown = await response.json();
  if (!isPreparedOperation(operation) || operation.operation !== kind) throw new Error('Unsupported native preparation');
  const card = page.getByRole('article', { name: `Prepared ${kind} ${operation.operation_id}`, exact: true });
  await expect(card.getByRole('heading', { name: `${kind} · PREPARED`, exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Confirm and submit request', exact: true })).toBeDisabled();
  await expect(page.getByRole('heading', { name: 'Manual remediation operations', exact: true })).toBeFocused();
  if (keyboard) {
    await expect(card.getByText(hostileReason, { exact: true })).toBeVisible();
    await expect(page.locator('img[src="x"]')).toHaveCount(0);
  }
  return card;
}
async function confirm(card: Locator, kind: string, keyboard = false): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true }).locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const reviewed = card.getByRole('checkbox', { name: /I reviewed this frozen target/ });
  const button = card.getByRole('button', { name: 'Confirm and submit request', exact: true });
  if (keyboard) {
    await reviewed.focus(); await reviewed.press('Space'); await expect(reviewed).toBeChecked();
    await button.focus(); await expect(button).toBeFocused(); await button.press('Enter');
  } else { await reviewed.check(); await button.click(); }
  await expect(card.getByRole('heading', { name: `${kind} · CONFIRMED`, exact: true })).toBeVisible();
  const result = (await card.locator('p').filter({ hasText: /^Confirmed request result UUID:/ }).locator('span').innerText()).trim();
  return { result, key };
}
async function prepareWithRecoveryGuards(page: Page, fixture: IntegratedFixture): Promise<Locator> {
  const path = origin + '/dashboard/api/remediation-operations';
  let releaseOld!: () => void, held = false, settled = false, card: Locator | undefined;
  const oldGate = new Promise<void>(resolve => { releaseOld = resolve; });
  await page.route(path, async route => {
    expect(route.request().method()).toBe('GET');
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    expect(await response.json()).toEqual({ schema_version: '1.0.0', items: [] });
    held = true; await oldGate;
    await route.fulfill({ response }); settled = true;
  }, { times: 1 });
  await runWithHistoryCleanup(async () => {
    await page.reload(); // An actual initial empty recovery read is delayed, not fabricated.
    await expect.poll(() => held).toBe(true);
    await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
    await expect(page.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
    await finding(page, fixture.scan_id, fixture.assessment_id);
    card = await prepare(page, 'Prepare proposal', 'PROPOSE');
    const key = (await card.getByText('Prepared operation UUID', { exact: true })
      .locator('xpath=following-sibling::dd[1]').innerText()).trim();
    const before = await read(page, `remediation-operations/${key}`);
    if (!isPreparedOperation(before)) throw new Error('Unsupported guarded preparation');
    expect(before.state).toBe('PREPARED'); expect(before.attempts).toBe(0);
    releaseOld(); await expect.poll(() => settled).toBe(true);
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await expect(card.getByRole('heading', { name: 'PROPOSE · PREPARED', exact: true })).toBeVisible();
    await expect(page.getByText(/Recover operations before preparing new work/)).toHaveCount(0);

    const replacementReason = page.getByRole('textbox', { name: /^Prepare proposal reason/ });
    await replacementReason.fill('Valid replacement input cannot bypass unavailable recovery.');
    let incomplete = false;
    await page.route(path, async route => {
      expect(route.request().method()).toBe('GET');
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      const actual = await response.json();
      expect(actual.items.map((item: { operation_id: string }) => item.operation_id)).toEqual([key]);
      // Corrupt only this browser's GET reply, after genuine auth/store handling. The BFF,
      // frozen operation, UUID, database and all mutation replies stay unchanged.
      await route.fulfill({ response, contentType: 'application/json',
        body: JSON.stringify({ ...actual, items: [] }) });
      incomplete = true;
    }, { times: 1 });
    await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
    await expect.poll(() => incomplete).toBe(true);
    await expect(page.getByText(/Operation recovery is unavailable/)).toBeVisible();
    await expect(page.getByText(/Recover operations before preparing new work/)).toBeVisible();
    await expect(card.getByRole('heading', { name: 'PROPOSE · PREPARED', exact: true })).toBeVisible();
    await expect(card.getByRole('checkbox', { name: /I reviewed this frozen target/ })).toBeDisabled();
    await expect(replacementReason).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Prepare proposal', exact: true })).toBeDisabled();
    expect(await read(page, `remediation-operations/${key}`)).toEqual(before);
    await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
    await expect(page.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
    await expect(card.getByRole('checkbox', { name: /I reviewed this frozen target/ })).toBeEnabled();
    await expect(card.getByRole('button', { name: 'Confirm and submit request', exact: true })).toBeDisabled();
    expect(await read(page, `remediation-operations/${key}`)).toEqual(before);
    await expect(page.getByRole('button', { name: 'Prepare proposal', exact: true })).toBeEnabled();
    await page.getByRole('button', { name: 'Prepare proposal', exact: true }).click();
    await expect(page.getByText(/This target already has an unresolved operation/)).toBeVisible();
    expect(await read(page, `remediation-operations/${key}`)).toEqual(before);
    await rejectChangedRecovery(page, key, 'input');
    console.log('D3_NATIVE_RECOVERY_GUARDS');
  }, async () => { releaseOld(); });
  if (!card) throw new Error('No guarded prepared operation');
  return card;
}

async function rejectChangedRecovery(page: Page, key: string, change: 'input' | 'confirmed-state') {
  const path = origin + '/dashboard/api/remediation-operations';
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported immutable recovery baseline');
  const card = page.getByRole('article', { name: `Prepared ${before.operation} ${key}`, exact: true });
  const reason = page.getByRole('textbox', { name: /^Prepare proposal reason/ });
  await reason.fill('A valid replacement reason must not bypass failed recovery.');
  let delivered = false;
  await page.route(path, async route => {
    expect(route.request().method()).toBe('GET');
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    const actual = await response.json();
    expect(actual.items).toHaveLength(1);
    const value: unknown = actual.items[0];
    if (!isPreparedOperation(value) || value.operation_id !== key) throw new Error('Unexpected actual recovery baseline');
    const changed = change === 'input'
      ? { ...value, input: { ...value.input, reason: 'Untrusted changed input under the original UUID.' } }
      : { ...value, state: 'PREPARED', attempts: 0, result: null };
    expect(isPreparedOperation(changed)).toBe(true); // Well-formed but semantically regressed.
    await route.fulfill({ response, contentType: 'application/json',
      body: JSON.stringify({ ...actual, items: [changed] }) });
    delivered = true;
  }, { times: 1 });
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect.poll(() => delivered).toBe(true);
  await expect(page.getByText(/Operation recovery is unavailable/)).toBeVisible();
  await expect(card.getByRole('heading', { name: `${before.operation} · ${before.state}`, exact: true })).toBeVisible();
  await expect(reason).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Prepare proposal', exact: true })).toBeDisabled();
  expect(await read(page, `remediation-operations/${key}`)).toEqual(before);
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect(page.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
  await expect(reason).toBeEnabled();
  expect(await read(page, `remediation-operations/${key}`)).toEqual(before);
  console.log('D3_NATIVE_RECOVERY_REJECTED_' + change.toUpperCase().replace('-', '_'));
}

async function confirmWithDuplicateClicks(page: Page, card: Locator): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true })
    .locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const path = origin + `/dashboard/api/remediation-operations/${key}/submit`;
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported duplicate-click preparation');
  let release!: () => void, held = false, posts = 0, result: string | undefined;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const count = (request: import('@playwright/test').Request) => {
    if (request.url() === path && request.method() === 'POST') posts += 1;
  };
  page.on('request', count);
  await page.route(path, async route => {
    const headers = await route.request().allHeaders();
    const response = await route.fetch({ headers: { ...headers, origin, 'sec-fetch-site': 'same-origin' } });
    expect(response.status()).toBe(200);
    const value: unknown = await response.json();
    if (!isPreparedOperation(value) || value.state !== 'CONFIRMED') throw new Error('Submission did not genuinely confirm');
    held = true; await gate; await route.fulfill({ response });
  }, { times: 1 });
  await runWithHistoryCleanup(async () => {
    await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
    const button = card.getByRole('button', { name: 'Confirm and submit request', exact: true });
    await button.dblclick();
    await expect.poll(() => held).toBe(true);
    await expect(button).toBeDisabled();
    await card.locator('form').evaluate(form => {
      (form as HTMLFormElement).requestSubmit(); (form as HTMLFormElement).requestSubmit();
    });
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    expect(posts).toBe(1);
    const committed = await read(page, `remediation-operations/${key}`);
    if (!isPreparedOperation(committed)) throw new Error('Unsupported confirmed duplicate-click result');
    expect(samePrepared(before, committed)).toBe(true);
    expect(committed.state).toBe('CONFIRMED'); expect(committed.attempts).toBe(1);
    release();
    await expect(card.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
    result = (await card.locator('p').filter({ hasText: /^Confirmed request result UUID:/ }).locator('span').innerText()).trim();
    await rejectChangedRecovery(page, key, 'confirmed-state');
    await expect(card.getByRole('checkbox', { name: /I reviewed this frozen target/ })).toHaveCount(0);
    expect(posts).toBe(1);
    console.log('D3_NATIVE_SINGLE_SUBMISSION');
  }, async () => { release(); page.off('request', count); });
  if (!result) throw new Error('No confirmed duplicate-click result');
  return { result, key };
}

async function confirmAfterLostBrowserReply(page: Page, card: Locator): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true }).locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const pattern = origin + '/dashboard/api/remediation-operations/' + key + '/submit';
  let committed = false, observedStatus = 0;
  await page.route(pattern, async route => {
    const headers = await route.request().allHeaders();
    console.log('D3_LOST_REPLY_BROWSER_HEADERS ' + JSON.stringify({
      originPresent: headers.origin === origin, fetchSitePresent: headers['sec-fetch-site'] === 'same-origin',
      csrfPresent: Boolean(headers['x-csrf-token']), contextPresent: Boolean(headers['x-dashboard-context'])
    }));
    // APIRequest-based route replay does not synthesize the browser's origin/fetch metadata.
    // Preserve its complete original headers and exact trusted same-origin context; no bypass.
    const response = await route.fetch({ headers: { ...headers, origin, 'sec-fetch-site': 'same-origin' } });
    observedStatus = response.status();
    if (observedStatus !== 200 || (await response.json()).state !== 'CONFIRMED') {
      await route.fulfill({ response }); return; // Preserve the rejection; never fabricate a commit.
    }
    committed = true;
    await route.abort('failed'); // Lose only the browser reply, after genuine upstream commit.
  }, { times: 1 });
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  await expect.poll(() => observedStatus).toBe(200);
  expect(committed).toBe(true);
  await expect(card.getByText(/Submission outcome is unconfirmed/)).toBeVisible();
  await expect(card.getByRole('button', { name: 'Explicitly retry original request' })).toBeDisabled();
  await page.reload(); // GET recovery, never a replacement key or automatic submission.
  const recovered = page.getByRole('article', { name: `Prepared PROPOSE ${key}`, exact: true });
  await expect(recovered.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
  const result = (await recovered.locator('p').filter({ hasText: /^Confirmed request result UUID:/ }).locator('span').innerText()).trim();
  return { result, key };
}
async function mutation(page: Page, path: string, data: unknown) {
  const session = await (await page.request.get(origin + '/dashboard/session')).json();
  return page.request.post(origin + '/dashboard/api/' + path, { data, headers: {
    Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'X-CSRF-Token': session.csrf_token,
    'X-Dashboard-Context': session.session_context
  } });
}
async function confirmAfterUnconfirmedUpstream(page: Page, card: Locator, reference?: IntegratedFixture): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true }).locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported prepared operation');
  expect(before.state).toBe('PREPARED'); expect(before.attempts).toBe(0);
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  await expect(card.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Explicitly retry original request' })).toBeDisabled();
  if (reference) {
    const spoofed = '5f02520a-fdc5-4ae1-a789-9d447104abb1';
    const uncertain = await read(page, `remediation-operations/${key}`);
    if (!isPreparedOperation(uncertain)) throw new Error('Unsupported untrusted-reference result');
    expect(samePrepared(before, uncertain)).toBe(true);
    expect(uncertain.state).toBe('UNCONFIRMED'); expect(uncertain.attempts).toBe(1); expect(uncertain.result).toBeNull();
    await expect(page.locator('body')).not.toContainText(spoofed);
    for (const replacement of [{ reason: 'Replace frozen input.' }, { operation_id: spoofed }]) {
      const denied = await mutation(page, `remediation-operations/${key}/submit`, replacement);
      expect(denied.status()).toBe(422);
    }
    const denied = await mutation(page, 'remediation-operations', {
      schema_version: '1.0.0', operation: 'PROPOSE', operation_id: spoofed,
      input: { finding_id: reference.finding_id, occurrence_id: reference.occurrence_id, reason: before.input.reason }
    });
    expect(denied.status()).toBe(422);
    expect(await read(page, `remediation-operations/${key}`)).toEqual(uncertain);
    const history = await read(page, 'remediations?limit=25');
    if (!proposalPage(history) || history.total !== 1) throw new Error('Expected sole genuine committed proposal');
    expect(history.items[0].content.proposal_id).not.toBe(spoofed);
    expect(history.items[0].content.baseline.occurrence_id).toBe(reference.occurrence_id);
    expect(history.items[0].content.baseline.assessment_id).toBe(reference.assessment_id);
    console.log('D3_NATIVE_REFERENCE_UNCONFIRMED_CLOSED_INPUT_RETAINED');
  }
  await page.reload(); // Neither uncertainty nor reload authorizes an automatic retry/new key.
  const recovered = page.getByRole('article', { name: `Prepared PROPOSE ${key}`, exact: true });
  await expect(recovered.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  const uncertain = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(uncertain)) throw new Error('Unsupported uncertain operation');
  expect(samePrepared(before, uncertain)).toBe(true);
  expect(uncertain.attempts).toBe(1); expect(uncertain.result).toBeNull();
  await expect(recovered.getByRole('button', { name: 'Explicitly retry original request' })).toBeDisabled();
  await recovered.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await recovered.getByRole('button', { name: 'Explicitly retry original request' }).click();
  await expect(recovered.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
  const after = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(after) || !after.result) throw new Error('Unsupported recovered result');
  expect(samePrepared(before, after)).toBe(true); expect(after.attempts).toBe(2);
  if (reference) {
    const history = await read(page, 'remediations?limit=25');
    if (!proposalPage(history) || history.total !== 1) throw new Error('Original-key recovery replaced history');
    expect(after.result.result_id).toBe(history.items[0].content.proposal_id);
  }
  return { result: after.result.result_id, key };
}
async function crossTabLogoutWithLateCoordination(page: Page, operationId: string) {
  const other = await page.context().newPage();
  let otherErrors = 0, otherWrites = 0;
  other.on('pageerror', () => { otherErrors += 1; });
  other.on('request', request => {
    if (new URL(request.url()).pathname.startsWith('/dashboard/api/') && request.method() !== 'GET') otherWrites += 1;
  });
  const operation = (target: Page) => target.getByRole('article', { name: `Prepared DECIDE ${operationId}`, exact: true });
  const region = (target: Page) => target.getByRole('region', { name: 'Manual remediation operations', exact: true });
  const oldSession = await (await page.request.get(origin + '/dashboard/session')).json();
  let releaseRead!: () => void, releaseLogout!: () => void;
  const readGate = new Promise<void>(resolve => { releaseRead = resolve; });
  const logoutGate = new Promise<void>(resolve => { releaseLogout = resolve; });
  let readHeld = false, readReleased = false, logoutHeld = false;
  const readPath = origin + '/dashboard/api/remediation-operations', logoutPath = origin + '/dashboard/auth/logout';
  await runWithHistoryCleanup(async () => {
    await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
    await expect(operation(page).getByRole('heading', { name: 'DECIDE · UNCONFIRMED', exact: true })).toBeVisible();
    await other.goto(origin + '/dashboard/');
    await expect(operation(other).getByRole('heading', { name: 'DECIDE · UNCONFIRMED', exact: true })).toBeVisible();
    await other.route(readPath, async route => {
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      readHeld = true;
      await readGate;
      await route.fulfill({ response });
      readReleased = true;
    }, { times: 1 });
    await other.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
    await expect.poll(() => readHeld).toBe(true);
    await page.route(logoutPath, async route => {
      logoutHeld = true; await logoutGate; await route.continue();
    }, { times: 1 });
    const completed = page.waitForResponse(response => response.url() === logoutPath);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect.poll(() => logoutHeld).toBe(true);
    for (const target of [page, other]) {
      await expect(region(target)).toHaveCount(0);
      await expect(target.getByText(operationId, { exact: true })).toHaveCount(0);
      await expect(target.getByText(/Submitted requests are not canceled/)).toBeVisible();
    }
    releaseRead();
    await expect.poll(() => readReleased).toBe(true);
    await other.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    for (const target of [page, other]) await expect(region(target)).toHaveCount(0);
    expect(otherErrors).toBe(0); expect(otherWrites).toBe(0);
    releaseLogout();
    expect((await completed).status()).toBe(204);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    expect((await other.request.get(readPath, { headers: { 'X-Dashboard-Context': oldSession.session_context } })).status()).toBe(401);
    for (const target of [page, other]) await expect(region(target)).toHaveCount(0);
  }, async () => {
    releaseRead(); releaseLogout();
    await page.unroute(logoutPath);
    await other.close();
  });
}
async function realSessionLossClearsOn401(page: Page, operationId: string) {
  const card = page.getByRole('article', { name: `Prepared PROPOSE ${operationId}`, exact: true });
  await expect(card.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
  const session = await (await page.request.get(origin + '/dashboard/session')).json();
  // Real server revocation, outside the page's event handlers: no synthetic 401 or new endpoint.
  const revoked = await page.request.post(origin + '/dashboard/auth/logout', { headers: {
    Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'X-CSRF-Token': session.csrf_token
  } });
  expect(revoked.status()).toBe(204);
  await expect(card).toBeVisible(); // The page has not yet observed the external session loss.
  const denied = page.waitForResponse(response => response.url() === origin + '/dashboard/api/remediation-operations'
    && response.request().method() === 'GET');
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  expect((await denied).status()).toBe(401);
  await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
  await expect(page.getByText(operationId, { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
  expect((await page.request.get(origin + '/dashboard/api/remediation-operations',
    { headers: { 'X-Dashboard-Context': session.session_context } })).status()).toBe(401);
}
const datum = (page: Page, label: string) => page.getByText(label, { exact: true }).locator('xpath=following-sibling::dd[1]');

async function deniedExtraVerification(page: Page, execution: string, scans: number) {
  const path = `remediation-verifications?execution_id=${execution}`;
  const before = await read(page, path);
  const prepared = await mutation(page, 'remediation-operations', { schema_version: '1.0.0',
    operation: 'REQUEST_VERIFICATION', target_id: execution,
    input: { reason: 'An explicit extra request must not bypass the accepted scan limit.' } });
  expect(prepared.status()).toBe(201);
  const operation: unknown = await prepared.json();
  if (!isPreparedOperation(operation)) throw new Error('Unsupported guarded preparation');
  const submitted = await mutation(page, `remediation-operations/${operation.operation_id}/submit`, {});
  expect(submitted.status()).toBe(200);
  const settled: unknown = await submitted.json();
  if (!isPreparedOperation(settled)) throw new Error('Unsupported guarded settlement');
  expect(samePrepared(operation, settled)).toBe(true);
  expect(settled.state).toBe('UNCONFIRMED'); expect(settled.result).toBeNull(); expect(settled.attempts).toBe(1);
  expect(await read(page, path)).toEqual(before);
  expect((await (await page.request.get(origin + '/__test/fixture')).json()).scan_submissions).toBe(scans);
}

async function capacityBeforeProposal(browser: Browser, page: Page, fixture: IntegratedFixture) {
  const sessionLimit = fixture.scenario === 'capacity-session';
  const owner = sessionLimit ? new CapacityOwner(page.request) : undefined;
  if (owner) { await owner.attach(); await owner.fill(); }
  else if (!fixture.capacity) throw new Error('No owned global capacity cohort');
  const old = owner ? await browser.newContext({ storageState: await page.context().storageState() }) : undefined;
  await runWithHistoryCleanup(async () => {
    await finding(page, fixture.scan_id, fixture.assessment_id);
    if (owner) {
      await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
      await expect(page.getByRole('article', { name: /^Prepared PROPOSE / })).toHaveCount(16);
    }
    await page.getByRole('textbox', { name: /^Prepare proposal reason/ })
      .fill('The real capacity boundary must refuse this new native preparation.');
    const completed = page.waitForResponse(response => response.url() === origin + '/dashboard/api/remediation-operations'
      && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Prepare proposal', exact: true }).click();
    const denied = await completed;
    expect(denied.status()).toBe(503);
    // The client rejects error status without decoding its untrusted body. Retain the exact
    // JSON contract check via the same real signed session, not an unread browser body.
    const probe = new CapacityOwner(page.request);
    await probe.attach(); await probe.rejectExtra();
    await expect(page.getByText('Preparation could not be confirmed. Refresh same-session operations before preparing again.', { exact: true })).toBeVisible();
    await expect(page.getByText(/Recover operations before preparing new work/)).toBeVisible();
    await expect(page.getByRole('article', { name: /^Prepared PROPOSE / })).toHaveCount(owner ? 16 : 0);
    await expect(page.getByRole('textbox', { name: /^Prepare proposal reason/ })).toBeDisabled();
    if (owner && old) {
      await owner.assertRetained();
      await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
      await expect(page.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
      await expect(page.getByRole('article', { name: /^Prepared PROPOSE / })).toHaveCount(16);
      await page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
      await expect(page.getByText(/An empty operation list does not prove no effect/)).toBeVisible();
      owner.revoked = true;
      await owner.assertOldRejected(old.request);
      await login(page, 'proposer');
      await expect(page.getByRole('article', { name: /^Prepared PROPOSE / })).toHaveCount(0);
      await finding(page, fixture.scan_id, fixture.assessment_id);
    } else {
      await fixture.capacity!.assertRetained();
      await fixture.capacity!.releaseOne(); // Real owning-session logout, no quota/clock mutation.
      await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
      await expect(page.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
    }
    await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })
      .getByText(/An empty operation list does not prove no effect/)).toBeVisible();
    await expect(page.getByRole('textbox', { name: /^Prepare proposal reason/ })).toBeEnabled();
    console.log(sessionLimit ? 'D3_NATIVE_CAPACITY_16' : 'D3_NATIVE_CAPACITY_256');
  }, async () => { if (old) await old.close(); });
}

async function confirmWhileServerInFlight(page: Page, card: Locator): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true })
    .locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported initial operation');
  expect(before.state).toBe('PREPARED'); expect(before.attempts).toBe(0);
  const other = await page.context().newPage();
  let otherErrors = 0, otherWrites = 0;
  other.on('pageerror', () => { otherErrors += 1; });
  other.on('request', request => {
    if (new URL(request.url()).pathname.startsWith('/dashboard/api/') && request.method() !== 'GET') otherWrites += 1;
  });
  await runWithHistoryCleanup(async () => {
    const pending = page.waitForResponse(response => response.url() === origin + `/dashboard/api/remediation-operations/${key}/submit`);
    await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
    await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
    await expect.poll(async () => (await (await page.request.get(origin + '/__test/fixture')).json()).proposal_reply_gate).toBe('HELD');
    await expect.poll(async () => (await read(page, `remediation-operations/${key}`) as { state: string }).state).toBe('IN_FLIGHT');
    // The first real bearer call has committed, but its response has not reached BFF settlement.
    // A second native tab recovers actual server state, not a held CONFIRMED browser response.
    await other.goto(origin + '/dashboard/');
    const recovered = other.getByRole('article', { name: `Prepared PROPOSE ${key}`, exact: true });
    await expect(recovered.getByRole('heading', { name: 'PROPOSE · IN_FLIGHT', exact: true })).toBeVisible();
    await expect(recovered.getByText('Dispatch is in flight. Refresh coordination; do not submit another intent.', { exact: true })).toBeVisible();
    await expect(recovered.getByRole('checkbox')).toHaveCount(0);
    await expect(recovered.getByRole('button')).toHaveCount(0);
    await expect(card.getByRole('button', { name: 'Confirm and submit request', exact: true })).toBeDisabled();
    const active = await read(other, `remediation-operations/${key}`);
    if (!isPreparedOperation(active)) throw new Error('Unsupported in-flight operation');
    expect(samePrepared(before, active)).toBe(true); expect(active.state).toBe('IN_FLIGHT');
    expect(active.attempts).toBe(1); expect(active.result).toBeNull();
    expect(otherWrites).toBe(0); // No write on page mount/recovery.
    // An explicit same-key concurrent BFF POST must return the exact IN_FLIGHT snapshot.
    // The read-through test observer then releases the first genuine upstream response.
    const duplicate = await mutation(other, `remediation-operations/${key}/submit`, {});
    expect(duplicate.status()).toBe(200); expect(await duplicate.json()).toEqual(active);
    await expect.poll(async () => (await (await page.request.get(origin + '/__test/fixture')).json()).proposal_reply_gate).toBe('RETURNED');
    expect((await pending).status()).toBe(200);
    const settled = await read(page, `remediation-operations/${key}`);
    expect(isPreparedOperation(settled) && settled.state === 'CONFIRMED').toBe(true);
    await expect(card.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
    const after = await read(page, `remediation-operations/${key}`);
    if (!isPreparedOperation(after) || !after.result) throw new Error('Unsupported settled operation');
    expect(samePrepared(before, after)).toBe(true); expect(after.attempts).toBe(1);
    await other.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
    await expect(recovered.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
    expect(await read(other, `remediation-operations/${key}`)).toEqual(after);
    expect(otherErrors).toBe(0); expect(otherWrites).toBe(0);
    console.log('D3_NATIVE_SERVER_IN_FLIGHT');
  }, async () => { await other.close(); });
  const after = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(after) || !after.result) throw new Error('Missing confirmed proposal');
  return { result: after.result.result_id, key };
}

async function retainAfterCapabilityLoss(page: Page, card: Locator, fixture: IntegratedFixture): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true })
    .locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported reviewed operation');
  expect(before.state).toBe('PREPARED'); expect(before.attempts).toBe(0);
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  await expect(card.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  await expect(page.getByText('proposer · ADMIN', { exact: true })).toBeVisible(); // Stale display hint, not signed authority.
  const session = await (await page.request.get(origin + '/dashboard/session')).json();
  expect(session.roles).toEqual(['VIEWER']); expect(session.subject).toBe('proposer');
  expect(session.issuer).toBe('http://127.0.0.1:9032'); expect(session).not.toHaveProperty('access_token');
  const uncertain = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(uncertain)) throw new Error('Unsupported uncertain operation');
  expect(samePrepared(before, uncertain)).toBe(true); expect(uncertain.attempts).toBe(1); expect(uncertain.result).toBeNull();
  await expect(card.getByRole('button', { name: 'Explicitly retry original request' })).toBeDisabled();
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  const rejected = page.waitForResponse(response => response.url() === origin + `/dashboard/api/remediation-operations/${key}/submit`);
  await card.getByRole('button', { name: 'Explicitly retry original request' }).click();
  expect((await rejected).status()).toBe(403);
  await expect(page.getByText('Submission outcome is unconfirmed. Refresh operations or explicitly retry the original operation. Do not replace its key or assume cancellation.', { exact: true })).toBeVisible();
  expect(await read(page, `remediation-operations/${key}`)).toEqual(uncertain);
  // A denied retry does not erase a real prior commit or authorize a replacement key.
  const values = await read(page, `remediations?finding_id=${fixture.finding_id}`);
  if (!proposalPage(values) || values.total !== 1 || values.items.length !== 1) throw new Error('Missing sole committed proposal');
  const proposal = values.items[0];
  expect(proposal.content.proposer.roles).toEqual(['ANALYST']);
  expect(proposal.content.baseline.occurrence_id).toBe(fixture.occurrence_id);
  await page.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
  await expect(page.getByRole('button', { name: `Open proposal ${proposal.content.proposal_id}`, exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  expect(await read(page, `remediation-operations/${key}`)).toEqual(uncertain);
  await page.reload(); // Genuine fresh session GET replaces the cached ADMIN display hint.
  await expect(page.getByText('proposer · VIEWER', { exact: true })).toBeVisible();
  const recovered = page.getByRole('article', { name: `Prepared PROPOSE ${key}`, exact: true });
  await expect(recovered.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  await expect(recovered.getByRole('checkbox')).toBeDisabled();
  await expect(recovered.getByRole('button', { name: 'Explicitly retry original request' })).toBeDisabled();
  expect(await read(page, `remediation-operations/${key}`)).toEqual(uncertain);
  console.log('D3_NATIVE_SIGNED_CAPABILITY_LOSS');
  return { result: proposal.content.proposal_id, key };
}

async function retainExpiredCapacity(page: Page, card: Locator, fixture: IntegratedFixture): Promise<{ result: string; key: string }> {
  const key = (await card.getByText('Prepared operation UUID', { exact: true })
    .locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported expiry preparation');
  expect(before.state).toBe('PREPARED'); expect(before.attempts).toBe(0);
  expect(before.expires_at - before.prepared_at).toBe(300);
  const owner = new CapacityOwner(page.request); await owner.attach();
  if (fixture.scenario === 'expiry-session') await owner.fillExpiry(before);
  else if (!fixture.capacity) throw new Error('Missing owned expiry cohort');
  await owner.rejectExtra(); // Real full capacity; no expired record has been evicted.
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  await expect(card.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  const uncertain = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(uncertain)) throw new Error('Unsupported expired forwarded operation');
  expect(samePrepared(before, uncertain)).toBe(true); expect(uncertain.attempts).toBe(1); expect(uncertain.result).toBeNull();
  if (fixture.scenario === 'expiry-session') expect(await owner.retainAfterExpiry(uncertain)).toBe(15);
  else await fixture.capacity!.retainAfterExpiry();
  await owner.rejectExtra(); // Still full after ordinary expiry, including the uncertain operation.
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'PROPOSE · EXPIRED', exact: true })).toHaveCount(fixture.scenario === 'expiry-session' ? 15 : 0);
  if (fixture.scenario === 'expiry-session') {
    for (const expired of await page.getByRole('article').filter({ has: page.getByRole('heading', { name: 'PROPOSE · EXPIRED', exact: true }) }).all()) {
      await expect(expired.getByRole('checkbox')).toHaveCount(0);
      await expect(expired.getByRole('button')).toHaveCount(0);
      await expect(expired.getByText('Preparation cannot be renewed. Expiry is not cancellation of any prior effects; review immutable history.', { exact: true })).toBeVisible();
    }
  }
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  const rejected = page.waitForResponse(response => response.url() === origin + `/dashboard/api/remediation-operations/${key}/submit`);
  await card.getByRole('button', { name: 'Explicitly retry original request' }).click();
  expect((await rejected).status()).toBe(409);
  const denied = await mutation(page, `remediation-operations/${key}/submit`, {});
  expect(denied.status()).toBe(409);
  expect(await denied.json()).toEqual({ detail: 'Preparation expired; prior effects are not canceled' });
  expect(await read(page, `remediation-operations/${key}`)).toEqual(uncertain);
  const history = await read(page, `remediations?finding_id=${fixture.finding_id}`);
  if (!proposalPage(history) || history.total !== 1 || history.items.length !== 1) throw new Error('Missing retained commit after expiry');
  await page.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
  const result = history.items[0].content.proposal_id;
  await expect(page.getByRole('button', { name: `Open proposal ${result}`, exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'PROPOSE · EXPIRED', exact: true })).toHaveCount(fixture.scenario === 'expiry-session' ? 15 : 0);
  expect(await read(page, `remediation-operations/${key}`)).toEqual(uncertain);
  if (fixture.scenario === 'expiry-session') await owner.assertRetained(); else await fixture.capacity!.assertRetained();
  console.log(fixture.scenario === 'expiry-session' ? 'D3_NATIVE_EXPIRED_16' : 'D3_NATIVE_EXPIRED_256');
  return { result, key };
}

async function expiredProposal(proposer: Page, approver: Page, requester: Page,
  fixture: IntegratedFixture, result: string, proposal: Proposal) {
  expect(proposal.approval_status).toBe('PROPOSED'); expect(proposal.decisions).toEqual([]);
  expect(proposal.blocking_reasons).toEqual(['EXPIRED']);
  expect(Date.parse(proposal.content.expires_at) - Date.parse(proposal.content.created_at)).toBe(86400000);
  expect(Date.parse(proposal.validity_checked_at)).toBeGreaterThanOrEqual(Date.parse(proposal.content.expires_at));
  for (const page of [approver, requester]) {
    await finding(page, fixture.scan_id, fixture.assessment_id);
    await page.getByRole('button', { name: `Open proposal ${result}`, exact: true }).click();
    await expect(datum(page, 'Historical approval')).toHaveText('PROPOSED');
    await expect(datum(page, 'Current proposal blockers')).toHaveText('EXPIRED');
    await expect(page.getByRole('button', { name: 'Prepare approval', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Prepare execution admission', exact: true })).toHaveCount(0);
    if (page === requester) await expect(page.getByText('Execution admission requires a retained approval.', { exact: true })).toBeVisible();
  }
  await approver.getByRole('textbox', { name: /^Prepare rejection reason/ }).fill('A rejection may close expired authority, but this story retains no decision.');
  await expect(approver.getByRole('button', { name: 'Prepare rejection', exact: true })).toBeEnabled();
  // A genuine signed BFF attempt independently verifies that disabled UI controls are not authority.
  const response = await mutation(approver, 'remediation-operations', { schema_version: '1.0.0', operation: 'DECIDE',
    target_id: result, input: { proposal_sha256: proposal.proposal_sha256, decision: 'APPROVE', reason: 'Expired authority cannot gain approval.' } });
  expect(response.status()).toBe(201);
  const prepared: unknown = await response.json();
  if (!isPreparedOperation(prepared)) throw new Error('Unsupported expired approval preparation');
  expect(prepared.actor.subject).toBe('approver'); expect(prepared.state).toBe('PREPARED');
  const submitted = await mutation(approver, `remediation-operations/${prepared.operation_id}/submit`, {});
  expect(submitted.status()).toBe(200);
  const denied: unknown = await submitted.json();
  if (!isPreparedOperation(denied)) throw new Error('Unsupported expired approval outcome');
  expect(samePrepared(prepared, denied)).toBe(true);
  expect(denied.state).toBe('UNCONFIRMED'); expect(denied.attempts).toBe(1); expect(denied.result).toBeNull();
  await approver.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect(approver.getByRole('heading', { name: 'DECIDE · UNCONFIRMED', exact: true })).toBeVisible();
  for (const page of [proposer, approver, requester]) {
    const retained = await read(page, `remediations/${result}`);
    if (!isProposal(retained)) throw new Error('Unsupported retained expired proposal');
    expect(retained.content).toEqual(proposal.content); expect(retained.proposal_sha256).toBe(proposal.proposal_sha256);
    expect(retained.approval_status).toBe('PROPOSED'); expect(retained.blocking_reasons).toEqual(['EXPIRED']);
    expect(retained.decisions).toEqual([]);
  }
  const evidence = await (await proposer.request.get(origin + '/__test/fixture')).json();
  expect(evidence.scan_submissions).toBe(0); expect(evidence.proposal_response_losses).toBe(1);
  console.log('D3_NATIVE_EXPIRED_PROPOSAL_NO_EXECUTION');
}

async function finishAuthorityPages(pages: Page[]) {
  for (const page of pages) {
    expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
    expect((await page.request.post(origin + '/dashboard/api/scans', { data: {} })).status()).toBe(405);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
    await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
  }
}

async function authorityCutoff(pages: Page[], fixture: IntegratedFixture, result: { result: string; key: string }, approved: boolean) {
  const [proposer, approver, requester] = pages;
  const original = await read(proposer, `remediations/${result.result}`);
  if (!isProposal(original)) throw new Error('Unsupported original authority');
  expect(original.approval_status).toBe(approved ? 'APPROVED' : 'PROPOSED');
  expect(original.blocking_reasons).toEqual([]);
  expect(original.decisions).toHaveLength(approved ? 1 : 0);
  const command = fixture.scenario === 'admission-stale' ? 'COLLECT_STALE' : 'CHANGE_GOVERNANCE';
  await fixture.control(command, result.result, result.key);
  await fixture.control(command, result.result, result.key); // Parent fence retains the original proof.
  for (const page of pages) {
    if (page !== proposer && !(approved && page === approver)) await finding(page, fixture.scan_id, fixture.assessment_id);
    await page.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
    await page.getByRole('button', { name: `Open proposal ${result.result}`, exact: true }).click();
    await expect(datum(page, 'Historical approval')).toHaveText(original.approval_status);
    await expect(datum(page, 'Current proposal blockers')).toContainText(scenarioExpected[fixture.scenario].reason);
    await expect(page.getByText('No execution requests on this page.', { exact: true })).toBeVisible();
    const current = await read(page, `remediations/${result.result}`);
    if (!isProposal(current)) throw new Error('Unsupported current authority projection');
    expect(current.content).toEqual(original.content); expect(current.proposal_sha256).toBe(original.proposal_sha256);
    expect(current.decisions).toEqual(original.decisions); expect(current.approval_status).toBe(original.approval_status);
    expect(current.blocking_reasons).toContain(scenarioExpected[fixture.scenario].reason);
    if (fixture.scenario.startsWith('governance-')) expect(current.blocking_reasons).toContain('STALE_GOVERNANCE');
  }
  const page = approved ? requester : approver, title = approved ? 'Prepare execution admission' : 'Prepare approval';
  await expect(page.getByText(approved ? /Current proposal blockers prevent admission/ : /Current blockers prevent approval/)).toBeVisible();
  await expect(page.getByRole('textbox', { name: new RegExp('^' + title + ' reason') })).toBeDisabled();
  await expect(page.getByRole('button', { name: title, exact: true })).toBeDisabled();
  const approval = original.decisions.find(decision => decision.kind === 'APPROVE');
  if (approved && !approval) throw new Error('Missing original signed approval');
  const operation = approved ? 'REQUEST_EXECUTION' : 'DECIDE';
  const response = await mutation(page, 'remediation-operations', { schema_version: '1.0.0', operation,
    target_id: result.result, input: { proposal_sha256: original.proposal_sha256,
      reason: 'Current blockers must not revive retained authority.',
      ...(approved ? { approval_decision_id: approval!.decision_id } : { decision: 'APPROVE' }) } });
  expect(response.status()).toBe(201);
  const prepared: unknown = await response.json();
  if (!isPreparedOperation(prepared)) throw new Error('Unsupported blocked preparation');
  const submitted = await mutation(page, `remediation-operations/${prepared.operation_id}/submit`, {});
  expect(submitted.status()).toBe(200);
  const denied: unknown = await submitted.json();
  if (!isPreparedOperation(denied)) throw new Error('Unsupported blocked result');
  expect(samePrepared(prepared, denied)).toBe(true); expect(denied.state).toBe('UNCONFIRMED');
  expect(denied.attempts).toBe(1); expect(denied.result).toBeNull();
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect(page.getByRole('heading', { name: `${operation} · UNCONFIRMED`, exact: true })).toBeVisible();
  console.log('D3_NATIVE_RETAINED_AUTHORITY_CUTOFF');
}

async function staleProposal(pages: Page[], fixture: IntegratedFixture, result: { result: string; key: string }) {
  const [proposer, approver] = pages;
  const original = await read(proposer, `remediations/${result.result}`);
  if (!isProposal(original)) throw new Error('Unsupported original stale proposal');
  expect(original.blocking_reasons).toEqual([]);
  await fixture.control('COLLECT_STALE', result.result, result.key);
  await fixture.control('COLLECT_STALE', result.result, result.key); // Same parent proof; never a second collection.
  expect(await read(proposer, 'scans')).toMatchObject({ total: 2 });
  for (const page of pages) {
    if (page !== proposer) await finding(page, fixture.scan_id, fixture.assessment_id);
    await page.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
    await page.getByRole('button', { name: `Open proposal ${result.result}`, exact: true }).click();
    await expect(datum(page, 'Historical approval')).toHaveText('PROPOSED');
    await expect(datum(page, 'Current proposal blockers')).toContainText('STALE_TARGET');
    await expect(page.getByText('No execution requests on this page.', { exact: true })).toBeVisible();
    const retained = await read(page, `remediations/${result.result}`);
    if (!isProposal(retained)) throw new Error('Unsupported retained stale proposal');
    expect(retained.content).toEqual(original.content); expect(retained.proposal_sha256).toBe(original.proposal_sha256);
    expect(retained.decisions).toEqual([]); expect(retained.blocking_reasons).toContain('STALE_TARGET');
  }
  await expect(approver.getByText(/Current blockers prevent approval/)).toBeVisible();
  await expect(approver.getByRole('textbox', { name: /^Prepare approval reason/ })).toBeDisabled();
  await expect(approver.getByRole('button', { name: 'Prepare approval', exact: true })).toBeDisabled();
  const response = await mutation(approver, 'remediation-operations', { schema_version: '1.0.0', operation: 'DECIDE',
    target_id: result.result, input: { proposal_sha256: original.proposal_sha256, decision: 'APPROVE', reason: 'The genuine service must deny stale approval.' } });
  expect(response.status()).toBe(201);
  const prepared: unknown = await response.json();
  if (!isPreparedOperation(prepared)) throw new Error('Unsupported stale approval preparation');
  const submitted = await mutation(approver, `remediation-operations/${prepared.operation_id}/submit`, {});
  expect(submitted.status()).toBe(200);
  const denied: unknown = await submitted.json();
  if (!isPreparedOperation(denied)) throw new Error('Unsupported stale approval outcome');
  expect(samePrepared(prepared, denied)).toBe(true);
  expect(denied.state).toBe('UNCONFIRMED'); expect(denied.attempts).toBe(1); expect(denied.result).toBeNull();
  await approver.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect(approver.getByRole('heading', { name: 'DECIDE · UNCONFIRMED', exact: true })).toBeVisible();
  console.log('D3_NATIVE_COLLECTED_STALE_EVIDENCE_DENIED_APPROVAL');
}

async function sessionLossAfterCommit(pages: Page[], fixture: IntegratedFixture, card: Locator) {
  const [proposer] = pages;
  const key = (await card.getByText('Prepared operation UUID', { exact: true }).locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const original = await read(proposer, `remediation-operations/${key}`);
  if (!isPreparedOperation(original)) throw new Error('Unsupported original preparation');
  const session = await (await proposer.request.get(origin + '/dashboard/session')).json();
  expect(session.authenticated).toBe(true); expect(session.subject).toBe('proposer');
  if (fixture.scenario === 'idle-expiry') expect(session.expires_at).toBeGreaterThan(session.idle_expires_at);
  else if (fixture.scenario === 'token-expiry') expect(session.expires_at).toBeLessThan(session.idle_expires_at);
  const reply = proposer.waitForResponse(response => response.url() === origin + `/dashboard/api/remediation-operations/${key}/submit`);
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  const response = await reply;
  expect(response.status()).toBe(fixture.scenario === 'idle-expiry' ? 401 : 200);
  const substituted = fixture.scenario === 'subject-replacement' || fixture.scenario === 'issuer-rejection';
  if (fixture.scenario === 'token-expiry' || substituted) {
    const value: unknown = await response.json();
    if (!isPreparedOperation(value)) throw new Error('Unsupported committed uncertainty');
    expect(samePrepared(original, value)).toBe(true);
    expect(value.state).toBe('UNCONFIRMED'); expect(value.attempts).toBe(1); expect(value.result).toBeNull();
    await expect(card.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
    if (substituted) {
      // The real signed verifier, not a fulfilled response or local logout, rejects this session.
      const rejected = proposer.waitForResponse(response => response.url() === origin + '/dashboard/api/remediation-operations'
        && response.request().method() === 'GET');
      await proposer.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
      expect((await rejected).status()).toBe(401);
    } else {
      // Real, initially signed ten-second token; no JWT/browser/global-clock patch or timeout increase.
      const remaining = session.expires_at * 1000 - Date.now() + 50;
      expect(remaining).toBeGreaterThan(0); expect(remaining).toBeLessThanOrEqual(11000);
      await proposer.waitForTimeout(remaining);
    }
  }
  await expect(proposer.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(proposer.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
  await expect(proposer.getByRole('region', { name: 'Remediation history', exact: true })).toHaveCount(0);
  await expect(proposer.getByRole('article', { name: `Prepared PROPOSE ${key}`, exact: true })).toHaveCount(0);
  await expect(proposer.getByText(/Submitted requests are not canceled/)).toBeVisible();
  expect((await proposer.request.get(origin + `/dashboard/api/remediation-operations/${key}`,
    { headers: { 'X-Dashboard-Context': session.session_context } })).status()).toBe(401);
  // A fresh explicit Code/PKCE login is not coordination recovery or a replacement operation.
  await login(proposer, 'proposer');
  const fresh = await (await proposer.request.get(origin + '/dashboard/session')).json();
  expect(fresh.subject).toBe('proposer'); expect(fresh.issuer).toBe(session.issuer);
  expect(fresh.session_context).not.toBe(session.session_context);
  expect(await read(proposer, 'remediation-operations')).toEqual({ schema_version: '1.0.0', items: [] });
  expect((await mutation(proposer, `remediation-operations/${key}/submit`, {})).status()).toBe(404);
  const history = await read(proposer, 'remediations');
  if (!proposalPage(history)) throw new Error('Unsupported manual immutable history');
  expect(history.total).toBe(1); expect(history.items).toHaveLength(1);
  const proposal = history.items[0];
  expect(proposal.content.proposer.subject).toBe('proposer'); expect(proposal.content.proposer.issuer).toBe(session.issuer);
  expect(proposal.content.baseline.occurrence_id).toBe(fixture.occurrence_id);
  expect(proposal.approval_status).toBe('PROPOSED'); expect(proposal.decisions).toEqual([]); expect(proposal.blocking_reasons).toEqual([]);
  for (const [index, page] of pages.entries()) {
    if (index > 0) await login(page, index === 1 ? 'approver' : 'requester');
    await finding(page, fixture.scan_id, fixture.assessment_id);
    await page.getByRole('button', { name: `Open proposal ${proposal.content.proposal_id}`, exact: true }).click();
    await expect(datum(page, 'Historical approval')).toHaveText('PROPOSED');
    await expect(datum(page, 'Current proposal blockers')).toHaveText('None reported at this read');
    await expect(page.getByText('No execution requests on this page.', { exact: true })).toBeVisible();
    const retained = await read(page, `remediations/${proposal.content.proposal_id}`);
    if (!isProposal(retained)) throw new Error('Unsupported retained proposal after session loss');
    expect(retained.content).toEqual(proposal.content); expect(retained.proposal_sha256).toBe(proposal.proposal_sha256);
  }
  const evidence = await (await proposer.request.get(origin + '/__test/fixture')).json();
  expect(evidence.scan_submissions).toBe(0); expect(evidence.proposal_response_losses).toBe(1);
  console.log(substituted ? 'D3_NATIVE_SUBSTITUTED_IDENTITY_REJECTED_MANUAL_HISTORY' : 'D3_NATIVE_EXPIRED_SESSION_MANUAL_HISTORY');
}

async function crossIssuerRestart(pages: Page[], fixture: IntegratedFixture, card: Locator) {
  const [proposer, approver, requester] = pages;
  const key = (await card.getByText('Prepared operation UUID', { exact: true }).locator('xpath=following-sibling::dd[1]').innerText()).trim();
  const before = await read(proposer, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported original authority preparation');
  const old = await (await proposer.request.get(origin + '/dashboard/session')).json();
  expect(old.issuer).toBe('http://127.0.0.1:9032'); expect(old.subject).toBe('proposer'); expect(old.roles).toEqual(['ANALYST']);
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  await expect(card.getByRole('heading', { name: 'PROPOSE · UNCONFIRMED', exact: true })).toBeVisible();
  const uncertain = await read(proposer, `remediation-operations/${key}`);
  if (!isPreparedOperation(uncertain)) throw new Error('Unsupported original authority uncertainty');
  expect(samePrepared(before, uncertain)).toBe(true); expect(uncertain.attempts).toBe(1); expect(uncertain.result).toBeNull();
  const history = await read(proposer, 'remediations');
  if (!proposalPage(history)) throw new Error('Unsupported original issuer history');
  expect(history.total).toBe(1); expect(history.items).toHaveLength(1);
  const original = history.items[0], result = original.content.proposal_id;
  expect(original.content.proposer.issuer).toBe(old.issuer); expect(original.content.proposer.subject).toBe(old.subject);
  expect((await (await proposer.request.get(origin + '/__test/fixture')).json()).proposal_response_losses).toBe(1);
  await fixture.control('RESTART_AUTHORITY', result, key);
  // Exact same control reply is fenced; it cannot stop/restart the replacement process again.
  await fixture.control('RESTART_AUTHORITY', result, key);
  const failed = proposer.waitForResponse(response => response.url() === origin + '/dashboard/api/remediation-operations' && response.request().method() === 'GET');
  await proposer.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  expect((await failed).status()).toBe(401);
  await expect(proposer.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(proposer.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
  await expect(proposer.getByRole('region', { name: 'Remediation history', exact: true })).toHaveCount(0);
  await expect(proposer.getByText(/Submitted requests are not canceled/)).toBeVisible();
  await login(proposer, 'proposer');
  const fresh = await (await proposer.request.get(origin + '/dashboard/session')).json();
  expect(fresh.issuer).toBe('http://127.0.0.1:9032/issuer-b'); expect(fresh.subject).toBe(old.subject); expect(fresh.roles).toEqual(['ADMIN']);
  expect(fresh.session_context).not.toBe(old.session_context);
  expect(await read(proposer, 'remediation-operations')).toEqual({ schema_version: '1.0.0', items: [] });
  expect((await proposer.request.get(origin + `/dashboard/api/remediation-operations/${key}`, { headers: { 'X-Dashboard-Context': fresh.session_context } })).status()).toBe(404);
  expect((await mutation(proposer, `remediation-operations/${key}/submit`, {})).status()).toBe(404);
  expect((await proposer.request.get(origin + '/dashboard/api/remediation-operations', { headers: { 'X-Dashboard-Context': old.session_context } })).status()).toBe(401);
  const retained = await read(proposer, `remediations/${result}`);
  if (!isProposal(retained)) throw new Error('Unsupported cross-issuer immutable proposal');
  expect(retained.content).toEqual(original.content); expect(retained.proposal_sha256).toBe(original.proposal_sha256);
  await Promise.all([login(approver, 'approver'), login(requester, 'requester')]);
  const review = await (await approver.request.get(origin + '/dashboard/session')).json();
  expect(review.issuer).toBe(fresh.issuer); expect(review.subject).toBe(old.subject); expect(review.roles).toEqual(['APPROVER']);
  console.log('D3_NATIVE_CROSS_ISSUER_RECONCILED');
  return { result, key };
}

async function denySameIssuerSubjectAdminExecution(page: Page, fixture: IntegratedFixture, proposalId: string, approvalId: string) {
  await finding(page, fixture.scan_id, fixture.assessment_id);
  await page.getByRole('button', { name: `Open proposal ${proposalId}`, exact: true }).click();
  await expect(page.getByText('Execution admission requires a third distinct issuer/subject pair, even for ADMIN.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Prepare execution admission', exact: true })).toHaveCount(0);
  const proposal = await read(page, `remediations/${proposalId}`);
  if (!isProposal(proposal)) throw new Error('Unsupported approved cross-issuer proposal');
  const prepared = await mutation(page, 'remediation-operations', { schema_version: '1.0.0', operation: 'REQUEST_EXECUTION', target_id: proposalId,
    input: { proposal_sha256: proposal.proposal_sha256, approval_decision_id: approvalId, reason: 'ADMIN must not bypass the same verified approval identity.' } });
  expect(prepared.status()).toBe(201);
  const operation: unknown = await prepared.json();
  if (!isPreparedOperation(operation)) throw new Error('Unsupported guarded execution preparation');
  const submitted = await mutation(page, `remediation-operations/${operation.operation_id}/submit`, {});
  expect(submitted.status()).toBe(200);
  const denied: unknown = await submitted.json();
  if (!isPreparedOperation(denied)) throw new Error('Unsupported guarded execution result');
  expect(samePrepared(operation, denied)).toBe(true); expect(denied.state).toBe('UNCONFIRMED'); expect(denied.attempts).toBe(1); expect(denied.result).toBeNull();
  const empty = await read(page, `remediation-executions?proposal_id=${proposalId}`);
  if (!executionPage(empty)) throw new Error('Unsupported guarded execution history');
  expect(empty.total).toBe(0); expect(empty.items).toEqual([]);
}

async function revokeNativeApproval(page: Page, proposal: Proposal, approval: string) {
  await page.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
  await page.getByRole('button', { name: `Open proposal ${proposal.content.proposal_id}`, exact: true }).click();
  await expect(page.getByText(/Revocation is not cancellation or proof of no earlier effect/)).toBeVisible();
  const operation = await confirm(await prepare(page, 'Prepare revocation', 'REVOKE'), 'REVOKE');
  const value = await read(page, `remediations/${proposal.content.proposal_id}`);
  if (!isProposal(value)) throw new Error('Unsupported revoked authority');
  expect(value.content).toEqual(proposal.content); expect(value.proposal_sha256).toBe(proposal.proposal_sha256);
  expect(value.approval_status).toBe('REVOKED'); expect(value.decisions.map(d => d.kind)).toEqual(['APPROVE', 'REVOKE']);
  expect(value.decisions[0].decision_id).toBe(approval);
  expect(value.decisions[1].decision_id).toBe(operation.result);
  expect(value.decisions[1].approval_decision_id).toBe(approval);
  expect(value.decisions[1].actor.subject).toBe('approver');
  expect(value.decisions[1].actor.roles).toEqual(['APPROVER']);
  await page.getByRole('button', { name: `Open proposal ${proposal.content.proposal_id}`, exact: true }).click();
  await expect(datum(page, 'Historical approval')).toHaveText('REVOKED');
  await expect(page.getByRole('button', { name: 'Prepare revocation', exact: true })).toHaveCount(0);
}

async function retainSameScanSelection(page: Page, fixture: IntegratedFixture, proposal: Proposal) {
  await page.getByRole('button', { name: `Open proposal ${proposal.content.proposal_id}`, exact: true }).click();
  await expect(datum(page, 'Proposal SHA-256')).toHaveText(proposal.proposal_sha256);
  let reportReads = 0;
  const observed = (request: Request) => {
    if (request.method() === 'GET' && [origin + `/dashboard/api/scans/${fixture.scan_id}`,
      origin + `/dashboard/api/scans/${fixture.scan_id}/technical-posture`].includes(request.url())) reportReads += 1;
  };
  page.on('request', observed);
  await runWithHistoryCleanup(async () => {
    for (const via of ['form', 'history row'] as const) {
      if (via === 'form') {
        await page.getByLabel('Open scan by UUID').fill(`  ${fixture.scan_id.toUpperCase()}  `);
        await page.getByRole('button', { name: 'Open scan', exact: true }).click();
      } else await page.getByRole('button', { name: new RegExp(fixture.scan_id), pressed: true }).click();
      await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      await expect(page.getByLabel('Open scan by UUID')).toHaveValue(fixture.scan_id);
      await expect(datum(page, 'Proposal SHA-256')).toHaveText(proposal.proposal_sha256);
      await expect(datum(page, 'Historical approval')).toHaveText('PROPOSED');
      await expect(page.getByText('Loading selected scan…', { exact: true })).toHaveCount(0);
      expect(new URL(page.url()).searchParams.get('scan')).toBe(fixture.scan_id);
      expect(reportReads).toBe(0);
    }
    console.log('D3_NATIVE_SAME_SCAN_RETAINED');
  }, async () => { page.off('request', observed); });
}

async function retainAfterFeatureHints(page: Page, fixture: IntegratedFixture, key: string, proposal: Proposal) {
  const before = await read(page, `remediation-operations/${key}`);
  if (!isPreparedOperation(before)) throw new Error('Unsupported operation before feature hint loss');
  expect(before.state).toBe('CONFIRMED'); expect(before.attempts).toBe(1);
  expect(before.result?.result_id).toBe(proposal.content.proposal_id);
  await retainSameScanSelection(page, fixture, proposal);
  for (const mode of ['disabled', 'missing'] as const) {
    let substituted = 0;
    await page.route(origin + '/dashboard/session', async route => {
      expect(route.request().method()).toBe('GET');
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      const actual = await response.json();
      expect(actual.authenticated).toBe(true); expect(actual.subject).toBe('proposer');
      expect(actual.roles).toEqual(['ANALYST']); expect(actual.features).toEqual({ remediation: true });
      expect(actual.issuer).toBe(proposal.content.proposer.issuer);
      expect(actual).not.toHaveProperty('access_token');
      const untrusted: Record<string, unknown> = { ...actual, features: { remediation: false } };
      if (mode === 'missing') delete untrusted.features;
      substituted += 1;
      await route.fulfill({ response, contentType: 'application/json', body: JSON.stringify(untrusted) });
    });
    await runWithHistoryCleanup(async () => {
      await page.reload();
      await expect(page.getByText('Read-only security console', { exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
      await expect(page.getByRole('link', { name: 'Manual operations', exact: true })).toHaveCount(0);
      await page.getByRole('button', { name: 'Back to scan selection', exact: true }).click();
      await expect(page.getByLabel('Open scan by UUID')).toBeFocused();
      await finding(page, fixture.scan_id, fixture.assessment_id);
      await page.getByRole('button', { name: `Open proposal ${proposal.content.proposal_id}`, exact: true }).click();
      await expect(datum(page, 'Proposal SHA-256')).toHaveText(proposal.proposal_sha256);
      await expect(datum(page, 'Historical approval')).toHaveText('PROPOSED');
      await expect(page.getByRole('button', { name: /^Prepare / })).toHaveCount(0);
      expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
      expect(substituted).toBe(1);
      // Browser hints are not server configuration or grants. Real signed READ remains enabled.
      expect(await read(page, `remediation-operations/${key}`)).toEqual(before);
    }, async () => { await page.unroute(origin + '/dashboard/session'); });
  }
  await page.reload();
  await expect(page.getByText('Human-approved remediation console', { exact: true })).toBeVisible();
  const card = page.getByRole('article', { name: `Prepared PROPOSE ${key}`, exact: true });
  await expect(card.getByRole('heading', { name: 'PROPOSE · CONFIRMED', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
  await expect(page.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
  const recovered = await read(page, 'remediation-operations');
  expect(recovered).toEqual({ schema_version: '1.0.0', items: [before] });
  const retained = await read(page, `remediations/${proposal.content.proposal_id}`);
  if (!isProposal(retained)) throw new Error('Unsupported retained proposal after feature hints');
  expect(retained.content).toEqual(proposal.content); expect(retained.proposal_sha256).toBe(proposal.proposal_sha256);
  expect(retained.decisions).toEqual([]); expect(retained.approval_status).toBe('PROPOSED');
  console.log('D3_NATIVE_FEATURE_HINTS_RETAINED');
}

async function rejectUnsupportedDetail(page: Page, kind: 'proposal' | 'execution' | 'verification', id: string) {
  const collection = { proposal: 'remediations', execution: 'remediation-executions', verification: 'remediation-verifications' }[kind];
  const label = { proposal: 'Historical approval', execution: 'Execution phase', verification: 'Verification verdict' }[kind];
  let substituted = 0;
  const path = origin + `/dashboard/api/${collection}/${id}`;
  await page.route(path, async route => {
    expect(route.request().method()).toBe('GET');
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    const actual = await response.json();
    const untrusted = structuredClone(actual);
    if (kind === 'proposal') {
      if (!isProposal(actual)) throw new Error('Unsupported genuine proposal before version fault');
      expect(actual.content.proposal_id).toBe(id);
      untrusted.content.schema_version = '9.0.0';
    } else if (kind === 'execution') {
      if (!isExecution(actual)) throw new Error('Unsupported genuine execution before version fault');
      expect(actual.content.execution_id).toBe(id); expect(actual.phase).toBe('ACKNOWLEDGED');
      expect(actual.events.map(event => event.content.schema_version)).toEqual(['1.0.0', ...Array(actual.events.length - 1).fill('2.0.0')]);
      untrusted.events[1].content.schema_version = '3.0.0';
    } else {
      if (!isVerification(actual) || !actual.receipt) throw new Error('Missing genuine sealed receipt before version fault');
      expect(actual.content.verification_id).toBe(id); expect(actual.receipt.outcome).toBe('VERIFIED');
      untrusted.receipt.schema_version = '9.0.0';
    }
    substituted += 1;
    await route.fulfill({ response, contentType: 'application/json', body: JSON.stringify(untrusted) });
  }, { times: 1 });
  await runWithHistoryCleanup(async () => {
    await page.getByRole('button', { name: `Open ${kind} ${id}`, exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'The server returned an unsupported response. Nothing has been assumed.' })).toBeVisible();
    await expect(datum(page, label)).toHaveCount(0);
    if (kind === 'proposal') {
      await expect(page.getByRole('button', { name: 'Prepare approval', exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Prepare execution admission', exact: true })).toHaveCount(0);
    } else if (kind === 'execution') await expect(page.getByRole('button', { name: 'Prepare linked verification', exact: true })).toHaveCount(0);
    else {
      // A rejected detail cannot invent a verdict. The independently valid ACK/history list
      // still permits another explicit read-only request under the accepted three-attempt policy.
      await expect(page.getByRole('button', { name: 'Prepare linked verification', exact: true })).toBeVisible();
    }
    expect(substituted).toBe(1);
    // Reopen performs a new authenticated GET. No response, version or history is repaired in storage.
    await page.getByRole('button', { name: `Close ${kind} detail`, exact: true }).click();
    await page.getByRole('button', { name: `Open ${kind} ${id}`, exact: true }).click();
    await expect(datum(page, label)).toHaveText(kind === 'proposal' ? 'PROPOSED' : kind === 'execution' ? 'ACKNOWLEDGED' : 'VERIFIED');
    await expect(page.getByRole('alert').filter({ hasText: 'The server returned an unsupported response. Nothing has been assumed.' })).toHaveCount(0);
    console.log('D3_NATIVE_UNSUPPORTED_' + kind.toUpperCase() + '_RECOVERED');
  }, async () => { await page.unroute(path); });
}

async function nativeJourney(browser: Browser, fixture: IntegratedFixture) {
  const expected = scenarioExpected[fixture.scenario];
  const roles = fixture.scenario === 'verified', keyboard = fixture.scenario === 'partial';
  const proposalExpiry = fixture.scenario === 'proposal-expiry';
  const crossIssuer = fixture.scenario === 'cross-issuer';
  const stale = fixture.scenario.startsWith('stale-');
  const governance = fixture.scenario.startsWith('governance-');
  const approvedCutoff = fixture.scenario === 'admission-stale' || fixture.scenario === 'governance-round-trip';
  const sessionLoss = fixture.scenario === 'idle-expiry' || fixture.scenario === 'token-expiry'
    || fixture.scenario === 'subject-replacement' || fixture.scenario === 'issuer-rejection';
  const executionExpiry = fixture.scenario === 'execution-expiry';
  const revokedBefore = fixture.scenario === 'revoked-before-intent', revokedAfter = fixture.scenario === 'revoked-after-ack';
  let revocationDone = false;
  const upstreamLoss = fixture.scenario === 'uncertain-submit' || proposalExpiry;
  const referenceFault = fixture.scenario === 'reply-reference' || fixture.scenario === 'history-reference';
  const capabilityLoss = fixture.scenario === 'capability-loss';
  const expiry = fixture.scenario === 'expiry-session' || fixture.scenario === 'expiry-global';
  const recoveryGuards = fixture.scenario === 'recovery-guards';
  const capacity = fixture.scenario === 'capacity-session' || fixture.scenario === 'capacity-global';
  const quarantined = fixture.scenario === 'quarantine' || fixture.scenario === 'late-ack';
  const limited = fixture.scenario === 'attempt-limit', attempts = quarantined || executionExpiry || revokedBefore ? 0 : limited ? 3 : 1;
  const started = Date.now();
  const checkpoint = (stage: string) => console.log(`D3_NATIVE_${stage} ${Date.now() - started}ms`);
  const identities = roles ? ['proposer', 'approver', 'requester', 'viewer']
    : limited ? ['proposer', 'approver', 'requester', 'requester'] : ['proposer', 'approver', 'requester'];
  const contexts = await Promise.all(identities.map(() => browser.newContext({ baseURL: origin,
    viewport: keyboard ? { width: 390, height: 844 } : { width: 1280, height: 800 } })));
  let cleaning = false, lifecycleFailures = 0;
  const lifecycle = (event: 'BROWSER_DISCONNECTED' | 'CONTEXT_CLOSED' | 'PAGE_CLOSED' | 'PAGE_CRASHED') => {
    if (cleaning) return;
    lifecycleFailures += 1;
    // Closed categories only: never emit browser stderr, URLs, cookies or response bodies.
    try { console.error('D3_NATIVE_LIFECYCLE_' + event); } catch { /* Preserve the primary failure. */ }
  };
  const disconnected = () => lifecycle('BROWSER_DISCONNECTED');
  browser.on('disconnected', disconnected);
  contexts.forEach(context => context.on('close', () => lifecycle('CONTEXT_CLOSED')));
  let errors = 0, unexpected = 0, dialogs = 0;
  let deniedOperationId = '';
  const writes = identities.map(() => 0);
  const counts = (requester: number) => roles ? [2, 2, requester + 2, 0]
    : limited ? [2, 2, requester, 0] : [upstreamLoss || referenceFault || capabilityLoss || expiry || capacity ? 3 : 2, revocationDone ? 4 : fixture.scenario === 'expiry-global' ? 3 : 2, requester];
  await runWithHistoryCleanup(async () => {
    const pages = await Promise.all(contexts.map(context => context.newPage()));
    pages.forEach((page, index) => {
      page.on('close', () => lifecycle('PAGE_CLOSED'));
      page.on('crash', () => lifecycle('PAGE_CRASHED'));
      page.on('pageerror', () => { errors += 1; });
      page.on('dialog', async dialog => { dialogs += 1; await dialog.dismiss(); });
      page.on('request', request => {
        const route = new URL(request.url()).pathname;
        if (route.startsWith('/dashboard/api/') && request.method() !== 'GET') {
          writes[index] += 1;
          if (request.method() !== 'POST' || !/^\/dashboard\/api\/remediation-operations(?:\/[a-f0-9-]+\/submit)?$/.test(route)) unexpected += 1;
        }
      });
    });
    const [proposer, approver, requester, viewer] = pages;
    let cachedHint = false;
    if (capabilityLoss) await proposer.route(origin + '/dashboard/session', async route => {
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      const actual = await response.json();
      if (!cachedHint && actual.authenticated === true && actual.subject === 'proposer') {
        expect(actual.roles).toEqual(['ANALYST']); cachedHint = true;
        await route.fulfill({ response, contentType: 'application/json', body: JSON.stringify({ ...actual, roles: ['ADMIN'] }) });
      } else await route.fulfill({ response });
    });
    if (sessionLoss || crossIssuer) await login(proposer, 'proposer');
    else await Promise.all(pages.map((page, index) => login(page, identities[index])));
    if (capabilityLoss) { expect(cachedHint).toBe(true); await proposer.unroute(origin + '/dashboard/session'); }
    checkpoint('SIGNED_IN');
    expect(writes).toEqual(identities.map(() => 0));
    if (roles) {
      await finding(viewer, fixture.scan_id, fixture.assessment_id);
      await expect(viewer.getByText(/Proposing requires the PROPOSE capability/)).toBeVisible();
      await expect(viewer.getByRole('button', { name: 'Prepare proposal', exact: true })).toHaveCount(0);
      const denied = await mutation(viewer, 'remediation-operations', { schema_version: '1.0.0', operation: 'PROPOSE',
        input: { finding_id: fixture.finding_id, occurrence_id: fixture.occurrence_id, reason: 'Viewer must not propose.' } });
      expect(denied.status()).toBe(403);
      expect(await denied.json()).toEqual({ detail: 'Dashboard operation capability required' });
      await finding(requester, fixture.scan_id, fixture.assessment_id);
      const own = await confirm(await prepare(requester, 'Prepare proposal', 'PROPOSE'), 'PROPOSE');
      await requester.getByRole('button', { name: `Open proposal ${own.result}`, exact: true }).click();
      await expect(requester.getByText(/ADMIN cannot bypass this separation/)).toBeVisible();
      await expect(requester.getByRole('button', { name: 'Prepare approval', exact: true })).toHaveCount(0);
      const ownProposal = await read(requester, `remediations/${own.result}`);
      if (!isProposal(ownProposal)) throw new Error('Unsupported ADMIN proposal');
      const prepared = await mutation(requester, 'remediation-operations', { schema_version: '1.0.0', operation: 'DECIDE',
        target_id: own.result, input: { proposal_sha256: ownProposal.proposal_sha256, decision: 'APPROVE', reason: 'ADMIN self-approval remains denied by genuine service.' } });
      expect(prepared.status()).toBe(201);
      const attempt = await prepared.json();
      deniedOperationId = attempt.operation_id;
      const settled = await mutation(requester, `remediation-operations/${attempt.operation_id}/submit`, {});
      expect(settled.status()).toBe(200); expect((await settled.json()).state).toBe('UNCONFIRMED');
      const unchanged = await read(requester, `remediations/${own.result}`);
      expect(isProposal(unchanged) && unchanged.approval_status === 'PROPOSED' && unchanged.decisions.length === 0).toBe(true);
      await requester.getByRole('button', { name: 'Back to scan selection', exact: true }).click();
      await expect(requester.getByLabel('Open scan by UUID')).toBeFocused();
    }
    if (capacity) await capacityBeforeProposal(browser, proposer, fixture);
    else if (!recoveryGuards) await finding(proposer, fixture.scan_id, fixture.assessment_id);
    const proposalCard = recoveryGuards ? await prepareWithRecoveryGuards(proposer, fixture)
      : await prepare(proposer, 'Prepare proposal', 'PROPOSE', keyboard);
    if (sessionLoss) {
      await sessionLossAfterCommit(pages, fixture, proposalCard);
      expect(writes).toEqual([2, 0, 0]); // The explicit old-key denial above used the API context.
      for (const page of pages) {
        expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
        expect((await page.request.post(origin + '/dashboard/api/scans', { data: {} })).status()).toBe(405);
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
        await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
      }
      expect(writes).toEqual([2, 0, 0]);
      expect(errors).toBe(0); expect(unexpected).toBe(0); expect(dialogs).toBe(0); expect(lifecycleFailures).toBe(0);
      checkpoint('COMPLETE'); return;
    }
    const proposalResult = crossIssuer ? await crossIssuerRestart(pages, fixture, proposalCard)
      : roles ? await confirmAfterLostBrowserReply(proposer, proposalCard)
      : expiry ? await retainExpiredCapacity(proposer, proposalCard, fixture)
      : capabilityLoss ? await retainAfterCapabilityLoss(proposer, proposalCard, fixture)
      : upstreamLoss || referenceFault ? await confirmAfterUnconfirmedUpstream(proposer, proposalCard, referenceFault ? fixture : undefined)
      : fixture.scenario === 'in-flight' ? await confirmWhileServerInFlight(proposer, proposalCard)
      : recoveryGuards ? await confirmWithDuplicateClicks(proposer, proposalCard) : await confirm(proposalCard, 'PROPOSE', keyboard);
    checkpoint('PROPOSAL');
    const proposal = await read(proposer, `remediations/${proposalResult.result}`);
    if (!isProposal(proposal)) throw new Error('Unsupported native proposal');
    expect(proposal.content.baseline.occurrence_id).toBe(fixture.occurrence_id);
    expect(proposal.content.baseline.assessment_id).toBe(fixture.assessment_id);
    if (fixture.scenario === 'feature-hints') await retainAfterFeatureHints(proposer, fixture, proposalResult.key, proposal);
    if (governance && !approvedCutoff) {
      await authorityCutoff(pages, fixture, proposalResult, false);
      expect(writes).toEqual([2, 0, 0]);
      await finishAuthorityPages(pages);
      expect(writes).toEqual([2, 0, 0]);
      expect(errors).toBe(0); expect(unexpected).toBe(0); expect(dialogs).toBe(0); expect(lifecycleFailures).toBe(0);
      checkpoint('COMPLETE'); return;
    }
    if (stale) {
      await staleProposal(pages, fixture, proposalResult);
      expect(writes).toEqual([2, 0, 0]); // Denied approval used the real signed API context above.
      for (const page of pages) {
        expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
        expect((await page.request.post(origin + '/dashboard/api/scans', { data: {} })).status()).toBe(405);
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
        await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
      }
      expect(writes).toEqual([2, 0, 0]);
      expect(errors).toBe(0); expect(unexpected).toBe(0); expect(dialogs).toBe(0); expect(lifecycleFailures).toBe(0);
      checkpoint('COMPLETE'); return;
    }
    if (proposalExpiry) {
      await expiredProposal(proposer, approver, requester, fixture, proposalResult.result, proposal);
      expect(writes).toEqual([3, 0, 0]); // The separate API preparation/submission were explicit above.
      for (const page of pages) {
        expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
        expect((await page.request.post(origin + '/dashboard/api/scans', { data: {} })).status()).toBe(405);
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
        await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
      }
      expect(writes).toEqual([3, 0, 0]);
      expect(errors).toBe(0); expect(unexpected).toBe(0); expect(dialogs).toBe(0); expect(lifecycleFailures).toBe(0);
      checkpoint('COMPLETE'); return;
    }
    await finding(approver, fixture.scan_id, fixture.assessment_id);
    if (fixture.scenario === 'history-versions') await rejectUnsupportedDetail(approver, 'proposal', proposalResult.result);
    else await approver.getByRole('button', { name: `Open proposal ${proposalResult.result}`, exact: true }).click();
    if (fixture.scenario === 'expiry-global') {
      await approver.getByRole('textbox', { name: /^Prepare approval reason/ }).fill('Expired records still occupy all exact global slots.');
      const denied = approver.waitForResponse(response => response.url() === origin + '/dashboard/api/remediation-operations' && response.request().method() === 'POST');
      await approver.getByRole('button', { name: 'Prepare approval', exact: true }).click();
      expect((await denied).status()).toBe(503);
      await expect(approver.getByText('Preparation could not be confirmed. Refresh same-session operations before preparing again.', { exact: true })).toBeVisible();
      await fixture.capacity!.assertRetained();
      await fixture.capacity!.releaseOne();
      await approver.getByRole('button', { name: 'Refresh same-session operations', exact: true }).click();
      await expect(approver.getByText('Coordination refreshed; no request was submitted.', { exact: true })).toBeVisible();
    }
    const approval = await confirm(await prepare(approver, 'Prepare approval', 'DECIDE', keyboard), 'DECIDE', keyboard);
    if (approvedCutoff) {
      await authorityCutoff(pages, fixture, proposalResult, true);
      expect(writes).toEqual([2, 2, 0]);
      await finishAuthorityPages(pages);
      expect(writes).toEqual([2, 2, 0]);
      expect(errors).toBe(0); expect(unexpected).toBe(0); expect(dialogs).toBe(0); expect(lifecycleFailures).toBe(0);
      checkpoint('COMPLETE'); return;
    }
    if (crossIssuer) await denySameIssuerSubjectAdminExecution(proposer, fixture, proposalResult.result, approval.result);
    await finding(requester, fixture.scan_id, fixture.assessment_id);
    await requester.getByRole('button', { name: `Open proposal ${proposalResult.result}`, exact: true }).click();
    const admission = await confirm(await prepare(requester, 'Prepare execution admission', 'REQUEST_EXECUTION', keyboard), 'REQUEST_EXECUTION', keyboard);
    checkpoint('ADMISSION');
    const queued = await read(requester, `remediation-executions/${admission.result}`);
    if (!isExecution(queued)) throw new Error('Unsupported native execution');
    expect(queued.phase).toBe('QUEUED'); expect(queued.reservation_held).toBe(true);
    if (executionExpiry) {
      expect(queued.blocking_reasons).toEqual(['EXECUTION_EXPIRED']);
      expect(Date.parse(queued.content.expires_at) - Date.parse(queued.content.created_at)).toBe(300000);
      expect(Date.parse(queued.validity_checked_at)).toBeGreaterThanOrEqual(Date.parse(queued.content.expires_at));
    }
    expect(queued.content.idempotency_key).toBe(admission.key);
    expect(queued.content.approval.decision_id).toBe(approval.result);
    expect([queued.content.proposal.proposer.subject, queued.content.approval.actor.subject,
      queued.content.requested_by.subject]).toEqual(crossIssuer ? ['proposer', 'proposer', 'requester'] : ['proposer', 'approver', 'requester']);
    expect([queued.content.proposal.proposer.issuer, queued.content.approval.actor.issuer,
      queued.content.requested_by.issuer]).toEqual(crossIssuer ? ['http://127.0.0.1:9032', 'http://127.0.0.1:9032/issuer-b', 'http://127.0.0.1:9032/issuer-b'] : Array(3).fill('http://127.0.0.1:9032'));
    expect(writes).toEqual(counts(2));
    if (revokedBefore) {
      await revokeNativeApproval(approver, proposal, approval.result);
      revocationDone = true;
      const revoked = await read(requester, `remediation-executions/${admission.result}`);
      if (!isExecution(revoked)) throw new Error('Unsupported revoked queued grant');
      expect(revoked.content).toEqual(queued.content); expect(revoked.events).toEqual(queued.events);
      expect(revoked.phase).toBe('QUEUED'); expect(revoked.reservation_held).toBe(true);
      expect(revoked.blocking_reasons).toEqual(['APPROVAL_REVOKED']);
      checkpoint('REVOKED_BEFORE_INSTALLED_INTENT');
      expect(writes).toEqual(counts(2));
    }
    // Private owning-parent control, never a browser HTTP worker-launch endpoint.
    await fixture.control('RUN_WORKER', admission.result, admission.key);
    checkpoint('INSTALLED_WORKER');
    const acknowledged = await read(requester, `remediation-executions/${admission.result}`);
    if (!isExecution(acknowledged)) throw new Error('Unsupported installed worker result');
    expect(acknowledged.content).toEqual(queued.content);
    const phase = executionExpiry || revokedBefore ? 'NO_WRITE' : quarantined ? 'QUARANTINED' : 'ACKNOWLEDGED';
    expect(acknowledged.phase).toBe(phase); expect(acknowledged.reservation_held).toBe(quarantined);
    expect(writes).toEqual(counts(2));
    if (fixture.scenario === 'history-versions') await rejectUnsupportedDetail(requester, 'execution', admission.result);
    else await requester.getByRole('button', { name: `Open execution ${admission.result}`, exact: true }).click();
    await expect(datum(requester, 'Execution phase')).toHaveText(phase);
    if (executionExpiry || revokedBefore) {
      await expect(datum(requester, 'Reservation held')).toHaveText('No');
      expect(acknowledged.events.map(entry => entry.content.kind)).toEqual(['REQUESTED', 'NO_WRITE']);
      expect(acknowledged.events.map(entry => entry.content.schema_version)).toEqual(['1.0.0', '2.0.0']);
      expect(acknowledged.events[1].content.blocking_reasons).toEqual([revokedBefore ? 'APPROVAL_REVOKED' : 'EXECUTION_EXPIRED']);
      await expect(requester.getByRole('button', { name: 'Prepare linked verification', exact: true })).toHaveCount(0);
      await expect(requester.getByText(/Linked verification requires a normal ACKNOWLEDGED execution/)).toBeVisible();
      await expect(requester.getByText(/No verification attempts on this page. This is not verified./)).toBeVisible();
      await deniedExtraVerification(requester, admission.result, 0);
      await fixture.control('RUN_WORKER', admission.result, admission.key);
      const retained = await read(requester, `remediation-executions/${admission.result}`);
      if (!isExecution(retained)) throw new Error('Unsupported retained expired execution');
      expect(retained.content).toEqual(acknowledged.content); expect(retained.events).toEqual(acknowledged.events);
      expect(retained.phase).toBe('NO_WRITE'); expect(retained.reservation_held).toBe(false);
      const original = await read(requester, `remediations/${proposalResult.result}`);
      if (!isProposal(original)) throw new Error('Unsupported retained original proposal');
      expect(original.content).toEqual(proposal.content); expect(original.proposal_sha256).toBe(proposal.proposal_sha256);
      checkpoint(revokedBefore ? 'REVOKED_NO_WRITE_RETAINED' : 'EXPIRED_NO_WRITE_RETAINED');
    }
    if (revokedAfter) {
      await revokeNativeApproval(approver, proposal, approval.result);
      revocationDone = true;
      const revoked = await read(requester, `remediation-executions/${admission.result}`);
      if (!isExecution(revoked)) throw new Error('Unsupported revoked acknowledged grant');
      expect(revoked.content).toEqual(acknowledged.content); expect(revoked.events).toEqual(acknowledged.events);
      expect(revoked.phase).toBe('ACKNOWLEDGED'); expect(revoked.reservation_held).toBe(false);
      expect(revoked.blocking_reasons).toEqual(['APPROVAL_REVOKED']);
      // Exact private replay cannot relaunch the installed worker after revocation.
      await fixture.control('RUN_WORKER', admission.result, admission.key);
      await requester.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
      await requester.getByRole('button', { name: `Open proposal ${proposalResult.result}`, exact: true }).click();
      await expect(datum(requester, 'Historical approval')).toHaveText('REVOKED');
      await requester.getByRole('button', { name: `Open execution ${admission.result}`, exact: true }).click();
      await expect(datum(requester, 'Execution phase')).toHaveText('ACKNOWLEDGED');
      await expect(datum(requester, 'Current execution blockers')).toHaveText('APPROVAL_REVOKED');
      await expect(requester.getByText(/Write authority may have expired or been revoked; this request grants no write/)).toBeVisible();
      expect(writes).toEqual(counts(2));
      checkpoint('REVOKED_AFTER_RETAINED_ACK');
    }
    if (quarantined) {
      await expect(datum(requester, 'Reservation held')).toHaveText('Yes');
      await expect(requester.getByText(/Unknown effect is quarantined/)).toBeVisible();
      await expect(requester.getByText(/quarantine and late acknowledgment are not eligible/)).toBeVisible();
      await expect(requester.getByText(/No verification attempts on this page. This is not verified./)).toBeVisible();
      await expect(requester.getByRole('button', { name: 'Prepare linked verification', exact: true })).toHaveCount(0);
      const kinds = acknowledged.events.map(entry => entry.content.kind);
      expect(kinds.slice(0, 4)).toEqual(['REQUESTED', 'CLAIMED', 'WRITE_INTENT', 'QUARANTINED']);
      expect(kinds.slice(4)).toEqual(fixture.scenario === 'late-ack' ? ['ACKNOWLEDGED', 'OBSERVED'] : ['OBSERVATION_FAILED']);
      expect(acknowledged.events.map(entry => entry.content.schema_version)).toEqual(['1.0.0', ...Array(kinds.length - 1).fill('2.0.0')]);
      if (fixture.scenario === 'late-ack') {
        expect(acknowledged.events[4].content.phase).toBe('QUARANTINED');
        const observation = acknowledged.events.at(-1)?.content;
        expect(observation?.schema_version === '2.0.0' && observation.observation?.encryption_by_default).toBe(true);
      }
      await deniedExtraVerification(requester, admission.result, 0);
      // The same private result is replayed; this never relaunches a quarantined worker.
      await fixture.control('RUN_WORKER', admission.result, admission.key);
      const retained = await read(requester, `remediation-executions/${admission.result}`);
      if (!isExecution(retained)) throw new Error('Unsupported retained quarantine');
      expect(retained.content).toEqual(acknowledged.content); expect(retained.events).toEqual(acknowledged.events);
      expect(retained.phase).toBe('QUARANTINED'); expect(retained.reservation_held).toBe(true);
      await expect(requester.getByRole('button', { name: 'Open verification', exact: false })).toHaveCount(0);
      checkpoint('QUARANTINE_RETAINED');
    }
    const completed: Verification[] = [];
    for (let ordinal = 1; ordinal <= attempts; ordinal += 1) {
    const requested = await confirm(await prepare(requester, 'Prepare linked verification', 'REQUEST_VERIFICATION', keyboard), 'REQUEST_VERIFICATION', keyboard);
    const pending = await read(requester, `remediation-verifications/${requested.result}`);
    if (!isVerification(pending)) throw new Error('Unsupported managed verification');
    expect(pending.content.execution_id).toBe(admission.result);
    expect(pending.content.idempotency_key).toBe(requested.key); expect(pending.receipt).toBeNull();
    expect(pending.content.attempt).toBe(ordinal);
    await requester.getByRole('button', { name: `Open execution ${admission.result}`, exact: true }).click();
    if (limited) {
      await expect(requester.getByRole('button', { name: 'Prepare linked verification', exact: true })).toHaveCount(0);
      await expect(requester.getByText(ordinal === 3 ? /three accepted verification attempts are exhausted/
        : /Review the active or unavailable verification attempt/)).toBeVisible();
      if (ordinal === 1) await deniedExtraVerification(viewer, admission.result, ordinal);
    }
    await requester.getByRole('button', { name: `Open verification ${requested.result}`, exact: true }).click();
    await expect(datum(requester, 'Verification verdict')).toHaveText('Pending; no verdict');
    await fixture.control('RELEASE_READER', requested.result, requested.key);
    checkpoint('MANAGED_READER');
    await expect.poll(async () => {
      const value = await read(requester, `remediation-verifications/${requested.result}`);
      return isVerification(value) ? value.receipt?.outcome : null;
    }).toBe(expected.outcome);
    const sealed = await read(requester, `remediation-verifications/${requested.result}`);
    if (!isVerification(sealed) || sealed.receipt === null) throw new Error('Missing genuine sealed receipt');
    if (fixture.scenario === 'verification-equal') {
      expect(sealed.content.created_at).toBe(sealed.content.acknowledged_at);
      expect(sealed.receipt.evidence?.observed_at).toBe(sealed.content.acknowledged_at);
      expect(sealed.receipt.evidence?.technical_result).toBe('PASS');
      console.log('D3_NATIVE_EQUAL_OBSERVATION_REJECTED');
    }
    if (fixture.scenario === 'verification-provenance') {
      expect(sealed.receipt.evidence).toBeNull();
      console.log('D3_NATIVE_UNAVAILABLE_PROVENANCE_REJECTED');
    }
    completed.push(sealed);
    const history = await read(requester, `remediation-verifications?execution_id=${admission.result}`);
    if (!verificationPage(history)) throw new Error('Unsupported verification history');
    expect(history.total).toBe(ordinal);
    expect([...history.items].sort((a, b) => a.content.attempt - b.content.attempt)).toEqual(completed);
    // Manual READ refresh, not an automatic POST or a pre-seeded verdict.
    await requester.getByRole('button', { name: 'Refresh remediation history', exact: true }).click();
    await requester.getByRole('button', { name: `Open proposal ${proposalResult.result}`, exact: true }).click();
    await requester.getByRole('button', { name: `Open execution ${admission.result}`, exact: true }).click();
    if (fixture.scenario === 'history-versions') await rejectUnsupportedDetail(requester, 'verification', requested.result);
    else await requester.getByRole('button', { name: `Open verification ${requested.result}`, exact: true }).click();
    await expect(datum(requester, 'Verification verdict')).toHaveText(expected.outcome);
    await expect(datum(requester, 'Verification classification')).toHaveText(expected.reason);
    await expect(datum(requester, 'Verification scan lifecycle')).toHaveText(expected.scan);
    await expect(datum(requester, 'Verification technical result')).toHaveText(expected.technical);
    await expect(datum(requester, 'Execution phase')).toHaveText('ACKNOWLEDGED');
    expect(writes).toEqual(counts(2 + 2 * ordinal));
    if (limited && ordinal < 3)
      await expect(requester.getByRole('button', { name: 'Prepare linked verification', exact: true })).toBeVisible();
    }
    if (limited) {
      await expect(requester.getByText(/three accepted verification attempts are exhausted/)).toBeVisible();
      await expect(requester.getByRole('button', { name: 'Prepare linked verification', exact: true })).toHaveCount(0);
      await deniedExtraVerification(viewer, admission.result, 3);
      expect(new Set(completed.map(value => value.content.scan_id)).size).toBe(3);
      expect(new Set(completed.map(value => value.content.verification_id)).size).toBe(3);
    }
    const evidence = await (await requester.request.get(origin + '/__test/fixture')).json();
    expect(evidence.scan_submissions).toBe(attempts);
    expect(evidence.proposal_response_losses).toBe(upstreamLoss || capabilityLoss || expiry ? 1 : 0);
    expect(writes).toEqual(counts(2 + 2 * attempts));
    if (keyboard) {
      expect(await requester.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      const back = requester.getByRole('button', { name: 'Back to scan selection', exact: true });
      await back.focus(); await back.press('Enter');
      await expect(requester.getByLabel('Open scan by UUID')).toBeFocused();
      await expect(requester.getByRole('region', { name: 'Remediation history', exact: true })).toHaveCount(0);
    }
    if (roles) await crossTabLogoutWithLateCoordination(requester, deniedOperationId);
    if (upstreamLoss) await realSessionLossClearsOn401(proposer, proposalResult.key);
    if (fixture.capacity) await fixture.capacity.assertRetained();
    for (const page of pages) {
      expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
      expect((await page.request.post(origin + '/dashboard/api/scans', { data: {} })).status()).toBe(405);
      if (!(roles && page === requester) && !(upstreamLoss && page === proposer))
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
      await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
    }
    expect(writes).toEqual(counts(2 + 2 * attempts));
    expect(errors).toBe(0); expect(unexpected).toBe(0); expect(dialogs).toBe(0);
    expect(lifecycleFailures).toBe(0);
    checkpoint('COMPLETE');
  }, async () => {
    cleaning = true;
    browser.off('disconnected', disconnected);
    if ((await Promise.allSettled(contexts.map(context => context.close()))).some(result => result.status === 'rejected'))
      throw new Error('Owned integrated browser context cleanup failed');
  });
}

for (const scenario of Object.keys(scenarioExpected) as ScenarioName[]) {
  test.describe(`scenario-${scenario}`, () => {
    test.use({ integratedScenario: scenario });
    const title = scenario === 'feature-hints'
      ? 'native disabled and missing UI hints → read-only history and original operation recovery → VERIFIED'
      : scenario === 'history-versions'
      ? 'native unsupported proposal, worker event and receipt versions → manual genuine READ recovery → VERIFIED'
      : scenario === 'reply-reference' || scenario === 'history-reference'
      ? 'native untrusted reference → retained original-key recovery → installed worker and read-only VERIFIED'
      : scenario === 'revoked-before-intent'
      ? 'native signed revocation before intent → installed NO_WRITE → no linked scan'
      : scenario === 'revoked-after-ack'
      ? 'native installed acknowledgment → signed revocation is not cancellation → read-only VERIFIED'
      : scenario.startsWith('governance-') || scenario === 'admission-stale'
      ? 'native retained authority → external governance or new evidence → denied approval or admission'
      : scenario.startsWith('stale-')
      ? 'native proposal → real collected newer or equal evidence → denied approval → immutable authority history'
      : scenario === 'subject-replacement' || scenario === 'issuer-rejection'
      ? 'native committed proposal → signed identity substitution → real session rejection → manual immutable history'
      : scenario === 'idle-expiry' || scenario === 'token-expiry'
      ? 'native committed proposal → elapsed session expiry → private clearing → fresh login and manual history'
      : scenario === 'proposal-expiry'
      ? 'native proposal expiry → retained original-key replay → denied approval → no execution or scan'
      : scenario === 'execution-expiry'
      ? 'native three-human authority → elapsed execution grant → installed NO_WRITE → no verification'
      : scenario === 'quarantine' || scenario === 'late-ack'
      ? 'native three-human authority → installed offline worker → retained quarantine → no verification'
      : `native three-human authority → installed offline worker → managed read-only scan → sealed ${scenarioExpected[scenario].outcome} receipt`;
    test(title,
      async ({ browser, integratedFixture }) => { await nativeJourney(browser, integratedFixture); });
  });
}
