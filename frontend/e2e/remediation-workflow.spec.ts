import type { Locator, Page } from '@playwright/test';
import { isProposal, isExecution, isVerification } from '../src/remediation-api';
import { test, expect, operationOrigin } from './operation-fixture';
import { runWithHistoryCleanup } from './history-page';

async function login(page: Page, identity: string) {
  await page.goto(operationOrigin + '/dashboard/');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByLabel('Test identity').selectOption(identity);
  await page.getByRole('button', { name: 'Approve test login', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Manual remediation operations', exact: true })).toBeVisible();
}
async function read(page: Page, path: string): Promise<unknown> {
  const status = await (await page.request.get(operationOrigin + '/dashboard/session')).json();
  expect(status.features).toEqual({ remediation: true }); expect(status).not.toHaveProperty('access_token');
  const response = await page.request.get(operationOrigin + '/dashboard/api/' + path,
    { headers: { 'X-Dashboard-Context': status.session_context } });
  expect(response.status()).toBe(200); return response.json();
}
async function openFinding(page: Page, scan: string, assessment: string) {
  await page.getByLabel('Open scan by UUID').fill(scan);
  await page.getByRole('button', { name: 'Open scan', exact: true }).click();
  await page.getByRole('button', { name: `Open assessment ${assessment}`, exact: true }).click();
  await page.getByRole('button', { name: 'Remediation history for this finding', exact: true }).click();
}
async function prepare(page: Page, title: string, kind: string, reason: string): Promise<Locator> {
  await page.getByRole('textbox', { name: new RegExp('^' + title + ' reason') }).fill(reason);
  await page.getByRole('button', { name: title, exact: true }).click();
  const card = page.getByRole('article', { name: new RegExp('^Prepared ' + kind + ' ') });
  await expect(card.getByRole('heading', { name: `${kind} · PREPARED`, exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Confirm and submit request', exact: true })).toBeDisabled();
  return card;
}
async function confirm(card: Locator, kind: string): Promise<string> {
  await card.getByRole('checkbox', { name: /I reviewed this frozen target/ }).check();
  await card.getByRole('button', { name: 'Confirm and submit request', exact: true }).click();
  await expect(card.getByRole('heading', { name: `${kind} · CONFIRMED`, exact: true })).toBeVisible();
  return (await card.locator('p').filter({ hasText: /^Confirmed request result UUID:/ }).locator('span').innerText()).trim();
}

test('signed three-human manual workflow → real bearer APIs → PostgreSQL history and same-session recovery', async ({ browser, operationFixture: fixture }) => {
  const started = Date.now();
  const checkpoint = (step: string) => console.log(`D2_NATIVE_${step} ${Date.now() - started}ms`);
  const contexts = await Promise.all([0, 1, 2].map(() => browser.newContext({ baseURL: operationOrigin,
    viewport: { width: 1280, height: 800 } })));
  let pageErrors = 0, unexpectedWrites = 0;
  const writes: number[] = [0, 0, 0];
  await runWithHistoryCleanup(async () => {
    const pages = await Promise.all(contexts.map(context => context.newPage()));
    pages.forEach((page, index) => {
      page.on('pageerror', () => { pageErrors += 1; });
      page.on('request', request => {
        if (new URL(request.url()).pathname.startsWith('/dashboard/api/') && request.method() !== 'GET') {
          if (request.method() !== 'POST' || !/^\/dashboard\/api\/remediation-operations(?:\/[a-f0-9-]+\/submit)?$/.test(new URL(request.url()).pathname)) unexpectedWrites += 1;
          writes[index] += 1;
        }
      });
    });
    const [proposer, approver, requester] = pages;
    await Promise.all(pages.map((page, index) => login(page, ['proposer', 'approver', 'requester'][index])));
    checkpoint('SIGNED_IN');
    expect(writes).toEqual([0, 0, 0]);

    await openFinding(proposer, fixture.scan_id, fixture.assessment_id);
    let card = await prepare(proposer, 'Prepare proposal', 'PROPOSE', 'Native exact-target workload and KMS review.');
    expect(writes).toEqual([1, 0, 0]);
    const originalId = await card.getByText('Prepared operation UUID', { exact: true }).locator('xpath=following-sibling::dd[1]').innerText();
    await proposer.reload(); // Recovery must not submit or regenerate a key.
    card = proposer.getByRole('article', { name: `Prepared PROPOSE ${originalId}`, exact: true });
    await expect(card.getByRole('heading', { name: 'PROPOSE · PREPARED', exact: true })).toBeVisible();
    expect(writes).toEqual([1, 0, 0]);
    const proposalId = await confirm(card, 'PROPOSE');
    checkpoint('PROPOSAL_CONFIRMED');
    const proposal = await read(proposer, `remediations/${proposalId}`);
    expect(isProposal(proposal)).toBe(true);
    if (!isProposal(proposal)) throw new Error('Unsupported persisted proposal');
    expect(proposal.content.proposer.subject).toBe('proposer');
    expect(proposal.content.baseline.assessment_id).toBe(fixture.assessment_id);

    await openFinding(approver, fixture.scan_id, fixture.assessment_id);
    await approver.getByRole('button', { name: `Open proposal ${proposalId}`, exact: true }).click();
    card = await prepare(approver, 'Prepare approval', 'DECIDE', 'Native independent approval of the sealed digest.');
    const approvalId = await confirm(card, 'DECIDE');
    checkpoint('APPROVAL_CONFIRMED');
    await openFinding(requester, fixture.scan_id, fixture.assessment_id);
    await requester.getByRole('button', { name: `Open proposal ${proposalId}`, exact: true }).click();
    card = await prepare(requester, 'Prepare execution admission', 'REQUEST_EXECUTION', 'Native bounded admission, not a worker launch.');
    const executionId = await confirm(card, 'REQUEST_EXECUTION');
    checkpoint('ADMISSION_CONFIRMED');
    const execution = await read(requester, `remediation-executions/${executionId}`);
    expect(isExecution(execution)).toBe(true);
    if (!isExecution(execution)) throw new Error('Unsupported persisted admission');
    expect(execution.phase).toBe('QUEUED'); expect(execution.reservation_held).toBe(true);
    expect(execution.content.approval.decision_id).toBe(approvalId);
    expect(execution.content.requested_by.subject).toBe('requester');
    expect(new Set([execution.content.proposal.proposer.subject, execution.content.approval.actor.subject,
      execution.content.requested_by.subject]).size).toBe(3);
    expect([execution.content.proposal.proposer.issuer, execution.content.approval.actor.issuer,
      execution.content.requested_by.issuer]).toEqual(Array(3).fill('http://127.0.0.1:9022'));
    expect((await (await requester.request.get(operationOrigin + '/__test/fixture')).json()).scan_submissions).toBe(0);

    // D2 proves manual observation of separate seeded normal-ACK history, not a worker run.
    await requester.getByRole('button', { name: 'Close proposal detail', exact: true }).click();
    await requester.getByRole('button', { name: `Open proposal ${fixture.seed_proposal_id}`, exact: true }).click();
    await requester.getByRole('button', { name: `Open execution ${fixture.seed_execution_id}`, exact: true }).click();
    card = await prepare(requester, 'Prepare linked verification', 'REQUEST_VERIFICATION', 'Native exact-policy observation only; no write.');
    const verificationId = await confirm(card, 'REQUEST_VERIFICATION');
    checkpoint('VERIFICATION_REQUEST_CONFIRMED');
    const verification = await read(requester, `remediation-verifications/${verificationId}`);
    expect(isVerification(verification)).toBe(true);
    if (!isVerification(verification)) throw new Error('Unsupported persisted verification request');
    expect(verification.content.execution_id).toBe(fixture.seed_execution_id);
    expect(verification.receipt).toBeNull(); // Recording executor: request confirmation is not VERIFIED.
    // Confirmation refreshes the parent READ panels, unmounting their nested detail selection.
    // Reopen this exact execution before selecting its newly recorded verification reference.
    await requester.getByRole('button', { name: `Open execution ${fixture.seed_execution_id}`, exact: true }).click();
    await requester.getByRole('button', { name: `Open verification ${verificationId}`, exact: true }).click();
    await expect(requester.getByText('Verification verdict', { exact: true }).locator('xpath=following-sibling::dd[1]')).toHaveText('Pending; no verdict');
    expect((await (await requester.request.get(operationOrigin + '/__test/fixture')).json()).scan_submissions).toBe(1);

    card = await prepare(approver, 'Prepare revocation', 'REVOKE', 'Native revocation is not a claim of cancellation.');
    await confirm(card, 'REVOKE');
    checkpoint('REVOCATION_CONFIRMED');
    const revoked = await read(approver, `remediations/${proposalId}`);
    expect(isProposal(revoked) && revoked.approval_status === 'REVOKED').toBe(true);
    const unchanged = await read(requester, `remediation-executions/${executionId}`);
    expect(isExecution(unchanged) && unchanged.phase === 'QUEUED' && unchanged.blocking_reasons.includes('APPROVAL_REVOKED')).toBe(true);
    expect(writes).toEqual([2, 4, 4]);
    for (const page of pages) {
      expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
      expect((await page.request.post(operationOrigin + '/dashboard/api/scans', { data: {} })).status()).toBe(405);
      await page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await expect(page.getByRole('region', { name: 'Manual remediation operations', exact: true })).toHaveCount(0);
      await expect(page.getByText(/Submitted requests are not canceled/)).toBeVisible();
    }
    expect(pageErrors).toBe(0);
    expect(unexpectedWrites).toBe(0);
    checkpoint('COMPLETE');
  }, async () => {
    const stopped = await Promise.allSettled(contexts.map(context => context.close()));
    if (stopped.some(result => result.status === 'rejected')) {
      throw new Error('Owned browser context cleanup failed');
    }
  });
});
