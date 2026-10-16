import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RemediationWorkflow, useRemediationWorkflow } from './RemediationWorkflow';
import { AdmissionAction, ProposalActions, ProposeRemediation, VerificationAction } from './RemediationActions';
import { operationId, operationRequest, operationSession, preparedOperation, resultId } from './operation-fixtures.test-support';
import { anchor, execution, page, proposal } from './remediation-fixtures.test-support';
import type { PreparedOperation } from './remediation-operations';

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const list = (items: PreparedOperation[] = []) => json({ schema_version: '1.0.0', items });
function Controls() {
  const workflow = useRemediationWorkflow();
  return workflow ? <button disabled={!workflow.ready || workflow.busy}
    onClick={() => { void workflow.prepare(operationRequest()); }}>Prepare controlled intent</button> : <p>Legacy read-only controls</p>;
}
function mount(children = <Controls />, session = operationSession(), onError = vi.fn()) {
  return render(<RemediationWorkflow session={session} onError={onError}>{children}</RemediationWorkflow>);
}
async function reviewAndSubmit() {
  const review = await screen.findByRole('checkbox', { name: /I reviewed this frozen target/ });
  fireEvent.click(review);
  fireEvent.click(screen.getByRole('button', { name: 'Confirm and submit request' }));
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('leaves legacy/default-off READ controls unchanged and performs no coordination request', () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  const { features: _features, issuer: _issuer, ...legacy } = operationSession();
  expect(_features).toBeTruthy(); expect(_issuer).toBeTruthy();
  render(<RemediationWorkflow session={legacy} onError={vi.fn()}><Controls /></RemediationWorkflow>);
  expect(screen.getByText('Legacy read-only controls')).toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Manual remediation operations' })).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
});

it('prepares only on click, displays frozen risk/input and requires a separate reviewed submission', async () => {
  const value = preparedOperation();
  const confirmed = { ...value, state: 'CONFIRMED', attempts: 1, result: { result_id: resultId, scan_id: null } };
  const fetch = vi.fn((url: string, options?: RequestInit) => Promise.resolve(!options?.method ? list()
    : url.endsWith('/submit') ? json(confirmed) : json(value, 201)));
  vi.stubGlobal('fetch', fetch); mount();
  const button = await screen.findByRole('button', { name: 'Prepare controlled intent' });
  await waitFor(() => expect(button).toBeEnabled());
  expect(fetch.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(0);
  fireEvent.click(button);
  await screen.findByRole('heading', { name: 'PROPOSE · PREPARED' });
  expect(fetch.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(1);
  expect(screen.getByText('Fixed action')).toBeInTheDocument();
  expect(screen.getByText('Frozen reason').nextElementSibling).toHaveTextContent(value.input.reason);
  expect(screen.getByRole('button', { name: 'Confirm and submit request' })).toBeDisabled();
  await reviewAndSubmit();
  await screen.findByRole('heading', { name: 'PROPOSE · CONFIRMED' });
  expect(screen.getByText(/This is not worker execution or a verification verdict/)).toBeInTheDocument();
  expect(fetch.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(2);
  expect(fetch.mock.calls.at(-1)?.[1]?.body).toBe('{}');
});

it('recovers existing operations after same-session reload without an automatic POST, even in StrictMode', async () => {
  const value = { ...preparedOperation(), state: 'UNCONFIRMED' as const, attempts: 1 };
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(list([value])));
  vi.stubGlobal('fetch', fetch);
  render(<StrictMode><RemediationWorkflow session={operationSession()} onError={vi.fn()}><Controls /></RemediationWorkflow></StrictMode>);
  await screen.findByRole('heading', { name: 'PROPOSE · UNCONFIRMED' });
  expect(screen.getByRole('button', { name: 'Explicitly retry original request' })).toBeDisabled();
  expect(fetch.mock.calls.every(([, o]) => !o.method)).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare controlled intent' }));
  await screen.findByText(/already has an unresolved operation/);
  expect(fetch.mock.calls.every(([, o]) => !o.method)).toBe(true);
});

it('keeps a lost submission uncertain and retries only the original UUID/body after explicit review', async () => {
  const value = preparedOperation(); let attempts = 0;
  const fetch = vi.fn((url: string, options?: RequestInit) => {
    if (!options?.method) return Promise.resolve(list([value]));
    expect(url).toBe(`/dashboard/api/remediation-operations/${operationId}/submit`);
    if (attempts++ === 0) return Promise.reject(new Error('private transport payload'));
    return Promise.resolve(json({ ...value, state: 'UNCONFIRMED', attempts: 1 }));
  });
  vi.stubGlobal('fetch', fetch); mount();
  await screen.findByRole('heading', { name: 'PROPOSE · PREPARED' });
  await reviewAndSubmit();
  await screen.findByRole('button', { name: 'Explicitly retry original request' });
  expect(screen.queryByText(/private transport payload/)).not.toBeInTheDocument();
  expect(attempts).toBe(1);
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Explicitly retry original request' }));
  await screen.findByRole('heading', { name: 'PROPOSE · UNCONFIRMED' });
  expect(attempts).toBe(2);
  expect(fetch.mock.calls.filter(([, o]) => o?.method).every(([, o]) => o?.body === '{}')).toBe(true);
});

it('ignores a superseded initial recovery response instead of erasing prepared work', async () => {
  let old!: (response: Response) => void;
  const value = preparedOperation(); let reads = 0;
  const fetch = vi.fn((_url: string, options?: RequestInit) => {
    if (options?.method) return Promise.resolve(json(value, 201));
    if (reads++ === 0) return new Promise<Response>(resolve => { old = resolve; });
    return Promise.resolve(list());
  });
  vi.stubGlobal('fetch', fetch); mount();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh same-session operations' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Prepare controlled intent' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Prepare controlled intent' }));
  await screen.findByRole('heading', { name: 'PROPOSE · PREPARED' });
  await act(async () => { old(list()); });
  expect(screen.getByRole('heading', { name: 'PROPOSE · PREPARED' })).toBeInTheDocument();
});

it('rejects a same-session list that loses an existing operation rather than allowing a replacement', async () => {
  const value = preparedOperation();
  const fetch = vi.fn().mockResolvedValueOnce(list([value])).mockResolvedValueOnce(list());
  vi.stubGlobal('fetch', fetch); mount();
  await screen.findByRole('heading', { name: 'PROPOSE · PREPARED' });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh same-session operations' }));
  await screen.findByText(/Operation recovery is unavailable/);
  expect(screen.getByRole('button', { name: 'Prepare controlled intent' })).toBeDisabled();
  expect(screen.getByRole('heading', { name: 'PROPOSE · PREPARED' })).toBeInTheDocument();
});

it('clears private coordination on 401 and ignores a response completing after unmount', async () => {
  const value = preparedOperation(), onError = vi.fn();
  const fetch = vi.fn().mockResolvedValueOnce(list([value])).mockResolvedValueOnce(json({}, 401));
  vi.stubGlobal('fetch', fetch); const first = mount(<Controls />, operationSession(), onError);
  await screen.findByRole('heading', { name: 'PROPOSE · PREPARED' }); await reviewAndSubmit();
  await waitFor(() => expect(onError).toHaveBeenCalledWith(expect.objectContaining({ status: 401 })));
  expect(screen.queryByText(operationId)).not.toBeInTheDocument();
  first.unmount();
  let old!: (response: Response) => void;
  fetch.mockImplementation(() => new Promise<Response>(resolve => { old = resolve; }));
  const second = mount(); second.unmount();
  await act(async () => { old(list([value])); });
  expect(screen.queryByText(operationId)).not.toBeInTheDocument();
});

it('does not turn quarantine, technical PASS or expired write authority into the wrong verification affordance', async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(list())); vi.stubGlobal('fetch', fetch);
  const first = mount(<VerificationAction execution={{ ...execution, phase: 'QUARANTINED' }} page={page([])} />);
  await screen.findByText(/quarantine and late acknowledgment are not eligible/);
  expect(screen.queryByRole('button', { name: 'Prepare linked verification' })).not.toBeInTheDocument(); first.unmount();
  const second = mount(<VerificationAction execution={{ ...execution, blocking_reasons: ['EXPIRED', 'APPROVAL_REVOKED'] }} page={page([])} />);
  await waitFor(() => expect(screen.getByRole('textbox', { name: /Prepare linked verification reason/ })).toBeEnabled());
  fireEvent.change(screen.getByRole('textbox', { name: /Prepare linked verification reason/ }), { target: { value: 'Observe only; no new write.' } });
  expect(screen.getByRole('button', { name: 'Prepare linked verification' })).toBeEnabled(); second.unmount();
});

it('allows stale proposal rejection and proposer revocation but never self-approval or third-human admission bypass', async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(list())); vi.stubGlobal('fetch', fetch);
  const pending = { ...proposal, approval_status: 'PROPOSED' as const, decisions: [] };
  const first = mount(<ProposalActions proposal={pending} />);
  await waitFor(() => expect(screen.getByRole('textbox', { name: /Prepare rejection reason/ })).toBeEnabled());
  expect(screen.getByRole('textbox', { name: /Prepare approval reason/ })).toBeDisabled(); first.unmount();
  const session = { ...operationSession(), subject: proposal.content.proposer.subject, roles: ['APPROVER'] };
  const second = mount(<><ProposalActions proposal={pending} /><ProposalActions proposal={proposal} /></>, session);
  await screen.findByText(/ADMIN cannot bypass/);
  await waitFor(() => expect(screen.getByRole('textbox', { name: /Prepare revocation reason/ })).toBeEnabled());
  expect(screen.queryByRole('button', { name: 'Prepare approval' })).not.toBeInTheDocument(); second.unmount();
  mount(<AdmissionAction proposal={{ ...proposal, blocking_reasons: [] }} hasExecution={false} />, { ...operationSession(), subject: proposal.decisions[0].actor.subject });
  await screen.findByText(/third distinct issuer\/subject pair/);
  expect(screen.queryByRole('button', { name: 'Prepare execution admission' })).not.toBeInTheDocument();
});

it('takes proposal IDs only from the exact completed FAIL anchor and never starts scanning', async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(list())); vi.stubGlobal('fetch', fetch);
  const first = mount(<ProposeRemediation anchor={{ ...anchor, assessment: { ...anchor.assessment, assessment_result: 'PASS' } }} />);
  await screen.findByText(/exact completed EC2-004 FAIL/);
  expect(screen.queryByRole('button', { name: 'Prepare proposal' })).not.toBeInTheDocument(); first.unmount();
  mount(<ProposeRemediation anchor={anchor} />);
  const reason = await screen.findByRole('textbox', { name: /Prepare proposal reason/ });
  await waitFor(() => expect(reason).toBeEnabled());
  const form = screen.getByRole('form', { name: 'Prepare proposal' });
  expect(within(form).getByText('Occurrence UUID').nextElementSibling).toHaveTextContent(anchor.assessment.finding_occurrence_id!);
  expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true);
});
