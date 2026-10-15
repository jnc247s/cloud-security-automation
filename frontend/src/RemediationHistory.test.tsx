import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RemediationHistory } from './RemediationHistory';
import { mismatch } from './InvestigationUI';
import { anchor, execution, id, page, proposal, verification } from './remediation-fixtures.test-support';

const readProps = { context: 'A'.repeat(43), onError: vi.fn() };
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); });
function stub(extra: Record<string, unknown> = {}) {
  const values: Record<string, unknown> = {
    'api/remediations': page([proposal]), [`api/remediations/${id(101)}`]: proposal,
    'api/remediation-executions': page([execution]), [`api/remediation-executions/${id(103)}`]: execution,
    'api/remediation-verifications': page([verification]), [`api/remediation-verifications/${id(109)}`]: verification, ...extra
  };
  const fetch = vi.fn((url: string, _options?: RequestInit) => {
    void _options;
    return Promise.resolve(new Response(JSON.stringify(values[url.replace('/dashboard/', '').split('?')[0]])));
  }); vi.stubGlobal('fetch', fetch); return fetch;
}
async function openProposal() { fireEvent.click(await screen.findByRole('button', { name: `Open proposal ${id(101)}` })); }
async function openExecution() { await openProposal(); fireEvent.click(await screen.findByRole('button', { name: `Open execution ${id(103)}` })); }
describe('read-only remediation history', () => {
  it('loads six reads on demand and keeps expired approval, acknowledgment and verification separate', async () => {
    const fetch = stub(); const { container } = render(<RemediationHistory anchor={anchor} readProps={readProps} />);
    await screen.findByRole('button', { name: `Open proposal ${id(101)}` }); expect(fetch).toHaveBeenCalledTimes(1);
    await openExecution(); fireEvent.click(await screen.findByRole('button', { name: `Open verification ${id(109)}` }));
    await screen.findByText('Verification verdict');
    for (const [label, value] of [['Historical approval', 'APPROVED'], ['Current proposal blockers', 'EXPIRED'],
      ['Execution phase', 'ACKNOWLEDGED'], ['Verification verdict', 'VERIFIED'], ['Verification technical result', 'PASS']])
      expect(screen.getByText(label).nextElementSibling).toHaveTextContent(value);
    expect(screen.getByText(proposal.content.reason)).toBeInTheDocument(); expect(container.querySelector('img')).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(6);
    for (const [, options] of fetch.mock.calls) {
      expect(options?.method).toBeUndefined(); expect(options?.headers).toEqual({ 'X-Dashboard-Context': readProps.context });
      expect(options?.cache).toBe('no-store'); expect(options?.credentials).toBe('same-origin'); expect(options?.signal).toBeInstanceOf(AbortSignal);
    }
  });
  it('explains unsupported controls without fetching or enabling a profile', () => {
    const fetch = stub(); render(<RemediationHistory anchor={{ ...anchor, scope: { ...anchor.scope, controls: [] } }} readProps={readProps} />);
    expect(screen.getByText(/no supported EC2-004 remediation/)).toBeInTheDocument(); expect(fetch).not.toHaveBeenCalled();
  });
  it('labels another occurrence without replacing the selected assessment', async () => {
    const old = structuredClone(proposal); old.content.baseline.occurrence_id = id(999);
    stub({ 'api/remediations': page([old]), [`api/remediations/${id(101)}`]: old });
    render(<RemediationHistory anchor={anchor} readProps={readProps} />); await openProposal();
    expect(await screen.findByText(/belongs to another retained occurrence/)).toBeInTheDocument();
    expect(screen.queryByText('Bound to the selected retained occurrence and policy.')).not.toBeInTheDocument();
  });
  it.each(['finding', 'proposal-detail', 'execution', 'verification'])('rejects a crossed %s before displaying its history', async kind => {
    const p = structuredClone(proposal), e = structuredClone(execution), v = structuredClone(verification);
    const extra: Record<string, unknown> = {};
    if (kind === 'finding') { p.content.finding_id = id(999); extra['api/remediations'] = page([p]); }
    if (kind === 'proposal-detail') { p.content.baseline.snapshot_id = id(999); extra[`api/remediations/${id(101)}`] = p; }
    if (kind === 'execution') { e.content.proposal.region = 'us-other-1'; extra['api/remediation-executions'] = page([e]); }
    if (kind === 'verification') { v.content.execution_sha256 = 'b'.repeat(64); extra['api/remediation-verifications'] = page([v]); }
    stub(extra); render(<RemediationHistory anchor={anchor} readProps={readProps} />);
    if (kind !== 'finding') await openProposal();
    if (kind === 'verification') fireEvent.click(await screen.findByRole('button', { name: `Open execution ${id(103)}` }));
    expect(await screen.findByRole('alert')).toHaveTextContent(mismatch);
    expect(screen.queryByText('Verification verdict')).not.toBeInTheDocument();
  });
  it('keeps INCONCLUSIVE independent from a technical PASS', async () => {
    const v = { ...verification, receipt: { ...verification.receipt!, outcome: 'INCONCLUSIVE', reason: 'KMS_CONTEXT_CHANGED' } };
    stub({ 'api/remediation-verifications': page([v]), [`api/remediation-verifications/${id(109)}`]: v });
    render(<RemediationHistory anchor={anchor} readProps={readProps} />); await openExecution();
    fireEvent.click(await screen.findByRole('button', { name: `Open verification ${id(109)}` }));
    await screen.findByText('Verification verdict');
    expect(screen.getByText('Verification verdict').nextElementSibling).toHaveTextContent('INCONCLUSIVE');
    expect(screen.getByText('Verification technical result').nextElementSibling).toHaveTextContent('PASS');
  });
  it('refresh removes details immediately and ignores a late response', async () => {
    let resolve!: (v: Response) => void;
    const fetch = vi.fn((url: string) => url.includes(`/remediations/${id(101)}`)
      ? new Promise<Response>(done => { resolve = done; }) : Promise.resolve(new Response(JSON.stringify(page([proposal])))));
    vi.stubGlobal('fetch', fetch); render(<RemediationHistory anchor={anchor} readProps={readProps} />); await openProposal();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh remediation history' }));
    await act(async () => resolve(new Response(JSON.stringify(proposal))));
    expect(screen.queryByText('Proposal UUID')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Close proposal detail' })).not.toBeInTheDocument();
  });
  it('identity replacement clears pending history and aborts old reads', async () => {
    let resolve!: (v: Response) => void; let oldSignal: AbortSignal | undefined;
    const fetch = vi.fn((_url: string, options?: RequestInit) => options?.headers && (options.headers as Record<string, string>)['X-Dashboard-Context'] === readProps.context
      ? new Promise<Response>(done => { resolve = done; oldSignal = options.signal as AbortSignal; })
      : Promise.resolve(new Response(JSON.stringify(page([])))));
    vi.stubGlobal('fetch', fetch); const view = render(<RemediationHistory anchor={anchor} readProps={readProps} />);
    view.rerender(<RemediationHistory anchor={anchor} readProps={{ ...readProps, context: 'B'.repeat(43) }} />);
    await screen.findByText(/No remediation proposals/); await act(async () => resolve(new Response(JSON.stringify(page([proposal])))));
    expect(oldSignal?.aborted).toBe(true); expect(screen.queryByRole('button', { name: `Open proposal ${id(101)}` })).not.toBeInTheDocument();
  });
  it('empty history and wrong pagination do not invent success', async () => {
    stub({ 'api/remediations': page([]) }); const view = render(<RemediationHistory anchor={anchor} readProps={readProps} />);
    expect(await screen.findByText(/Absence of remediation is not PASS or verified/)).toBeInTheDocument();
    view.unmount(); stub({ 'api/remediations': page([proposal], 25) }); render(<RemediationHistory anchor={anchor} readProps={readProps} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(mismatch);
  });
});
