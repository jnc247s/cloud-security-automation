import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Investigation } from './Investigation';
import { GraphPanel, SnapshotPanel } from './InvestigationDetails';
import { Payload } from './InvestigationUI';
import { assessment, at, control, exception, finding, id, outcome, page, relationship, report, resource, snapshot } from './investigation-fixtures.test-support';

const readProps = { context: 'A'.repeat(43), onError: vi.fn() };
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); });
function stub(extra: Record<string, unknown> = {}) {
  const fetch = vi.fn((url: string, _options?: RequestInit) => {
    void _options; // Keep request options in mock.calls for boundary assertions below.
    const path = url.replace('/dashboard/', '');
    const data: Record<string, unknown> = {
      'api/assessments': page([assessment]), [`api/assessments/${id(2)}`]: assessment,
      [`api/resources/${id(3)}`]: resource, [`api/resources/${id(3)}/history`]: page([snapshot]),
      [`api/controls/${id(5)}`]: control, 'api/findings': page([finding]), 'api/exceptions': page([exception]),
      [`api/source-outcomes/${id(10)}`]: outcome, [`api/relationships/${id(12)}`]: relationship, ...extra
    };
    return Promise.resolve(new Response(JSON.stringify(data[path.split('?')[0]]), { headers: { 'X-Dashboard-Read-At': at } }));
  }); vi.stubGlobal('fetch', fetch); return fetch;
}
describe('bounded on-demand investigation', () => {
  it('loads no per-row details until selected and keeps history/current exceptions distinct', async () => {
    const fetch = stub(); const { container } = render(<Investigation scope={report} {...readProps} />);
    fireEvent.click(await screen.findByRole('button', { name: `Open assessment ${id(2)}` }));
    await screen.findByText('Historical definition');
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(screen.getByText('historical ARN')).toBeInTheDocument(); expect(screen.getByText('first-seen ARN')).toBeInTheDocument();
    expect(screen.getByText(assessment.reason)).toBeInTheDocument(); expect(container.querySelector('img')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Current findings and exceptions' }));
    fireEvent.click(await screen.findByRole('button', { name: `ACCEPTED_RISK — ${id(13)}` }));
    expect(await screen.findByText('Expired at server reference time')).toBeInTheDocument();
    expect(screen.getByText(/never rewrite technical FAIL/)).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(7);
    for (const [, options] of fetch.mock.calls as unknown as [string, RequestInit][]) {
      expect(options.headers).toEqual({ 'X-Dashboard-Context': 'A'.repeat(43) });
      expect(options.credentials).toBe('same-origin'); expect(options.cache).toBe('no-store');
      expect(options.signal).toBeInstanceOf(AbortSignal);
    }
    fireEvent.click(screen.getByRole('button', { name: 'Open cited source ' + id(10) }));
    expect(await screen.findByText('normalized://test')).toBeInTheDocument();
    expect(container.querySelector('a')).toBeNull();
  });
  it('rejects another scan or profile before rendering a row', async () => {
    stub({ 'api/assessments': page([{ ...assessment, scan_id: id(99) }]) });
    render(<Investigation scope={report} {...readProps} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('does not match');
    expect(screen.queryByRole('button', { name: /Open assessment/ })).not.toBeInTheDocument();
  });
  it('never substitutes a newer snapshot', async () => {
    stub({ [`api/resources/${id(3)}/history`]: page([{ ...snapshot, scan_id: id(99), name: 'newest misleading name' }]) });
    render(<Investigation scope={report} {...readProps} />);
    fireEvent.click(await screen.findByRole('button', { name: `Open assessment ${id(2)}` }));
    await screen.findByText('Historical definition');
    expect(screen.getByRole('alert')).toHaveTextContent('does not match');
    expect(screen.queryByText('newest misleading name')).not.toBeInTheDocument();
  });
  it('clears superseded sensitive graph data and errors on scan replacement', async () => {
    let rejectOld!: (error: Error) => void;
    const fetch = vi.fn(() => new Promise<Response>((_, reject) => { rejectOld = reject; })); vi.stubGlobal('fetch', fetch);
    const { rerender } = render(<GraphPanel key={id(1)} selected={{ kind: 'source-outcomes', id: id(10) }} scope={report} readProps={readProps} selectGraph={() => undefined} />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    const old = rejectOld;
    rerender(<GraphPanel key={id(99)} selected={{ kind: 'source-outcomes', id: id(10) }} scope={{ ...report, scan: { ...report.scan, scan_id: id(99) } }} readProps={readProps} selectGraph={() => undefined} />);
    await act(async () => { old(new Error('old sensitive reason')); });
    expect(screen.queryByText('old sensitive reason')).not.toBeInTheDocument(); expect(readProps.onError).not.toHaveBeenCalled();
  });
  it('preserves unresolved references without a target snapshot request', async () => {
    const fetch = stub(); render(<GraphPanel selected={{ kind: 'relationships', id: id(12) }} scope={report} readProps={readProps} selectGraph={() => undefined} />);
    expect(await screen.findByText(/Unresolved target reference/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open exact target snapshot' })).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it.each(['control', 'version', 'checksum', 'catalog'])('rejects mismatched %s metadata without citation links', async kind => {
    const changed = { ...control, versions: control.versions.map(v => ({ ...v })) };
    if (kind === 'control') changed.control_id = id(99);
    if (kind === 'version') changed.versions[0].control_version_id = id(99);
    if (kind === 'checksum') changed.versions[0].definition_checksum = 'b'.repeat(64);
    if (kind === 'catalog') changed.versions[0].catalog_id = id(99);
    stub({ [`api/controls/${id(5)}`]: changed });
    render(<Investigation scope={report} {...readProps} />);
    fireEvent.click(await screen.findByRole('button', { name: `Open assessment ${id(2)}` }));
    expect(await screen.findByRole('alert')).toHaveTextContent('does not match');
    expect(screen.queryByRole('button', { name: /Open cited/ })).not.toBeInTheDocument();
  });
  it.each(['source', 'artifact', 'subject', 'edge', 'endpoint'])('rejects mismatched %s graph identity', async kind => {
    const source = { ...outcome, subject: { ...outcome.subject }, artifact: { ...outcome.artifact } };
    const edge = { ...relationship, source: { ...relationship.source } };
    if (kind === 'source') source.scan_id = id(99);
    if (kind === 'artifact') source.artifact.artifact_id = id(99);
    if (kind === 'subject') source.subject.stable_resource_id = id(99);
    if (kind === 'edge') edge.observation_id = id(99);
    if (kind === 'endpoint') edge.source.resource_snapshot_id = id(99);
    stub({ [`api/source-outcomes/${id(10)}`]: source, [`api/relationships/${id(12)}`]: edge });
    render(<GraphPanel selected={kind === 'edge' || kind === 'endpoint'
      ? { kind: 'relationships', id: id(12), relationship }
      : { kind: 'source-outcomes', id: id(10), outcome }} scope={report} readProps={readProps} selectGraph={() => undefined} />);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByText('normalized://test')).not.toBeInTheDocument();
  });
  it('clears invalid applied filters and makes bounded result/page requests only', async () => {
    const fetch = vi.fn((url: string) => {
      const params = new URL('https://test/' + url).searchParams;
      const offset = Number(params.get('offset') ?? 0);
      return Promise.resolve(new Response(JSON.stringify(page(offset ? [] : [assessment], offset, 26))));
    }); vi.stubGlobal('fetch', fetch);
    render(<Investigation scope={report} {...readProps} />);
    await screen.findByRole('button', { name: `Open assessment ${id(2)}` });
    fireEvent.click(screen.getByRole('button', { name: 'Next assessments page' }));
    await screen.findByText(/No assessments on this filtered page/);
    expect(fetch.mock.calls[1][0]).toContain('limit=25&offset=25');
    fireEvent.change(screen.getByLabelText('Technical result'), { target: { value: 'FAIL' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply assessment filters' }));
    await screen.findByRole('button', { name: `Open assessment ${id(2)}` });
    expect(fetch.mock.calls[2][0]).toContain('offset=0&result=FAIL');
    fireEvent.change(screen.getByLabelText('Assessment resource UUID'), { target: { value: 'not-an-id' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply assessment filters' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('require UUIDs');
    expect(screen.queryByRole('button', { name: /Open assessment/ })).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(3);
  });
  it('ignores a late successful detail after identity replacement and aborts old reads', async () => {
    const pending: { resolve: (v: Response) => void; signal: AbortSignal }[] = [];
    vi.stubGlobal('fetch', vi.fn((_url: string, options: RequestInit) => new Promise<Response>(resolve =>
      pending.push({ resolve, signal: options.signal as AbortSignal }))));
    const { rerender } = render(<GraphPanel key="identity-A" selected={{ kind: 'source-outcomes', id: id(10) }}
      scope={report} readProps={readProps} selectGraph={() => undefined} />);
    await waitFor(() => expect(pending).toHaveLength(1));
    rerender(<GraphPanel key="identity-B" selected={{ kind: 'source-outcomes', id: id(10) }}
      scope={report} readProps={{ ...readProps, context: 'B'.repeat(43) }} selectGraph={() => undefined} />);
    await act(async () => { pending[0].resolve(new Response(JSON.stringify(outcome))); });
    expect(pending[0].signal.aborted).toBe(true);
    expect(screen.queryByText('normalized://test')).not.toBeInTheDocument();
  });
  it.each(['global', 'external'])('shows exact %s identity without confusing it with collection account', async kind => {
    const global = kind === 'global', owner = global ? 'aws' : '210987654321';
    stub({ [`api/resources/${id(3)}`]: { ...resource, aws_account_id: owner, scope: global ? 'global' : 'regional', region: global ? 'global' : 'us-east-1' },
      [`api/resources/${id(3)}/history`]: page([{ ...snapshot, scope: global ? 'global' : 'regional', region: global ? null : 'us-east-1' }]) });
    render(<SnapshotPanel scanId={id(1)} resourceId={id(3)} snapshotId={id(4)} readProps={readProps} />);
    expect(await screen.findByText(owner)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('renders hostile, deep and large payloads safely with explicit display limits', () => {
    const deep = Array.from({ length: 20 }).reduce<Record<string, unknown>>(child => ({ child }), {});
    const { container } = render(<Payload value={ { hostile: '<script>secret()</script>', deep, huge: 'x'.repeat(20000) } } label="Evidence" />);
    expect(screen.getByText(/Display truncated/)).toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull(); expect(container.querySelector('pre')!.textContent!.length).toBeLessThan(12005);
  });
});
