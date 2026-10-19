import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScanContext, ScanShell } from './ScanShell';
import type { Posture } from './api';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/dashboard/'); });
describe('read-only selection lifecycle', () => {
  it.each([
    ['form', 'loaded'], ['history row', 'loaded'],
    ['form', 'error'], ['history row', 'error'],
    ['form', 'pending'], ['history row', 'pending']
  ] as const)('retains the same exact selection via %s while its read is %s until explicit Refresh', async (via, state) => {
    const id = 'abcdefab-1234-4123-8123-123456789abc';
    const scan = { scan_id: id, status: 'COMPLETED' as const, aws_account_id: '123456789012',
      requested_regions: ['us-east-1'], successful_regions: ['us-east-1'], requested_services: ['ec2'],
      successful_collectors: ['ec2'], started_at: '2026-10-18T00:00:00Z', completed_at: '2026-10-18T00:00:01Z',
      failure: null, scanner_version: 'test', control_catalog_id: 'test', control_catalog_version: '1.0.0',
      assessment_profile_id: 'test', assessment_profile_version: '1.0.0', assessment_profile_checksum: 'a'.repeat(64),
      inventory_sha256: null, result_checksum: null, scope: null };
    const report = { scan, availability: 'UNAVAILABLE', schema_version: '1.0.0',
      interpretation: 'TECHNICAL_CONTEXT_ONLY', assessment_counts: null };
    let refreshed = false, resolveDetail: ((response: Response) => void) | undefined;
    const reply = (value: unknown) => new Response(JSON.stringify(value));
    const fetch = vi.fn((url: string, options?: RequestInit): Promise<Response> => {
      expect(options?.method ?? 'GET').toBe('GET');
      if (url === '/dashboard/api/scans?limit=25&offset=0')
        return Promise.resolve(reply({ items: [scan], total: 1, limit: 25, offset: 0 }));
      if (url === `/dashboard/api/scans/${id}/technical-posture`) return Promise.resolve(reply(report));
      if (url !== `/dashboard/api/scans/${id}`) throw new Error('Unexpected selection read');
      if (!refreshed && state === 'error') return Promise.reject(new Error('Retained report read failed.'));
      if (!refreshed && state === 'pending') return new Promise(resolve => { resolveDetail = resolve; });
      return Promise.resolve(reply(scan));
    });
    window.history.replaceState(null, '', `/dashboard/?scan=${id}&other=preserved&login=complete`);
    const onError = vi.fn(); vi.stubGlobal('fetch', fetch);
    render(<ScanShell context={'A'.repeat(43)} onError={onError} />);
    const row = await screen.findByRole('button', { name: new RegExp(id), pressed: true });
    if (state === 'loaded') await screen.findByText(/No retained result bundle is available/);
    else if (state === 'error') expect(await screen.findByRole('alert')).toHaveTextContent('Retained report read failed.');
    else expect(screen.getByText('Loading selected scan…')).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(3);
    if (via === 'form') {
      fireEvent.change(screen.getByLabelText('Open scan by UUID'), { target: { value: `  ${id.toUpperCase()}  ` } });
      fireEvent.click(screen.getByRole('button', { name: 'Open scan' }));
    } else fireEvent.click(row);
    expect(screen.getByLabelText('Open scan by UUID')).toHaveValue(id);
    expect(new URLSearchParams(window.location.search).get('scan')).toBe(id);
    expect(new URLSearchParams(window.location.search).get('other')).toBe('preserved');
    expect(new URLSearchParams(window.location.search).has('login')).toBe(false);
    expect(fetch).toHaveBeenCalledTimes(3); // Same identity does not imply a new read or an automatic retry.
    if (state === 'loaded') expect(screen.getByText(/No retained result bundle is available/)).toBeInTheDocument();
    else if (state === 'error') expect(screen.getByRole('alert')).toHaveTextContent('Retained report read failed.');
    else {
      expect(screen.getByText('Loading selected scan…')).toBeInTheDocument();
      await act(async () => resolveDetail!(reply(scan)));
      expect(screen.getByText(/No retained result bundle is available/)).toBeInTheDocument();
    }
    refreshed = true;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByText(/No retained result bundle is available/);
    expect(fetch).toHaveBeenCalledTimes(6);
    expect(screen.queryByText('Loading selected scan…')).not.toBeInTheDocument();
    expect(screen.queryByText('Retained report read failed.')).not.toBeInTheDocument();
    // This narrow scan fixture deliberately lacks full NIST context. Its independent guard
    // stays fail-closed; a selected-scan refresh must not invent or suppress that context.
    expect(screen.getByRole('alert')).toHaveTextContent('The NIST context is unsupported or inconsistent.');
    expect(onError).toHaveBeenCalledTimes(state === 'error' ? 1 : 0);
    for (const [, options] of fetch.mock.calls) {
      expect(options).toMatchObject({ credentials: 'same-origin', cache: 'no-store',
        headers: { 'X-Dashboard-Context': 'A'.repeat(43) } });
      expect(options?.method ?? 'GET').toBe('GET'); expect(options?.body).toBeUndefined();
    }
  });
  it('explicit Back clears selection, returns focus and keeps controls before changing history', async () => {
    const id = '11111111-1111-1111-1111-111111111111';
    window.history.replaceState(null, '', `/dashboard/?scan=${id}&other=preserved`);
    let resolve!: (response: Response) => void;
    const fetch = vi.fn((url: string) => url.includes(`/scans/${id}`)
      ? new Promise<Response>(done => { resolve = done; })
      : Promise.resolve(new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 }))));
    vi.stubGlobal('fetch', fetch); render(<ScanShell context={'A'.repeat(43)} onError={() => undefined} />);
    await screen.findByText('No scans on this page.');
    const input = screen.getByLabelText('Open scan by UUID');
    expect(input.compareDocumentPosition(screen.getByText('No scans on this page.')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Back to scan selection' }));
    expect(input).toHaveFocus(); expect(input).toHaveValue('');
    expect(new URLSearchParams(window.location.search).has('scan')).toBe(false);
    expect(new URLSearchParams(window.location.search).get('other')).toBe('preserved');
    await act(async () => resolve(new Response('{}')));
    expect(screen.queryByText('Loading selected scan…')).not.toBeInTheDocument();
    expect(screen.getByText(/Select a scan to view/)).toBeInTheDocument();
  });
  it('browser Back restores a deep-link selection without making selection choose latest', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 }))));
    render(<ScanShell context={'A'.repeat(43)} onError={() => undefined} />);
    await screen.findByText('No scans on this page.');
    window.history.replaceState(null, '', '/dashboard/?scan=11111111-1111-1111-1111-111111111111');
    fireEvent.popState(window);
    expect(screen.getByLabelText('Open scan by UUID')).toHaveValue('11111111-1111-1111-1111-111111111111');
    expect(screen.getByRole('button', { name: 'Back to scan selection' })).toBeInTheDocument();
  });
  it('renders hostile metadata as text and unavailable counts never become a passing result', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const report: Posture = {
      availability: 'UNAVAILABLE', schema_version: '1.0.0', interpretation: 'TECHNICAL_CONTEXT_ONLY',
      scan: { scan_id: '11111111-1111-1111-1111-111111111111', status: 'FAILED',
        aws_account_id: null, requested_regions: [], successful_regions: [], requested_services: [],
        successful_collectors: [], started_at: '2026-10-03T00:00:00Z', completed_at: null,
        failure: { code: 'test_failure', message: hostile }, scanner_version: 'test',
        control_catalog_id: 'test', control_catalog_version: '1.0.0', assessment_profile_id: hostile,
        assessment_profile_version: '1.0.0', assessment_profile_checksum: 'test',
        inventory_sha256: null, result_checksum: null, scope: null }
    };
    const { container } = render(<ScanContext report={report} />);
    expect(screen.getByText(`${hostile} / 1.0.0`)).toBeInTheDocument();
    expect(screen.getByText(`test_failure: ${hostile}`)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByText(/not a passing assessment/)).toBeInTheDocument();
    expect(screen.queryByText('PASS')).not.toBeInTheDocument();
  });
  it('does not select latest or invent a passing empty report', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 })));
    vi.stubGlobal('fetch', fetch);
    render(<ScanShell context={'A'.repeat(43)} onError={() => undefined} />);
    expect(await screen.findByText('No scans on this page.')).toBeInTheDocument();
    expect(screen.getByText(/Select a scan to view/)).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].headers).toEqual({ 'X-Dashboard-Context': 'A'.repeat(43) });
    expect(screen.queryByText('PASS')).not.toBeInTheDocument();
  });
  it('rejects malformed selection before requesting report data', async () => {
    window.history.replaceState(null, '', '/dashboard/?scan=latest');
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 })));
    vi.stubGlobal('fetch', fetch);
    render(<ScanShell context={'A'.repeat(43)} onError={() => undefined} />);
    expect(screen.getByRole('alert')).toHaveTextContent('valid scan UUID');
    await screen.findByText('No scans on this page.');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('does not render a superseded error or response after selection changes', async () => {
    const id = '11111111-1111-1111-1111-111111111111';
    let rejectOld!: (reason: Error) => void;
    const fetch = vi.fn((url: string) => url.includes(id)
      ? new Promise<Response>((_, reject) => { rejectOld = reject; })
      : Promise.resolve(new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 }))));
    vi.stubGlobal('fetch', fetch);
    render(<ScanShell context={'A'.repeat(43)} onError={() => undefined} />);
    fireEvent.change(screen.getByLabelText('Open scan by UUID'), { target: { value: id } });
    fireEvent.click(screen.getByRole('button', { name: 'Open scan' }));
    await waitFor(() => expect(screen.getByText('Loading selected scan…')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Open scan by UUID'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Open scan' }));
    await act(async () => { rejectOld(new Error('old user data')); });
    expect(screen.queryByText('old user data')).not.toBeInTheDocument();
    expect(screen.getByText(/Select a scan to view/)).toBeInTheDocument();
  });
});
