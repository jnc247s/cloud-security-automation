import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScanContext, ScanShell } from './ScanShell';
import type { Posture } from './api';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/dashboard/'); });
describe('read-only selection lifecycle', () => {
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
