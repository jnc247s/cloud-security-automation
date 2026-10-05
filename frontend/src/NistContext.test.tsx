import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NistContext, nistText } from './NistContext';
import { id, nistFixture, unavailableFixture } from './nist-fixtures';

afterEach(cleanup);
async function expand(label: string) {
  const summary = screen.getByText(label, { exact: true });
  const details = summary.closest('details')!;
  await act(async () => { details.open = true; fireEvent(details, new Event('toggle')); });
}
describe('read-only NIST context', () => {
  it('bounds text disclosures and labels with an explicit truncation notice', () => {
    expect(nistText('x'.repeat(4096))).toBe('x'.repeat(2048) + '… [Display truncated]');
    expect(nistText('x'.repeat(1024), 512)).toBe('x'.repeat(512) + '… [Display truncated]');
  });
  it('requires explicit exact release and lazily opens hierarchy, contributors and text-only provenance without requests', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    try {
      const { container } = render(<NistContext report={nistFixture()} />);
      expect(screen.getByLabelText('Select exact framework release')).toHaveValue('');
      expect(screen.queryByText('FUNCTION PR — Protect')).not.toBeInTheDocument();
      expect(screen.getByText(/not the full CSF Core/)).toBeInTheDocument();
      fireEvent.change(screen.getByLabelText('Select exact framework release'), { target: { value: id(100) } });
      expect(screen.queryByText('CATEGORY PR.DS — Data security')).not.toBeInTheDocument();
      await expand('FUNCTION PR — Protect');
      const root = screen.getByText('FUNCTION PR — Protect').closest('details')!;
      expect(within(root).getByText('PASS assessments').nextElementSibling).toHaveTextContent('1');
      await expand('CATEGORY PR.DS — Data security');
      await expand('SUBCATEGORY PR.DS-01 — First outcome');
      await expand('Contributing controls and mappings (2)');
      await expand(`Mapping PR.DS-01 · ${id(200)}`);
      expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
      expect(screen.getByText('Verified at').nextElementSibling).toHaveTextContent('2026-09-01T01:00:00+01:00');
      expect(container.querySelector('img, script, a')).toBeNull();
      fireEvent.change(screen.getByLabelText('Select exact framework release'), { target: { value: id(110) } });
      expect(screen.queryByText('CATEGORY PR.DS — Data security')).not.toBeInTheDocument();
      expect(screen.queryByText('<img src=x onerror=alert(1)>')).not.toBeInTheDocument();
      expect(fetch).not.toHaveBeenCalled();
    } finally { vi.unstubAllGlobals(); }
  });
  it.each([false, true])('shows unavailable counts with retained definitions, not zero: running=%s', running => {
    render(<NistContext report={unavailableFixture(running)} />);
    expect(screen.getByText('Assessment counts unavailable — not zero.')).toBeInTheDocument();
    expect(screen.queryByText('PASS assessments')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Select exact framework release')).toBeInTheDocument();
  });
  it('fails closed independently of investigation data', () => {
    const v = nistFixture(); v.frameworks[0].references[0].mapped_control_version_ids = [];
    render(<NistContext report={v} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Valid investigation views remain separate');
    expect(screen.queryByText('PASS assessments')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Select exact framework release')).not.toBeInTheDocument();
  });
  it('does not call unmapped context a passing NIST result', async () => {
    render(<NistContext report={nistFixture()} />);
    fireEvent.change(screen.getByLabelText('Select exact framework release'), { target: { value: id(100) } });
    await expand('FUNCTION PR — Protect'); await expand('CATEGORY PR.DS — Data security');
    await expand('SUBCATEGORY PR.DS-03 — Unmapped outcome');
    expect(screen.getByText(/No mapped controls. This outcome is not assessed/)).toBeInTheDocument();
  });
});
