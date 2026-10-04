import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { App } from './App';

class TestChannel {
  static instances: TestChannel[] = [];
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  messages: unknown[] = [];
  closed = false;
  constructor() { TestChannel.instances.push(this); }
  postMessage(value: unknown) { this.messages.push(value); }
  close() { this.closed = true; }
  receive(value: unknown) { this.onmessage?.({ data: value } as MessageEvent<unknown>); }
}
const authenticated = (subject = 'reader-A', context = 'A'.repeat(43)) => ({ authenticated: true,
  csrf_token: `csrf-${subject}`, subject, roles: ['VIEWER'], session_context: context,
  expires_at: Date.now() / 1000 + 3600, idle_expires_at: Date.now() / 1000 + 900 });
const empty = () => new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 }));
const json = (value: unknown) => new Response(JSON.stringify(value));
beforeEach(() => { vi.stubGlobal('BroadcastChannel', TestChannel); });
afterEach(() => {
  cleanup(); vi.unstubAllGlobals(); TestChannel.instances = [];
  window.history.replaceState(null, '', '/dashboard/');
});

it('clears on cross-tab logout before confirmation and ignores a superseded session response', async () => {
  let resolveOld!: (value: Response) => void;
  const fetch = vi.fn((url: string) => url.endsWith('/session')
    ? new Promise<Response>(resolve => { resolveOld = resolve; }) : Promise.resolve(empty()));
  vi.stubGlobal('fetch', fetch);
  render(<App />);
  await act(async () => { TestChannel.instances[0].receive({ type: 'clear', context: 'A'.repeat(43) }); });
  await act(async () => { TestChannel.instances[0].receive({ type: 'session', context: 'A'.repeat(43) }); });
  await act(async () => { resolveOld(json(authenticated())); });
  expect(screen.queryByText(/reader-A/)).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Scan history' })).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Signing out in another tab');
  expect(fetch).toHaveBeenCalledTimes(1); // No bootstrap that could restore the pre-logout cookie.
});

it('clears identity/data across tabs and binds replacement reads to the new context without echo', async () => {
  let session = authenticated();
  const fetch = vi.fn<(url: string, options?: RequestInit) => Promise<Response>>(
    url => Promise.resolve(url.endsWith('/session') ? json(session) : empty()));
  vi.stubGlobal('fetch', fetch);
  const { unmount } = render(<App />);
  expect(await screen.findByText('reader-A · VIEWER')).toBeInTheDocument();
  await screen.findByText('No scans on this page.');
  const notifications = TestChannel.instances[0];
  expect(notifications.messages).toEqual([{ type: 'session', context: 'A'.repeat(43) }]);
  await act(async () => { notifications.receive({ type: 'clear', context: 'A'.repeat(43) }); });
  expect(screen.queryByText('reader-A · VIEWER')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Scan history' })).not.toBeInTheDocument();
  session = authenticated('reader-B', 'B'.repeat(43));
  await act(async () => { notifications.receive({ type: 'session', context: 'B'.repeat(43) }); });
  expect(await screen.findByText('reader-B · VIEWER')).toBeInTheDocument();
  const reads = fetch.mock.calls.filter(([url]) => url.includes('/api/scans'));
  expect(reads.at(-1)?.[1]?.headers).toEqual({ 'X-Dashboard-Context': 'B'.repeat(43) });
  expect(notifications.messages).toHaveLength(1);
  unmount(); expect(notifications.closed).toBe(true);
});

it('does not clear unchanged sessions or accept malformed tab notifications', async () => {
  const fetch = vi.fn((url: string) => Promise.resolve(url.endsWith('/session') ? json(authenticated()) : empty()));
  vi.stubGlobal('fetch', fetch);
  render(<App />);
  await screen.findByText('reader-A · VIEWER');
  const notifications = TestChannel.instances[0];
  await act(async () => {
    for (const value of [null, {}, { type: 'session', context: '../api' },
      { type: 'session', context: 'A'.repeat(43) }, { type: 'clear', context: 'B'.repeat(43) }])
      notifications.receive(value);
  });
  expect(screen.getByText('reader-A · VIEWER')).toBeInTheDocument();
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/session'))).toHaveLength(1);
});

it('ignores an old identity list response even if it completes after replacement bootstrap', async () => {
  let session = authenticated();
  let resolveOld!: (value: Response) => void;
  let listCalls = 0;
  const fetch = vi.fn((url: string) => {
    if (url.endsWith('/session')) return Promise.resolve(json(session));
    if (listCalls++ === 0) return new Promise<Response>(resolve => { resolveOld = resolve; });
    return Promise.resolve(empty());
  });
  vi.stubGlobal('fetch', fetch);
  render(<App />);
  await screen.findByText('reader-A · VIEWER');
  const notifications = TestChannel.instances[0];
  session = authenticated('reader-B', 'B'.repeat(43));
  await act(async () => { notifications.receive({ type: 'session', context: 'B'.repeat(43) }); });
  await screen.findByText('reader-B · VIEWER');
  await screen.findByText('No scans on this page.');
  await act(async () => { resolveOld(json({ items: [{
    scan_id: '11111111-1111-1111-1111-111111111111', status: 'COMPLETED', aws_account_id: 'old-identity-data',
    requested_regions: [], successful_regions: [], requested_services: [], successful_collectors: [],
    started_at: '2026-10-04T00:00:00Z', completed_at: null, failure: null
  }], total: 1, limit: 25, offset: 0 })); });
  expect(screen.queryByText(/old-identity-data/)).not.toBeInTheDocument();
  expect(screen.getByText('reader-B · VIEWER')).toBeInTheDocument();
});

it('announces immediate logout invalidation without secrets and ignores late logout errors after identity changes', async () => {
  let rejectLogout!: (value: Error) => void;
  let session = authenticated();
  const fetch = vi.fn((url: string) => url.endsWith('/logout')
    ? new Promise<Response>((_, reject) => { rejectLogout = reject; })
    : Promise.resolve(url.endsWith('/session') ? json(session) : empty()));
  vi.stubGlobal('fetch', fetch);
  render(<App />);
  await screen.findByText('reader-A · VIEWER');
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  expect(screen.queryByText('reader-A · VIEWER')).not.toBeInTheDocument();
  const notifications = TestChannel.instances[0];
  expect(notifications.messages.at(-1)).toEqual({ type: 'clear', context: 'A'.repeat(43) });
  expect(JSON.stringify(notifications.messages)).not.toMatch(/csrf|reader-A|roles|token/);
  session = authenticated('reader-B', 'B'.repeat(43));
  await act(async () => { notifications.receive({ type: 'session', context: 'B'.repeat(43) }); });
  await screen.findByText('reader-B · VIEWER');
  await act(async () => { rejectLogout(new Error('late logout error')); });
  await waitFor(() => expect(screen.queryByText(/late logout error/)).not.toBeInTheDocument());
});
