import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { App } from './App';
import { operationSession, preparedOperation, resultId } from './operation-fixtures.test-support';

class Channel {
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  postMessage() {}
  close() {}
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const scans = () => json({ items: [], total: 0, limit: 25, offset: 0 });
beforeEach(() => vi.stubGlobal('BroadcastChannel', Channel));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/dashboard/'); });

it('clears a pending remediation submission before sign-out completes and never restores its late response', async () => {
  const value = preparedOperation(); let signedIn = true;
  let finish!: (response: Response) => void;
  const fetch = vi.fn((url: string) => {
    if (url.endsWith('/session')) return Promise.resolve(json(signedIn ? operationSession() : { authenticated: false, csrf_token: 'login-only-csrf' }));
    if (url.endsWith('/auth/logout')) { signedIn = false; return Promise.resolve(new Response(null, { status: 204 })); }
    if (url.endsWith('/submit')) return new Promise<Response>(resolve => { finish = resolve; });
    if (url.endsWith('/remediation-operations')) return Promise.resolve(json({ schema_version: '1.0.0', items: [value] }));
    return Promise.resolve(scans());
  });
  vi.stubGlobal('fetch', fetch); render(<App />);
  await screen.findByRole('heading', { name: 'PROPOSE · PREPARED' });
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed this frozen target/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Confirm and submit request' }));
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => url.endsWith('/submit'))).toBe(true));
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  expect(screen.queryByText(value.operation_id)).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Manual remediation operations' })).not.toBeInTheDocument();
  await screen.findByRole('button', { name: /^Sign in$/ });
  await act(async () => { finish(json({ ...value, state: 'CONFIRMED', attempts: 1, result: { result_id: resultId, scan_id: null } })); });
  expect(screen.queryByText(resultId)).not.toBeInTheDocument();
  expect(screen.getByText(/Submitted requests are not canceled/)).toBeInTheDocument();
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

it('recovers sign-in after a coordination 401 without retaining old identity or data', async () => {
  let sessionReads = 0;
  const fetch = vi.fn((url: string) => {
    if (url.endsWith('/session')) return Promise.resolve(json(sessionReads++ === 0
      ? operationSession() : { authenticated: false, csrf_token: 'login-only-csrf' }));
    if (url.endsWith('/remediation-operations')) return Promise.resolve(json({}, 401));
    return Promise.resolve(scans());
  });
  vi.stubGlobal('fetch', fetch); render(<App />);
  await screen.findByRole('button', { name: /^Sign in$/ });
  expect(screen.queryByText('operator · ADMIN')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Manual remediation operations' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Scan history' })).not.toBeInTheDocument();
  expect(screen.getByText(/Submitted requests are not canceled/)).toBeInTheDocument();
});
