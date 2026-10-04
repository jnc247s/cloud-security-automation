import { useCallback, useEffect, useRef, useState } from 'react';
import { action, APIError, isSession, read, type Session } from './api';
import { ScanShell } from './ScanShell';

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [message, setMessage] = useState('Checking sign-in…');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const channel = useRef<BroadcastChannel | null>(null);
  const currentContext = useRef<string | null | undefined>(undefined);
  const signingOutContext = useRef<string | null>(null);
  const clear = useCallback((text: string) => {
    generation.current += 1;
    currentContext.current = undefined;
    setSession(null); setBusy(false); setMessage(text);
  }, []);
  const bootstrap = useCallback(async (signal?: AbortSignal, announce = false) => {
    const current = ++generation.current;
    try {
      const value = await read('session', isSession, signal);
      if (current === generation.current) {
        if (value.authenticated && value.session_context === signingOutContext.current) return;
        signingOutContext.current = null;
        currentContext.current = value.authenticated ? value.session_context : null;
        setSession(value); setMessage(value.authenticated ? '' : 'Sign in to view scan history.');
        if (announce) channel.current?.postMessage({ type: 'session', context: currentContext.current });
      }
    } catch (error) {
      if (!signal?.aborted && current === generation.current)
        setMessage(error instanceof Error ? error.message : 'Sign-in unavailable.');
    }
  }, []);
  useEffect(() => {
    // Ephemeral same-origin notifications only: no JWT, CSRF token, identity or report.
    // Server cookie/bearer/READ and expected-context checks remain authoritative.
    const notifications = new BroadcastChannel('cloudsec-dashboard-session');
    channel.current = notifications;
    notifications.onmessage = (event: MessageEvent<unknown>) => {
      const value = event.data;
      if (typeof value !== 'object' || value === null || !('type' in value) || !('context' in value)
        || !(value.context === null || (typeof value.context === 'string'
          && /^[A-Za-z0-9_-]{43}$/.test(value.context)))) return;
      if (value.type === 'clear') {
        if (typeof value.context === 'string'
          && (currentContext.current === undefined || currentContext.current === value.context)) {
          signingOutContext.current = value.context;
          clear('Signing out in another tab…');
        }
      } else if (value.type === 'session' && currentContext.current !== value.context
        && (signingOutContext.current === null || value.context !== signingOutContext.current)) {
        clear('Checking sign-in…'); void bootstrap(); // Do not echo notifications.
      }
    };
    return () => { notifications.close(); channel.current = null; };
  }, [bootstrap, clear]);
  useEffect(() => {
    const controller = new AbortController();
    void bootstrap(controller.signal, true);
    return () => { controller.abort(); generation.current += 1; };
  }, [bootstrap]);
  useEffect(() => {
    if (!session?.authenticated) return;
    const remaining = Math.min(session.expires_at, session.idle_expires_at) * 1000 - Date.now();
    // Status does not extend server idle time. At the old deadline, check whether a read extended it.
    const timer = setTimeout(() => {
      // Clear before checking: a network failure must not retain expired identity/data.
      clear('Checking sign-in…'); void bootstrap(undefined, true);
    }, Math.max(0, remaining));
    return () => clearTimeout(timer);
  }, [session, bootstrap, clear]);
  useEffect(() => {
    const restored = (event: PageTransitionEvent) => {
      if (event.persisted) { clear('Checking sign-in…'); void bootstrap(undefined, true); }
    };
    window.addEventListener('pageshow', restored);
    return () => window.removeEventListener('pageshow', restored);
  }, [bootstrap, clear]);

  async function login() {
    if (!session || session.authenticated || busy) return;
    setBusy(true);
    const current = generation.current;
    try {
      const response = await action('login', session.csrf_token);
      const value: unknown = await response.json();
      if (typeof value !== 'object' || value === null || !('authorization_url' in value)
        || typeof value.authorization_url !== 'string') throw new Error('Sign-in unavailable.');
      const url = new URL(value.authorization_url);
      if (url.protocol !== 'https:' && !(url.protocol === 'http:'
        && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)))
        throw new Error('Sign-in unavailable.');
      if (current === generation.current) window.location.assign(url.href);
    } catch (error) {
      if (current === generation.current) {
        setBusy(false); setMessage(error instanceof Error ? error.message : 'Sign-in unavailable.');
        // A rejected transaction is consumed server-side. Bootstrap a fresh CSRF-bound login.
        void bootstrap();
      }
    }
  }
  async function logout() {
    if (!session?.authenticated) return;
    const csrf = session.csrf_token;
    signingOutContext.current = session.session_context;
    channel.current?.postMessage({ type: 'clear', context: session.session_context });
    clear('Signing out…'); // Unmount data immediately, before the request can complete.
    const current = generation.current;
    try {
      await action('logout', csrf);
      if (current !== generation.current) return;
      window.history.replaceState(null, '', '/dashboard/');
      await bootstrap(undefined, true);
    } catch (error) {
      if (current === generation.current)
        setMessage(error instanceof Error ? `${error.message} Reload to confirm sign-out.` : 'Sign-out could not be confirmed. Reload.');
    }
  }
  function readError(error: Error) {
    if (error instanceof APIError && error.status === 401) {
      clear(error.message); void bootstrap(undefined, true);
    }
  }

  return <div className="app">
    <a className="skip" href="#main">Skip to content</a>
    <header><div><p className="eyebrow">Read-only security console</p>
      <h1>Cloud Security Control Plane</h1></div>
      {session?.authenticated ? <div className="identity">
        <span>{session.subject} · {session.roles.join(', ')}</span>
        <button onClick={() => { void logout(); }}>Sign out</button>
      </div> : null}
    </header>
    <main id="main"><p className="notice">Technical evidence context, not NIST certification or an organization-wide compliance score.</p>
      {message ? <p role="status">{message}</p> : null}
      {new URLSearchParams(window.location.search).get('login') === 'failed' ?
        <p role="alert">Sign-in was not completed. Please try again.</p> : null}
      {session?.authenticated ? <ScanShell key={session.session_context} context={session.session_context} onError={readError} />
        : session ? <button disabled={busy} onClick={() => { void login(); }}>
          {busy ? 'Opening sign-in…' : 'Sign in'}</button>
        : <button onClick={() => { void bootstrap(undefined, true); }}>Retry sign-in check</button>}
    </main>
  </div>;
}
