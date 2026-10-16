import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { APIError, type Session } from './api';
import { Metadata, Payload } from './InvestigationUI';
import { actionId, sameImmutable } from './remediation-api';
import { canPrepare, normalizedPreparation, OperationError, prepareOperation, recoverOperations,
  remediationEnabled, sameIntentTarget, samePrepared, submitOperation,
  type Preparation, type PreparedOperation, type RemediationSession } from './remediation-operations';

export const reconciliationNotice = 'Submitted requests are not canceled by timeout, logout or expiry. '
  + 'After session or process loss, sign in and review immutable history before any replacement. An empty operation list does not prove no effect.';
interface Workflow {
  session: RemediationSession; ready: boolean; busy: boolean; revision: number;
  prepare: (request: Preparation) => Promise<boolean>;
}
const WorkflowContext = createContext<Workflow | null>(null);
export const useRemediationWorkflow = () => useContext(WorkflowContext);
export function RemediationWorkflow({ session, onError, children }: {
  session: Extract<Session, { authenticated: true }>; onError: (error: Error) => void; children: ReactNode
}) {
  return remediationEnabled(session) ? <EnabledWorkflow key={session.session_context} session={session} onError={onError}>
    {children}</EnabledWorkflow> : <>{children}</>;
}
function EnabledWorkflow({ session, onError, children }: { session: RemediationSession;
  onError: (error: Error) => void; children: ReactNode }) {
  const [operations, setOperations] = useState<PreparedOperation[]>([]);
  const [uncertain, setUncertain] = useState<Set<string>>(new Set());
  const [ready, setReady] = useState(false), [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(''), [revision, setRevision] = useState(0);
  const operationsRef = useRef<PreparedOperation[]>([]), busyRef = useRef(false), live = useRef(true);
  const readGeneration = useRef(0);
  const controllers = useRef(new Set<AbortController>()), errors = useRef(onError);
  const heading = useRef<HTMLHeadingElement>(null);
  const { issuer, subject, session_context: context } = session;
  useEffect(() => { errors.current = onError; }, [onError]);
  function replace(values: PreparedOperation[]) { operationsRef.current = values; setOperations(values); }
  function accept(value: PreparedOperation) {
    replace([...operationsRef.current.filter(v => v.operation_id !== value.operation_id), value]);
    if (value.state === 'CONFIRMED') setUncertain(previous => {
      const next = new Set(previous); next.delete(value.operation_id); return next;
    });
  }
  function report(error: unknown, stage: OperationError['stage']) {
    const safe = error instanceof OperationError ? error : new OperationError(stage, 0);
    if (safe instanceof APIError && safe.status === 401) {
      live.current = false;
      replace([]); setUncertain(new Set()); setReady(false);
    }
    setMessage(safe.message); errors.current(safe);
  }
  useEffect(() => {
    live.current = true;
    const currentRead = ++readGeneration.current;
    const controller = new AbortController(); controllers.current.add(controller);
    let active = true;
    void recoverOperations({ issuer, subject, session_context: context }, controller.signal).then(values => {
      if (active && currentRead === readGeneration.current) { operationsRef.current = values; setOperations(values); setReady(true); }
    }).catch((error: unknown) => {
      if (active && currentRead === readGeneration.current) {
        const safe = error instanceof OperationError ? error : new OperationError('RECOVER', 0);
        setMessage(safe.message); errors.current(safe);
      }
    }).finally(() => { controllers.current.delete(controller); });
    const activeControllers = controllers.current;
    return () => {
      active = false; live.current = false; readGeneration.current += 1;
      for (const pending of activeControllers) pending.abort();
      activeControllers.clear();
    };
  }, [issuer, subject, context]);
  async function refresh() {
    if (busyRef.current || !live.current) return;
    busyRef.current = true; setBusy(true);
    readGeneration.current += 1; // Supersede a still-pending initial recovery read.
    const controller = new AbortController(); controllers.current.add(controller);
    try {
      const values = await recoverOperations(session, controller.signal);
      if (!live.current) return;
      // A changed immutable body/deadline is not a new grant under an existing UUID.
      if (operationsRef.current.some(old => !values.some(value => value.operation_id === old.operation_id))
        || values.some(value => operationsRef.current.some(old => old.operation_id === value.operation_id
          && (!samePrepared(old, value) || value.attempts < old.attempts
            || old.state === 'EXPIRED' && value.state !== 'EXPIRED'
            || old.state === 'CONFIRMED' && (value.state !== 'CONFIRMED' || !sameImmutable(value.result, old.result))))))
        throw new OperationError('RECOVER', 0);
      replace(values); setReady(true); setMessage('Coordination refreshed; no request was submitted.');
      setUncertain(previous => new Set([...previous].filter(id => !values.some(v => v.operation_id === id && v.state === 'CONFIRMED'))));
    } catch (error) { if (live.current) { setReady(false); report(error, 'RECOVER'); } }
    finally { controllers.current.delete(controller); busyRef.current = false; if (live.current) setBusy(false); }
  }
  async function prepare(request: Preparation): Promise<boolean> {
    if (!ready || busyRef.current || !live.current) return false;
    let normalized: Preparation;
    try { normalized = normalizedPreparation(request); }
    catch (error) { report(error, 'PREPARE'); return false; }
    if (operationsRef.current.some(v => ['PREPARED', 'IN_FLIGHT', 'UNCONFIRMED'].includes(v.state) && sameIntentTarget(v, normalized))
      || operationsRef.current.some(v => uncertain.has(v.operation_id) && sameIntentTarget(v, normalized))) {
      setMessage('This target already has an unresolved operation. Use that original operation or reconcile its immutable history; do not prepare a replacement key.');
      heading.current?.focus(); return false;
    }
    busyRef.current = true; setBusy(true); setMessage('');
    const controller = new AbortController(); controllers.current.add(controller);
    try {
      const value = await prepareOperation(session, normalized, controller.signal);
      if (!live.current) return false;
      accept(value); setMessage('Prepared only. Review the frozen request below, then explicitly confirm submission.');
      heading.current?.focus(); return true;
    } catch (error) {
      if (live.current) { setReady(false); report(error, 'PREPARE'); }
      return false;
    } finally { controllers.current.delete(controller); busyRef.current = false; if (live.current) setBusy(false); }
  }
  async function submit(value: PreparedOperation) {
    if (!ready || busyRef.current || !live.current) return;
    busyRef.current = true; setBusy(true); setMessage('');
    const controller = new AbortController(); controllers.current.add(controller);
    try {
      const result = await submitOperation(session, value, controller.signal);
      if (!live.current) return;
      accept(result);
      if (result.state === 'CONFIRMED') {
        setRevision(v => v + 1);
        setMessage('Request confirmed in immutable history. This is not worker execution or a verification verdict.');
      } else setMessage('Request outcome is not confirmed. Refresh coordination or explicitly retry the same operation; never replace its key.');
    } catch (error) {
      if (live.current) {
        // This is browser uncertainty, not an invented server phase or attempt count.
        setUncertain(previous => new Set([...previous, value.operation_id]));
        report(error, 'SUBMIT');
      }
    } finally { controllers.current.delete(controller); busyRef.current = false; if (live.current) setBusy(false); }
  }
  return <WorkflowContext.Provider value={{ session, ready, busy, revision, prepare }}>
    {children}
    <section className="remediation-workflow" aria-label="Manual remediation operations">
      <h2 id="remediation-operations" ref={heading} tabIndex={-1}>Manual remediation operations</h2>
      <p className="notice">{reconciliationNotice}</p>
      <p>Preparation is temporary coordination, not approval or an execution grant. No worker is launched here. Backend scopes remain independently controlled.</p>
      <button onClick={() => { void refresh(); }} disabled={busy}>Refresh same-session operations</button>
      {!ready ? <p role="status">Recover operations before preparing new work. No automatic submission or retry occurs.</p> : null}
      {message ? <p role="status">{message}</p> : null}
      {ready && operations.length === 0 ? <p>No operations in this session. Review prior immutable history if a session or process was lost.</p> : null}
      {operations.map(value => <OperationCard key={value.operation_id} value={value} uncertain={uncertain.has(value.operation_id)}
        disabled={!ready || busy || !canPrepare(session, value.operation)} submit={submit} />)}
    </section>
  </WorkflowContext.Provider>;
}
function OperationCard({ value, uncertain, disabled, submit }: { value: PreparedOperation;
  uncertain: boolean; disabled: boolean; submit: (value: PreparedOperation) => Promise<void> }) {
  const [reviewed, setReviewed] = useState(false);
  const canSubmit = value.state === 'PREPARED' || value.state === 'UNCONFIRMED';
  return <article className="prepared-operation" aria-label={`Prepared ${value.operation} ${value.operation_id}`}>
    <h3>{value.operation} · {value.state}</h3>
    <Metadata rows={[
      ['Prepared operation UUID', value.operation_id], ['Frozen target UUID', value.target_id],
      ['Actor issuer', value.actor.issuer], ['Actor subject', value.actor.subject],
      ['Prepared at', new Date(value.prepared_at * 1000).toISOString()], ['Preparation expires at', new Date(value.expires_at * 1000).toISOString()],
      ['Last server coordination state', value.state], ['Server dispatch attempts', value.attempts]
    ]} />
    <Metadata rows={[
      ['Fixed action', `${actionId} / 1.0.0`], ['Frozen reason', value.input.reason],
      ...(value.operation === 'PROPOSE' ? [['Finding UUID', value.input.finding_id], ['Retained occurrence UUID', value.input.occurrence_id]] as [string, string][] : []),
      ...('proposal_sha256' in value.input ? [['Frozen proposal SHA-256', value.input.proposal_sha256]] as [string, string][] : []),
      ...('approval_decision_id' in value.input ? [['Frozen approval UUID', value.input.approval_decision_id]] as [string, string][] : []),
      ...(value.operation === 'DECIDE' ? [['Frozen decision', value.input.decision]] as [string, string][] : [])
    ]} />
    <p>{value.risk_summary}</p>
    <Payload value={value.input} label="Frozen request for explicit review" />
    {value.operation === 'PROPOSE' ? <p>This is not yet a sealed proposal; no proposal digest exists at preparation.</p> : null}
    {value.operation === 'REQUEST_EXECUTION' ? <p>Submitting requests a bounded third-human execution grant. An independently operated write worker may use accepted authority; this page does not launch it.</p> : null}
    {value.operation === 'REQUEST_VERIFICATION' ? <p>Submitting may queue a linked read-only scan. It cannot retry the remediation write and does not itself establish a verdict.</p> : null}
    {uncertain || value.state === 'UNCONFIRMED' ? <p role="alert">Submission outcome is unconfirmed. A later denial or an old PREPARED read cannot prove an earlier commit absent. Use this same operation, never a replacement key.</p> : null}
    {value.state === 'IN_FLIGHT' ? <p>Dispatch is in flight. Refresh coordination; do not submit another intent.</p> : null}
    {value.state === 'EXPIRED' ? <p>Preparation cannot be renewed. Expiry is not cancellation of any prior effects; review immutable history.</p> : null}
    {value.result ? <><p>Confirmed request result UUID: <span className="mono">{value.result.result_id}</span></p>
      {value.result.scan_id ? <p>Linked read-only scan UUID: <span className="mono">{value.result.scan_id}</span></p> : null}
      <p>Refresh and inspect the relevant immutable history. Request confirmation is not execution success or VERIFIED.</p></> : null}
    {canSubmit ? <form onSubmit={event => { event.preventDefault(); if (!disabled && reviewed) { setReviewed(false); void submit(value); } }}>
      <label><input type="checkbox" checked={reviewed} onChange={event => setReviewed(event.target.checked)} disabled={disabled} />
        I reviewed this frozen target, input, actor and risk; this submission does not launch a worker.</label>
      <button disabled={disabled || !reviewed}>{value.state === 'UNCONFIRMED' || uncertain ? 'Explicitly retry original request' : 'Confirm and submit request'}</button>
    </form> : null}
  </article>;
}
