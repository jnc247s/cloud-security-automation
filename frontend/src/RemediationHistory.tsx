import { useState } from 'react';
import { Metadata, mismatch, Paging, Payload, ReadState } from './InvestigationUI';
import { useInvestigationRead, type ReadProps } from './useInvestigationRead';
import { AdmissionAction, ProposalActions, ProposeRemediation, VerificationAction } from './RemediationActions';
import { useRemediationWorkflow } from './RemediationWorkflow';
import { exactOccurrence, executionBound, executionPage, isExecution, isProposal, isVerification,
  proposalPage, sameFinding, sameImmutable, verificationBound, verificationPage,
  type Execution, type Proposal, type RemediationAnchor, type Verification } from './remediation-api';

export function RemediationHistory({ anchor, readProps }: { anchor: RemediationAnchor; readProps: ReadProps }) {
  const control = anchor.scope.controls.find(c => c.control_id === anchor.assessment.control_id
    && c.control_version_id === anchor.assessment.control_version_id);
  if (control?.control_key !== 'EC2-004' || !anchor.assessment.finding_id || !anchor.assessment.finding_occurrence_id)
    return <p>This assessment has no supported EC2-004 remediation occurrence. Controls and saved evidence have not been changed.</p>;
  return <ProposalHistory key={`${anchor.assessment.assessment_id}:${readProps.context}`} anchor={anchor} readProps={readProps} />;
}
function ProposalHistory({ anchor, readProps }: { anchor: RemediationAnchor; readProps: ReadProps }) {
  const workflow = useRemediationWorkflow();
  const [offset, setOffset] = useState(0), [selected, setSelected] = useState<Proposal | null>(null), [revision, setRevision] = useState(0);
  const state = useInvestigationRead(`api/remediations?finding_id=${anchor.assessment.finding_id}&limit=25&offset=${offset}`, proposalPage, readProps, revision + (workflow?.revision ?? 0));
  const page = state.data?.value;
  const bound = page && page.limit === 25 && page.offset === offset && page.items.every(p => sameFinding(p.content, anchor));
  return <section aria-label="Remediation history"><h4>Remediation history</h4>
    <p>Read-only history for this exact finding. Historical approval, current blockers, execution, verification and technical results are separate. No worker is launched here.</p>
    <ProposeRemediation anchor={anchor} />
    <button onClick={() => { setSelected(null); setRevision(v => v + 1); }}>Refresh remediation history</button>
    <ReadState error={state.error} ready={Boolean(page)} />
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : !page.items.length ? <p>No remediation proposals on this page. Absence of remediation is not PASS or verified.</p>
      : <ul>{page.items.map(p => <li key={p.content.proposal_id}>
        <button onClick={() => setSelected(p)}>Open proposal {p.content.proposal_id}</button>
        <p>{p.approval_status} · {exactOccurrence(p.content, anchor) ? 'Selected retained occurrence' : 'Different retained occurrence; not substituted for this assessment'}</p>
      </li>)}</ul> : null}
    <Paging label="proposals" offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={v => { setOffset(v); setSelected(null); }} />
    {selected && bound && !state.error ? <><button onClick={() => setSelected(null)}>Close proposal detail</button>
      <ProposalDetail key={selected.content.proposal_id} selected={selected} anchor={anchor} readProps={readProps} /></> : null}
  </section>;
}
function ProposalDetail({ selected, anchor, readProps }: { selected: Proposal; anchor: RemediationAnchor; readProps: ReadProps }) {
  const workflow = useRemediationWorkflow();
  const state = useInvestigationRead(`api/remediations/${selected.content.proposal_id}`, isProposal, readProps, workflow?.revision ?? 0);
  const p = state.data?.value;
  const bound = p && sameImmutable(p.content, selected.content) && p.proposal_sha256 === selected.proposal_sha256 && sameFinding(p.content, anchor);
  return <><ReadState error={state.error} ready={Boolean(p)} />
    {!state.error && p ? !bound ? <p role="alert">{mismatch}</p> : <>
      <Metadata rows={[
        ['Proposal UUID', p.content.proposal_id], ['Proposal SHA-256', p.proposal_sha256], ['Finding UUID', p.content.finding_id],
        ['Retained occurrence UUID', p.content.baseline.occurrence_id], ['Retained assessment UUID', p.content.baseline.assessment_id],
        ['Retained scan UUID', p.content.baseline.scan_id], ['Account / Region', `${p.content.account_id} / ${p.content.region}`],
        ['Fixed action', `${p.content.action_id} / ${p.content.action_version}`], ['Risk', p.content.risk_summary],
        ['Historical approval', p.approval_status], ['Current proposal blockers', p.blocking_reasons.join(', ') || 'None reported at this read'],
        ['Validity checked at', p.validity_checked_at], ['Authority expires at', p.content.expires_at], ['Proposal reason', p.content.reason],
        ['Proposer issuer', p.content.proposer.issuer], ['Proposer subject', p.content.proposer.subject]
      ]} />
      <p>{exactOccurrence(p.content, anchor) ? 'Bound to the selected retained occurrence and policy.' : 'This proposal belongs to another retained occurrence. It does not replace the selected assessment.'}</p>
      <p>Approval is historical, not proof of execution readiness. Current blockers can differ between reads; no browser clock grants authority.</p>
      <Payload value={p.content.baseline} label="Immutable baseline and source bindings" />
      <Payload value={p.decisions} label="Immutable decisions and verified actor context" />
      <ProposalActions proposal={p} />
      <ExecutionHistory key={p.content.proposal_id} proposal={p} readProps={readProps} />
    </> : null}</>;
}
function ExecutionHistory({ proposal, readProps }: { proposal: Proposal; readProps: ReadProps }) {
  const workflow = useRemediationWorkflow();
  const [offset, setOffset] = useState(0), [selected, setSelected] = useState<Execution | null>(null);
  const state = useInvestigationRead(`api/remediation-executions?proposal_id=${proposal.content.proposal_id}&limit=25&offset=${offset}`, executionPage, readProps, workflow?.revision ?? 0);
  const page = state.data?.value;
  const bound = page && page.limit === 25 && page.offset === offset && page.items.every(e => executionBound(e, proposal));
  return <section aria-label="Execution admission history"><h5>Execution admission history</h5>
    <p>Admission records a third identity's grant. QUEUED is not an AWS call; ACKNOWLEDGED is not a verification verdict.</p>
    {bound && !state.error ? <AdmissionAction proposal={proposal} hasExecution={page.total > 0} /> : null}
    <ReadState error={state.error} ready={Boolean(page)} />
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : !page.items.length ? <p>No execution requests on this page.</p>
      : <ul>{page.items.map(e => <li key={e.content.execution_id}><button onClick={() => setSelected(e)}>Open execution {e.content.execution_id}</button> {e.phase}</li>)}</ul> : null}
    <Paging label="executions" offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={v => { setOffset(v); setSelected(null); }} />
    {selected && bound && !state.error ? <><button onClick={() => setSelected(null)}>Close execution detail</button>
      <ExecutionDetail key={selected.content.execution_id} selected={selected} proposal={proposal} readProps={readProps} /></> : null}
  </section>;
}
function ExecutionDetail({ selected, proposal, readProps }: { selected: Execution; proposal: Proposal; readProps: ReadProps }) {
  const workflow = useRemediationWorkflow();
  const state = useInvestigationRead(`api/remediation-executions/${selected.content.execution_id}`, isExecution, readProps, workflow?.revision ?? 0);
  const e = state.data?.value;
  const bound = e && sameImmutable(e.content, selected.content) && e.execution_sha256 === selected.execution_sha256 && executionBound(e, proposal);
  return <><ReadState error={state.error} ready={Boolean(e)} />
    {!state.error && e ? !bound ? <p role="alert">{mismatch}</p> : <>
      <Metadata rows={[
        ['Execution UUID', e.content.execution_id], ['Execution SHA-256', e.execution_sha256], ['Execution phase', e.phase],
        ['Reservation held', e.reservation_held ? 'Yes' : 'No'], ['Current execution blockers', e.blocking_reasons.join(', ') || 'None reported at this read'],
        ['Execution validity checked at', e.validity_checked_at], ['Write grant expires at', e.content.expires_at],
        ['Requester issuer', e.content.requested_by.issuer], ['Requester subject', e.content.requested_by.subject]
      ]} />
      {e.phase === 'QUARANTINED' ? <p className="notice">Unknown effect is quarantined. A late acknowledgment or true readback does not clear quarantine, authorize a retry or establish verification.</p>
        : <p>Expired or revoked write authority does not erase history. Normal acknowledgment may still be eligible for an explicit read-only verification request.</p>}
      <Payload value={e.events} label="Versioned human and worker event history" />
      <VerificationHistory key={e.content.execution_id} execution={e} readProps={readProps} />
    </> : null}</>;
}
function VerificationHistory({ execution, readProps }: { execution: Execution; readProps: ReadProps }) {
  const workflow = useRemediationWorkflow();
  const [offset, setOffset] = useState(0), [selected, setSelected] = useState<Verification | null>(null);
  const state = useInvestigationRead(`api/remediation-verifications?execution_id=${execution.content.execution_id}&limit=25&offset=${offset}`, verificationPage, readProps, workflow?.revision ?? 0);
  const page = state.data?.value;
  const bound = page && page.limit === 25 && page.offset === offset && page.items.every(v => verificationBound(v, execution));
  return <section aria-label="Read-only verification history"><h5>Read-only verification history</h5>
    {bound && !state.error ? <VerificationAction execution={execution} page={page} /> : null}
    <ReadState error={state.error} ready={Boolean(page)} />
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : !page.items.length ? <p>No verification attempts on this page. This is not verified.</p>
      : <ul>{page.items.map(v => <li key={v.content.verification_id}><button onClick={() => setSelected(v)}>Open verification {v.content.verification_id}</button>
        {' '}Attempt {v.content.attempt}: {v.receipt?.outcome ?? 'Pending; no verification verdict'}</li>)}</ul> : null}
    <Paging label="verifications" offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={v => { setOffset(v); setSelected(null); }} />
    {selected && bound && !state.error ? <><button onClick={() => setSelected(null)}>Close verification detail</button>
      <VerificationDetail key={selected.content.verification_id} selected={selected} execution={execution} readProps={readProps} /></> : null}
  </section>;
}
function VerificationDetail({ selected, execution, readProps }: { selected: Verification; execution: Execution; readProps: ReadProps }) {
  const workflow = useRemediationWorkflow();
  const state = useInvestigationRead(`api/remediation-verifications/${selected.content.verification_id}`, isVerification, readProps, workflow?.revision ?? 0);
  const v = state.data?.value;
  const bound = v && sameImmutable(v.content, selected.content) && v.verification_sha256 === selected.verification_sha256 && verificationBound(v, execution);
  return <><ReadState error={state.error} ready={Boolean(v)} />
    {!state.error && v ? !bound ? <p role="alert">{mismatch}</p> : <>
      <Metadata rows={[
        ['Verification UUID', v.content.verification_id], ['Verification SHA-256', v.verification_sha256],
        ['Verification scan UUID', v.content.scan_id], ['Verification attempt', v.content.attempt],
        ['Verification verdict', v.receipt?.outcome ?? 'Pending; no verdict'], ['Verification classification', v.receipt?.reason ?? 'No sealed receipt'],
        ['Verification scan lifecycle', v.receipt?.scan_status ?? 'No terminal receipt'],
        ['Verification technical result', v.receipt?.evidence?.technical_result ?? 'No decisive retained evidence'],
        ['Verification receipt SHA-256', v.receipt_sha256], ['Verification observed at', v.receipt?.evidence?.observed_at ?? null]
      ]} />
      <p>VERIFIED records a complete later PASS with unchanged KMS context. It does not prove worker causation, usable key access, encryption of existing volumes or lasting state. Findings remain governed by ordinary scan assessment.</p>
      <Payload value={v} label="Immutable verification intent and receipt" />
    </> : null}</>;
}
