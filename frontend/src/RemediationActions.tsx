import { useId, useState, type ReactNode } from 'react';
import { Metadata } from './InvestigationUI';
import type { Page } from './investigation-api';
import { actionRisk, type Execution, type Proposal, type RemediationAnchor, type Verification } from './remediation-api';
import { canPrepare, differentActor, validReason, type Preparation } from './remediation-operations';
import { useRemediationWorkflow } from './RemediationWorkflow';

function ManualForm({ title, build, disabledReason, children }: { title: string;
  build: (reason: string) => Preparation; disabledReason?: string; children?: ReactNode }) {
  const workflow = useRemediationWorkflow(), id = useId();
  const [reason, setReason] = useState(''), [message, setMessage] = useState('');
  if (!workflow) return null;
  return <form aria-label={title} className="remediation-form" onSubmit={event => {
    event.preventDefault();
    if (disabledReason || !validReason(reason) || workflow.busy || !workflow.ready) return;
    setMessage('');
    void workflow.prepare(build(reason)).then(prepared => {
      if (prepared) { setReason(''); setMessage('Prepared for review in Manual remediation operations. Nothing was submitted automatically.'); }
    });
  }}>
    <h5>{title}</h5>{children}
    {disabledReason ? <p>{disabledReason}</p> : null}
    <label htmlFor={id}>{title} reason (1 to 2,000 Unicode characters)</label>
    <textarea id={id} value={reason} maxLength={4000} rows={3} onChange={event => setReason(event.target.value)}
      disabled={workflow.busy || !workflow.ready || Boolean(disabledReason)} required />
    <p>{[...reason].length} / 2,000 characters. The server rechecks authority and target state at submission.</p>
    <button disabled={workflow.busy || !workflow.ready || Boolean(disabledReason) || !validReason(reason)}>{title}</button>
    {message ? <p role="status">{message}</p> : null}
  </form>;
}
export function ProposeRemediation({ anchor }: { anchor: RemediationAnchor }) {
  const workflow = useRemediationWorkflow();
  if (!workflow) return null;
  const control = anchor.scope.controls.find(c => c.control_id === anchor.assessment.control_id
    && c.control_version_id === anchor.assessment.control_version_id);
  if (control?.control_key !== 'EC2-004') return <p>This retained control has no supported remediation action.</p>;
  if (!canPrepare(workflow.session, 'PROPOSE')) return <p>Proposing requires the PROPOSE capability; history remains readable.</p>;
  const a = anchor.assessment, s = anchor.scope.scan;
  if (s.status !== 'COMPLETED' || a.assessment_result !== 'FAIL' || !a.finding_id || !a.finding_occurrence_id)
    return <p>A proposal needs an exact completed EC2-004 FAIL occurrence. Technical results and missing evidence are not changed here.</p>;
  return <ManualForm title="Prepare proposal" build={reason => ({ schema_version: '1.0.0', operation: 'PROPOSE',
    input: { finding_id: a.finding_id!, occurrence_id: a.finding_occurrence_id!, reason } })}>
    <Metadata rows={[
      ['Retained scan UUID', a.scan_id], ['Retained assessment UUID', a.assessment_id],
      ['Retained resource UUID', a.resource_id], ['Retained snapshot UUID', a.resource_snapshot_id],
      ['Finding UUID', a.finding_id], ['Occurrence UUID', a.finding_occurrence_id],
      ['Retained account', s.aws_account_id], ['Retained Regions', s.requested_regions.join(', ')],
      ['Retained profile checksum', s.assessment_profile_checksum]
    ]} />
    <p>{actionRisk}</p><p>The service validates complete retained KMS/evidence and current governance. Preparation does not seal a proposal or bypass eligibility.</p>
  </ManualForm>;
}
export function ProposalActions({ proposal: p }: { proposal: Proposal }) {
  const workflow = useRemediationWorkflow();
  if (!workflow) return null;
  const base = { schema_version: '1.0.0' as const, target_id: p.content.proposal_id };
  const approval = p.decisions.find(d => d.kind === 'APPROVE');
  return <>
    {p.approval_status === 'PROPOSED' && canPrepare(workflow.session, 'DECIDE') ? differentActor(workflow.session, p.content.proposer) ? <>
      <ManualForm title="Prepare approval" disabledReason={p.blocking_reasons.length ? 'Current blockers prevent approval. Refresh history; a rejection may still be possible.' : undefined}
        build={reason => ({ ...base, operation: 'DECIDE', input: { proposal_sha256: p.proposal_sha256, decision: 'APPROVE', reason } })} />
      <ManualForm title="Prepare rejection" build={reason => ({ ...base, operation: 'DECIDE',
        input: { proposal_sha256: p.proposal_sha256, decision: 'REJECT', reason } })} />
    </> : <p>Initial approval or rejection requires a different verified issuer/subject pair; ADMIN cannot bypass this separation.</p> : null}
    {p.approval_status === 'APPROVED' && approval && canPrepare(workflow.session, 'REVOKE') ?
      <ManualForm title="Prepare revocation" build={reason => ({ ...base, operation: 'REVOKE',
        input: { proposal_sha256: p.proposal_sha256, approval_decision_id: approval.decision_id, reason } })}>
        <p>Any current APPROVE principal may revoke, including a proposer with that capability. Revocation is not cancellation or proof of no earlier effect.</p>
      </ManualForm> : null}
  </>;
}
export function AdmissionAction({ proposal: p, hasExecution }: { proposal: Proposal; hasExecution: boolean }) {
  const workflow = useRemediationWorkflow();
  if (!workflow || !canPrepare(workflow.session, 'REQUEST_EXECUTION')) return null;
  const approval = p.decisions.find(d => d.kind === 'APPROVE');
  if (hasExecution) return <p>An execution request already exists for this proposal. Inspect its history rather than prepare another admission.</p>;
  if (p.approval_status !== 'APPROVED' || !approval) return <p>Execution admission requires a retained approval.</p>;
  if (!differentActor(workflow.session, p.content.proposer) || !differentActor(workflow.session, approval.actor))
    return <p>Execution admission requires a third distinct issuer/subject pair, even for ADMIN.</p>;
  return <ManualForm title="Prepare execution admission" disabledReason={p.blocking_reasons.length ? 'Current proposal blockers prevent admission; refresh history.' : undefined}
    build={reason => ({ schema_version: '1.0.0', operation: 'REQUEST_EXECUTION', target_id: p.content.proposal_id,
      input: { proposal_sha256: p.proposal_sha256, approval_decision_id: approval.decision_id, reason } })}>
    <p>This requests a bounded write grant, not a worker launch. A separate authorized worker may use accepted authority; no AWS operation runs in the browser.</p>
  </ManualForm>;
}
export function VerificationAction({ execution, page }: { execution: Execution; page: Page<Verification> }) {
  const workflow = useRemediationWorkflow();
  if (!workflow || !canPrepare(workflow.session, 'REQUEST_VERIFICATION')) return null;
  if (execution.phase !== 'ACKNOWLEDGED') return <p>Linked verification requires a normal ACKNOWLEDGED execution; quarantine and late acknowledgment are not eligible.</p>;
  if (page.total >= 3) return <p>The three accepted verification attempts are exhausted. No automatic new scan or write retry is available.</p>;
  if (page.items.length !== page.total || page.items.some(v => v.receipt === null))
    return <p>Review the active or unavailable verification attempt before preparing another. Accepted submission failures count toward the limit.</p>;
  return <ManualForm title="Prepare linked verification" build={reason => ({ schema_version: '1.0.0', operation: 'REQUEST_VERIFICATION',
    target_id: execution.content.execution_id, input: { reason } })}>
    <p>Write authority may have expired or been revoked; this request grants no write. Submission may queue an exact-policy read-only scan. A confirmed request is not a verification verdict.</p>
  </ManualForm>;
}
