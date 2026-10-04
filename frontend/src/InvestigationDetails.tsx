import { useState } from 'react';
import { assessmentBound, eligibility, exceptionPage, findingPage, isAssessmentDetail, isControl,
  isFindingDetail, isOutcomeDetail, isRelationship, isResource, proofLinks, sameEndpoint, sameOutcome, snapshotPage,
  type Assessment, type Citation, type Endpoint, type Finding, type Outcome, type Relationship, type Scope } from './investigation-api';
import { Metadata, mismatch, Paging, Payload, ReadState } from './InvestigationUI';
import { useInvestigationRead, type ReadProps } from './useInvestigationRead';

export interface GraphSelection { kind: 'source-outcomes' | 'relationships'; id: string;
  citation?: Citation; outcome?: Outcome; relationship?: Relationship; provenance?: Relationship['provenance'] }
export type SelectGraph = (selection: GraphSelection) => void;

export function SnapshotPanel({ scanId, resourceId, snapshotId, readProps }: { scanId: string;
  resourceId: string; snapshotId: string; readProps: ReadProps }) {
  const history = useInvestigationRead(`api/resources/${resourceId}/history?scan_id=${scanId}&limit=25`, snapshotPage, readProps);
  const identity = useInvestigationRead(`api/resources/${resourceId}`, isResource, readProps);
  const error = history.error || identity.error;
  const page = history.data?.value, resource = identity.data?.value;
  const snapshot = page?.items[0];
  const bound = page && resource && page.total === 1 && page.offset === 0 && page.limit === 25 && page.items.length === 1
    && resource.resource_id === resourceId && snapshot?.resource_id === resourceId && snapshot.scan_id === scanId
    && snapshot.snapshot_id === snapshotId && snapshot.scope === resource.scope
    && snapshot.region === (resource.scope === 'global' ? null : resource.region);
  return <section aria-label="Exact observed snapshot"><h4>Exact observed snapshot</h4>
    <ReadState error={error} ready={Boolean(page && resource)} />
    {!error && page && resource ? !bound ? <p role="alert">{mismatch}</p> : <>
      <p>Stable identity and first-seen ARN are separate from this scan's immutable observation. Latest configuration is never substituted.</p>
      <Metadata rows={[
        ['Resource UUID', resourceId], ['Snapshot UUID', snapshotId], ['Snapshot scan UUID', scanId],
        ['Resource owner', resource.aws_account_id], ['AWS resource ID', resource.aws_resource_id],
        ['Service / family', `${resource.service} / ${resource.resource_type}`], ['Scope', snapshot.scope],
        ['Observed Region', snapshot.region], ['First-seen ARN', resource.arn], ['Observed ARN', snapshot.arn],
        ['Observed name', snapshot.name], ['Observed at', snapshot.observed_at], ['State SHA-256', snapshot.state_sha256]
      ]} /><Payload value={snapshot.tags} label="Observed tags" />
      <Payload value={snapshot.normalized_configuration} label="Observed configuration" />
    </> : null}</section>;
}

export function AssessmentPanel({ selected, scope, readProps, selectGraph }: { selected: Assessment; scope: Scope;
  readProps: ReadProps; selectGraph: SelectGraph }) {
  const state = useInvestigationRead(`api/assessments/${selected.assessment_id}`, isAssessmentDetail, readProps);
  const value = state.data?.value;
  const bound = value && assessmentBound(value, scope) && value.assessment_id === selected.assessment_id
    && value.resource_id === selected.resource_id && value.resource_snapshot_id === selected.resource_snapshot_id
    && value.control_id === selected.control_id && value.control_version_id === selected.control_version_id
    && value.assessment_result === selected.assessment_result;
  return <section aria-label="Historical assessment detail"><h3>Historical assessment detail</h3>
    <ReadState error={state.error} ready={Boolean(value)} />
    {!state.error && value ? !bound ? <p role="alert">{mismatch}</p> : <BoundAssessment key={value.assessment_id}
      value={value} scope={scope} readProps={readProps} selectGraph={selectGraph} /> : null}</section>;
}
function BoundAssessment({ value, scope, readProps, selectGraph }: { value: import('./investigation-api').AssessmentDetail;
  scope: Scope; readProps: ReadProps; selectGraph: SelectGraph }) {
  const control = useInvestigationRead(`api/controls/${value.control_id}`, isControl, readProps);
  const [operational, setOperational] = useState(false);
  const versions = control.data?.value.versions.filter(v => v.control_version_id === value.control_version_id);
  const version = versions?.[0];
  const definition = scope.controls.find(c => c.control_version_id === value.control_version_id && c.control_id === value.control_id);
  const bound = control.data && control.data.value.control_id === value.control_id && versions?.length === 1
    && version?.catalog_id === scope.catalog.catalog_id && version.catalog_key === scope.scan.control_catalog_id
    && version.catalog_version === scope.scan.control_catalog_version && definition
    && definition.control_key === control.data.value.control_key && definition.definition_checksum === version.definition_checksum;
  return <><Metadata rows={[
    ['Assessment UUID', value.assessment_id], ['Technical result', value.assessment_result], ['Reason', value.reason],
    ['Evaluated at', value.evaluated_at], ['Control UUID', value.control_id], ['Control version UUID', value.control_version_id],
    ['Profile version UUID', value.assessment_profile_version_id], ['Historical finding UUID', value.finding_id],
    ['Historical occurrence UUID', value.finding_occurrence_id]
  ]} /><Payload value={value.missing_evidence} label="Missing required evidence" />
    <SnapshotPanel scanId={value.scan_id} resourceId={value.resource_id} snapshotId={value.resource_snapshot_id} readProps={readProps} />
    <h4>Exact control definition</h4><ReadState error={control.error} ready={Boolean(control.data)} />
    {!control.error && control.data ? !bound ? <p role="alert">{mismatch}</p> : <>
      <Metadata rows={[
        ['Control key', control.data.value.control_key], ['Definition title', version!.title],
        ['Severity', version!.severity], ['Definition checksum', version!.definition_checksum]
      ]} /><Payload value={version} label="Version-bound control metadata" />
    </> : null}
    <h4>Structured assessment evidence</h4>
    {value.evidence.length === 0 ? <p>No decisive evidence artifacts were retained. Missing evidence is not PASS.</p> : null}
    {value.evidence.map(evidence => {
      const links = bound ? proofLinks(evidence, control.data!.value.control_key) : null;
      return <article key={evidence.evidence_id}><Metadata rows={[
        ['Evidence UUID', evidence.evidence_id], ['Schema', `${evidence.schema_name} / ${evidence.schema_version}`],
        ['Evidence key', evidence.evidence_key], ['Payload SHA-256', evidence.payload_sha256],
        ['Collector', evidence.collector], ['Source / API', `${evidence.source} / ${evidence.source_api}`], ['Collected at', evidence.collected_at]
      ]} /><Payload value={evidence.payload} label="Retained evidence payload" />
        {links ? <><p>Typed citations bound to this evidence scan; these are navigation pointers, not fresh rule evaluation.</p>
          {links.sources.map(citation => <button key={citation.source_outcome_id} onClick={() => selectGraph({ kind: 'source-outcomes', id: citation.source_outcome_id, citation })}>Open cited source {citation.source_outcome_id}</button>)}
          {links.edges.map(id => <button key={id} onClick={() => selectGraph({ kind: 'relationships', id })}>Open cited relationship {id}</button>)}
        </> : <p>Legacy or unsupported source-proof schema: raw structured evidence remains readable; no graph link is inferred.</p>}
      </article>;
    })}
    <Payload value={value.framework_mappings} label="Retained mapping provenance (not a NIST result)" />
    <button onClick={() => setOperational(v => !v)} aria-expanded={operational}>Current findings and exceptions</button>
    {operational ? <Operational key={value.assessment_id} assessment={value} readProps={readProps} /> : null}
  </>;
}

function Operational({ assessment, readProps }: { assessment: Assessment; readProps: ReadProps }) {
  const [offset, setOffset] = useState(0), [status, setStatus] = useState(''), [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<Finding | null>(null);
  const state = useInvestigationRead(`api/findings?resource_id=${assessment.resource_id}&control_id=${assessment.control_id}&limit=25&offset=${offset}${status ? `&status=${status}` : ''}`, findingPage, readProps, revision);
  const page = state.data?.value;
  const bound = page && page.offset === offset && page.limit === 25 && page.items.every(x => x.resource_id === assessment.resource_id
    && x.control_id === assessment.control_id && (!status || x.status === status));
  return <section aria-label="Current operational handling"><h4>Current operational handling</h4>
    <p>Retrieved current state, not finding or exception state at scan time. ACCEPTED_RISK and exceptions never rewrite technical {assessment.assessment_result}.</p>
    <label>Finding status<select value={status} onChange={e => { setStatus(e.target.value); setOffset(0); setSelected(null); }}>
      <option value="">All statuses</option>{['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'].map(x => <option key={x}>{x}</option>)}</select></label>
    <button onClick={() => { setSelected(null); setRevision(v => v + 1); }}>Refresh current handling</button>
    <ReadState error={state.error} ready={Boolean(page)} />
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : <>
      <p>Server retrieval reference: {state.data?.readAt ?? 'unavailable'}; pages can change between reads.</p>
      {page.items.length === 0 ? <p>No current findings on this filtered page. This does not change the historical assessment.</p> : <ul>
        {page.items.map(f => <li key={f.finding_id}><button onClick={() => setSelected(f)}>{f.status} — {f.finding_id}</button>
          <span> · {f.occurrence_count} retained occurrences</span></li>)}</ul>}
    </> : null}
    <Paging label="findings" offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={v => { setSelected(null); setOffset(v); }} />
    {selected && bound ? <CurrentFinding key={`${selected.finding_id}:${revision}`} finding={selected} readProps={readProps} /> : null}
  </section>;
}
function CurrentFinding({ finding, readProps }: { finding: Finding; readProps: ReadProps }) {
  const [offset, setOffset] = useState(0), [history, setHistory] = useState(false);
  const state = useInvestigationRead(`api/exceptions?finding_id=${finding.finding_id}&limit=25&offset=${offset}`, exceptionPage, readProps);
  const detail = useInvestigationRead(history ? `api/findings/${finding.finding_id}` : null, isFindingDetail, readProps);
  const page = state.data?.value;
  const bound = page && page.offset === offset && page.limit === 25 && page.items.every(x => x.finding_id === finding.finding_id
    && x.resource_id === finding.resource_id && x.control_id === finding.control_id);
  const detailBound = detail.data && detail.data.value.finding_id === finding.finding_id
    && detail.data.value.resource_id === finding.resource_id && detail.data.value.control_id === finding.control_id;
  return <><Metadata rows={[
    ['Current finding UUID', finding.finding_id], ['Current stored status', finding.status], ['Finding owner', finding.aws_account_id],
    ['First detected', finding.first_detected_at], ['Last detected', finding.last_detected_at], ['Resolved at', finding.resolved_at]
  ]} /><h5>Time-aware exceptions</h5><ReadState error={state.error} ready={Boolean(page)} />
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : <>
      <p>Eligibility evaluated only at server reference {state.data?.readAt ?? 'unavailable'}. Refresh to retrieve current state; this is not a transactionally frozen mixed report.</p>
      {page.items.length === 0 ? <p>No exceptions on this page.</p> : page.items.map(x => <article key={x.exception_id}>
        <Metadata rows={[
          ['Exception UUID', x.exception_id], ['Stored exception status', x.status], ['Eligibility', eligibility(x, state.data?.readAt ?? null)],
          ['Approved by', x.approved_by], ['Reason', x.reason], ['Created at', x.created_at], ['Expires at', x.expires_at], ['Revoked at', x.revoked_at]
        ]} /></article>)}
    </> : null}
    <Paging label="exceptions" offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={setOffset} />
    <button onClick={() => setHistory(v => !v)} aria-expanded={history}>Retained finding occurrences</button>
    {history ? <><p>This existing detail API returns all retained occurrences and exceptions without pagination. Display is bounded; the API payload is not.</p>
      <ReadState error={detail.error} ready={Boolean(detail.data)} />
      {!detail.error && detail.data ? !detailBound ? <p role="alert">{mismatch}</p> : <>
        <p>Finding detail retrieved at server reference {detail.data.readAt ?? 'unavailable'}; it may differ from the list retrieval.</p>
        <Payload value={detail.data.value.occurrences} label="Retained occurrence history" />
      </> : null}</> : null}
  </>;
}

export function GraphPanel({ selected, scope, readProps, selectGraph }: { selected: GraphSelection; scope: Scope;
  readProps: ReadProps; selectGraph: SelectGraph }) {
  return selected.kind === 'source-outcomes' ? <OutcomePanel key={selected.id} selected={selected} scope={scope} readProps={readProps} />
    : <RelationshipPanel key={selected.id} selected={selected} scope={scope} readProps={readProps} selectGraph={selectGraph} />;
}
function OutcomePanel({ selected, scope, readProps }: { selected: GraphSelection; scope: Scope; readProps: ReadProps }) {
  const state = useInvestigationRead(`api/source-outcomes/${selected.id}`, isOutcomeDetail, readProps);
  const value = state.data?.value;
  const citation = selected.citation, old = selected.outcome, provenance = selected.provenance;
  const bound = value && value.source_outcome_id === selected.id && value.scan_id === scope.scan.scan_id
    && value.collection_account_id === scope.scan.aws_account_id
    && (!citation || value.artifact_id === citation.artifact_id && value.evidence_sha256 === citation.evidence_sha256)
    && (!old || sameOutcome(value, old))
    && (!provenance || value.evidence_reference === provenance.evidence_reference && value.collector === provenance.collector
      && value.collector_version === provenance.collector_version && value.source === provenance.source
      && value.source_api === provenance.source_api && value.collected_at === provenance.collected_at);
  return <section aria-label="Source outcome and artifact"><h3>Source outcome and artifact</h3>
    <ReadState error={state.error} ready={Boolean(value)} />
    {!state.error && value ? !bound ? <p role="alert">{mismatch}</p> : <>
      <Metadata rows={[
        ['Source outcome UUID', value.source_outcome_id], ['Source scan UUID', value.scan_id], ['Collection account', value.collection_account_id],
        ['Source state', value.state], ['Failure category', value.failure_category], ['Phase', value.phase], ['Evidence kind', value.evidence_kind],
        ['Collector / version', `${value.collector} / ${value.collector_version}`], ['Source API', value.source_api], ['Source collected at', value.collected_at],
        ['Artifact UUID', value.artifact_id], ['Evidence reference (text only)', value.evidence_reference], ['Evidence SHA-256', value.evidence_sha256],
        ['Artifact schema', `${value.artifact.evidence_schema} / ${value.artifact.evidence_schema_version}`]
      ]} /><Payload value={value.subject} label="Exact source subject" />
      <Payload value={value.artifact.normalized_payload} label="Normalized source artifact" />
    </> : null}</section>;
}
function RelationshipPanel({ selected, scope, readProps, selectGraph }: { selected: GraphSelection; scope: Scope;
  readProps: ReadProps; selectGraph: SelectGraph }) {
  const state = useInvestigationRead(`api/relationships/${selected.id}`, isRelationship, readProps);
  const [endpoint, setEndpoint] = useState<Endpoint | null>(null);
  const value = state.data?.value, old = selected.relationship;
  const bound = value && value.observation_id === selected.id && value.scan_id === scope.scan.scan_id
    && value.collection_account_id === scope.scan.aws_account_id && (!old || value.relationship_id === old.relationship_id
      && value.source_outcome_id === old.source_outcome_id && sameEndpoint(value.source, old.source)
      && sameEndpoint(value.target, old.target) && value.resolution === old.resolution && value.relationship_type === old.relationship_type
      && (['collector', 'collector_version', 'source', 'source_api', 'evidence_reference', 'collected_at'] as const)
        .every(k => value.provenance[k] === old.provenance[k]));
  return <section aria-label="Directional relationship"><h3>Directional relationship</h3><ReadState error={state.error} ready={Boolean(value)} />
    {!state.error && value ? !bound ? <p role="alert">{mismatch}</p> : <>
      <Metadata rows={[
        ['Observation UUID', value.observation_id], ['Relationship UUID', value.relationship_id], ['Relationship scan UUID', value.scan_id],
        ['Direction / type', value.relationship_type], ['Resolution', value.resolution], ['Relationship source outcome UUID', value.source_outcome_id]
      ]} /><p>Source → target. An unresolved reference is not a collected resource; no reverse or multi-hop traversal is inferred.</p>
      {(['source', 'target'] as const).map(side => <article key={side}><h4>{side === 'source' ? 'Source endpoint' : 'Target endpoint'}</h4>
        <Payload value={value[side]} label={`${side} identity and scope`} />
        {value[side].identity_state === 'stable' && value[side].resource_snapshot_id
          ? <button onClick={() => setEndpoint(value[side])}>Open exact {side} snapshot</button>
          : <p>Unresolved target reference — {value[side].reference_id ?? value[side].stable_resource_id}; no snapshot is available.</p>}
      </article>)}
      <Payload value={value.provenance} label="Relationship provenance" />
      <button onClick={() => selectGraph({ kind: 'source-outcomes', id: value.source_outcome_id, provenance: value.provenance })}>Open relationship source artifact</button>
      {endpoint?.stable_resource_id && endpoint.resource_snapshot_id ? <SnapshotPanel key={endpoint.resource_snapshot_id}
        scanId={value.scan_id} resourceId={endpoint.stable_resource_id} snapshotId={endpoint.resource_snapshot_id} readProps={readProps} /> : null}
    </> : null}</section>;
}
