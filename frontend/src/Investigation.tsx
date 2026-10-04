import { useState, type FormEvent } from 'react';
import { isUUID } from './api';
import { assessmentBound, assessmentPage, isOutcome, isRelationship, pageOf,
  results, sourceStates, resolutions, type Assessment, type Outcome, type Relationship, type Scope } from './investigation-api';
import { AssessmentPanel, GraphPanel, type GraphSelection } from './InvestigationDetails';
import { mismatch, Paging, ReadState } from './InvestigationUI';
import { useInvestigationRead, type ReadProps } from './useInvestigationRead';

const graphPage = pageOf<Outcome | Relationship>((v): v is Outcome | Relationship => isOutcome(v) || isRelationship(v));
export function Investigation({ scope, ...readProps }: ReadProps & { scope: Scope }) {
  const [view, setView] = useState<'assessments' | 'source-outcomes' | 'relationships'>('assessments');
  const [graph, setGraph] = useState<GraphSelection | null>(null);
  return <section className="investigation" aria-labelledby="investigation"><h2 id="investigation">Exact-scan investigation</h2>
    <p>Read-only retained facts. Pages are bounded, but mutable totals and current handling are not a frozen mixed report. No NIST outcome result or compliance score is calculated.</p>
    <nav aria-label="Investigation views">{(['assessments', 'source-outcomes', 'relationships'] as const).map(kind =>
      <button key={kind} aria-pressed={view === kind} onClick={() => { setGraph(null); setView(kind); }}>{kind === 'assessments' ? 'Assessments' : kind === 'source-outcomes' ? 'Source outcomes' : 'Relationships'}</button>)}</nav>
    {view === 'assessments' ? <AssessmentList key={scope.scan.scan_id} scope={scope} readProps={readProps} selectGraph={setGraph} />
      : <GraphList key={`${scope.scan.scan_id}:${view}`} kind={view} scope={scope} readProps={readProps} selectGraph={setGraph} />}
    {graph ? <><button onClick={() => setGraph(null)}>Close graph detail</button><GraphPanel key={`${graph.kind}:${graph.id}`}
      selected={graph} scope={scope} readProps={readProps} selectGraph={setGraph} /></> : null}
  </section>;
}
function AssessmentList({ scope, readProps, selectGraph }: { scope: Scope; readProps: ReadProps;
  selectGraph: (v: GraphSelection | null) => void }) {
  const [offset, setOffset] = useState(0), [selected, setSelected] = useState<Assessment | null>(null);
  const [result, setResult] = useState(''), [resource, setResource] = useState(''), [control, setControl] = useState('');
  const [filters, setFilters] = useState({ result: '', resource: '', control: '' }), [filterError, setFilterError] = useState('');
  const params = new URLSearchParams({ scan_id: scope.scan.scan_id, limit: '25', offset: String(offset) });
  if (filters.result) params.set('result', filters.result);
  if (filters.resource) params.set('resource_id', filters.resource);
  if (filters.control) params.set('control_id', filters.control);
  const state = useInvestigationRead(filterError ? null : `api/assessments?${params}`, assessmentPage, readProps);
  const page = state.data?.value;
  const bound = page && page.offset === offset && page.limit === 25 && page.items.every(x => assessmentBound(x, scope)
    && (!filters.result || x.assessment_result === filters.result) && (!filters.resource || x.resource_id === filters.resource)
    && (!filters.control || x.control_id === filters.control));
  function submit(e: FormEvent) {
    e.preventDefault(); const r = resource.trim().toLowerCase(), c = control.trim().toLowerCase();
    setSelected(null); selectGraph(null);
    if ((r && !isUUID(r)) || (c && !isUUID(c))) { setFilterError('Resource and control filters require UUIDs.'); return; }
    setFilterError(''); setOffset(0); setFilters({ result, resource: r, control: c });
  }
  return <><form onSubmit={submit} aria-label="Assessment filters"><label>Technical result<select value={result} onChange={e => setResult(e.target.value)}>
    <option value="">All four states</option>{results.map(x => <option key={x}>{x}</option>)}</select></label>
    <label>Assessment resource UUID<input value={resource} maxLength={64} onChange={e => setResource(e.target.value)} /></label>
    <label>Assessment control UUID<input value={control} maxLength={64} onChange={e => setControl(e.target.value)} /></label>
    <button>Apply assessment filters</button></form>
    {filterError ? <p role="alert">{filterError}</p> : <ReadState error={state.error} ready={Boolean(page)} />}
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : page.items.length === 0
      ? <p>No assessments on this filtered page. Missing or unassessed targets are not PASS or NOT_APPLICABLE.</p>
      : <div className="table-scroll"><table><caption>Historical technical assessments for {scope.scan.scan_id}</caption>
        <thead><tr><th scope="col">Result</th><th scope="col">Resource UUID</th><th scope="col">Control version UUID</th><th scope="col">Detail</th></tr></thead>
        <tbody>{page.items.map(x => <tr key={x.assessment_id}><td>{x.assessment_result}</td><td className="mono">{x.resource_id}</td><td className="mono">{x.control_version_id}</td>
          <td><button onClick={() => { selectGraph(null); setSelected(x); }}>Open assessment {x.assessment_id}</button></td></tr>)}</tbody></table></div> : null}
    <Paging label="assessments" offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={v => { setOffset(v); setSelected(null); selectGraph(null); }} />
    {selected && bound ? <><button onClick={() => { setSelected(null); selectGraph(null); }}>Close assessment detail</button>
      <AssessmentPanel key={selected.assessment_id} selected={selected} scope={scope} readProps={readProps} selectGraph={selectGraph} /></> : null}
  </>;
}
function GraphList({ kind, scope, readProps, selectGraph }: { kind: 'source-outcomes' | 'relationships'; scope: Scope;
  readProps: ReadProps; selectGraph: (v: GraphSelection | null) => void }) {
  const [offset, setOffset] = useState(0), [filter, setFilter] = useState(''), [resource, setResource] = useState('');
  const [applied, setApplied] = useState({ filter: '', resource: '' }), [error, setError] = useState('');
  const params = new URLSearchParams({ scan_id: scope.scan.scan_id, limit: '25', offset: String(offset) });
  if (applied.filter) params.set(kind === 'source-outcomes' ? 'state' : 'resolution', applied.filter);
  if (applied.resource) params.set(kind === 'source-outcomes' ? 'subject_resource_id' : 'source_resource_id', applied.resource);
  const state = useInvestigationRead(error ? null : `api/${kind}?${params}`, graphPage, readProps);
  const page = state.data?.value;
  const bound = page && page.offset === offset && page.limit === 25 && page.items.every(x => x.scan_id === scope.scan.scan_id
    && x.collection_account_id === scope.scan.aws_account_id && (kind === 'source-outcomes' ? isOutcome(x)
      && (!applied.filter || x.state === applied.filter) && (!applied.resource || x.subject.stable_resource_id === applied.resource)
      : isRelationship(x) && (!applied.filter || x.resolution === applied.filter) && (!applied.resource || x.source.stable_resource_id === applied.resource)));
  function submit(e: FormEvent) {
    e.preventDefault(); const id = resource.trim().toLowerCase(); selectGraph(null);
    if (id && !isUUID(id)) { setError('A resource UUID is required for that filter.'); return; }
    setError(''); setOffset(0); setApplied({ filter, resource: id });
  }
  return <><form onSubmit={submit} aria-label="Graph filters"><label>{kind === 'source-outcomes' ? 'Source state' : 'Relationship resolution'}
    <select value={filter} onChange={e => setFilter(e.target.value)}><option value="">All states</option>
      {(kind === 'source-outcomes' ? sourceStates : resolutions).map(x => <option key={x}>{x}</option>)}</select></label>
    <label>{kind === 'source-outcomes' ? 'Source subject resource UUID' : 'Relationship source resource UUID'}<input value={resource} maxLength={64} onChange={e => setResource(e.target.value)} /></label>
    <button>Apply graph filters</button></form>{error ? <p role="alert">{error}</p> : null}
    {!error ? <ReadState error={state.error} ready={Boolean(page)} /> : null}
    {!state.error && page ? !bound ? <p role="alert">{mismatch}</p> : page.items.length === 0 ? <p>No {kind} on this filtered page. Absence of graph records is not proof of assessment success.</p>
      : <div className="table-scroll"><table><caption>Exact-scan {kind}</caption><thead><tr><th scope="col">Kind / direction</th><th scope="col">State</th><th scope="col">Detail</th></tr></thead>
        <tbody>{page.items.map(x => isOutcome(x) ? <tr key={x.source_outcome_id}><td>{x.evidence_kind}</td><td>{x.state}</td>
          <td><button onClick={() => selectGraph({ kind: 'source-outcomes', id: x.source_outcome_id, outcome: x })}>Open source {x.source_outcome_id}</button></td></tr>
          : <tr key={x.observation_id}><td>{x.source.aws_resource_id} → {x.target.aws_resource_id} ({x.relationship_type})</td><td>{x.resolution}</td>
            <td><button onClick={() => selectGraph({ kind: 'relationships', id: x.observation_id, relationship: x })}>Open relationship {x.observation_id}</button></td></tr>)}</tbody></table></div> : null}
    <Paging label={kind} offset={offset} total={page?.total ?? 0} ready={Boolean(bound)} change={v => { setOffset(v); selectGraph(null); }} />
  </>;
}
