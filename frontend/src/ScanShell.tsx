import { useEffect, useRef, useState, type FormEvent } from 'react';
import { isDetail, isPage, isPosture, isUUID, read, type Posture, type ScanPage } from './api';
import { Investigation } from './Investigation';
import { isScope } from './investigation-api';

function selection() { return (new URLSearchParams(window.location.search).get('scan') ?? '').toLowerCase(); }
export function ScanShell({ onError, context }: { onError: (error: Error) => void; context: string }) {
  const [selected, setSelected] = useState(selection);
  const [input, setInput] = useState(selection);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [page, setPage] = useState<{ offset: number; value: ScanPage } | null>(null);
  const [report, setReport] = useState<{ id: string; value: Posture } | null>(null);
  const [listError, setListError] = useState('');
  const [reportError, setReportError] = useState('');
  const errors = useRef(onError);
  useEffect(() => { errors.current = onError; }, [onError]);
  useEffect(() => {
    function pop() { const id = selection(); setSelected(id); setInput(id); }
    window.addEventListener('popstate', pop);
    return () => window.removeEventListener('popstate', pop);
  }, []);
  useEffect(() => {
    const controller = new AbortController(); let active = true;
    setPage(null); setListError('');
    void read(`api/scans?limit=25&offset=${offset}`, isPage, controller.signal, context)
      .then(value => { if (active) setPage({ offset, value }); })
      .catch((error: Error) => { if (active) { setListError(error.message); errors.current(error); } });
    return () => { active = false; controller.abort(); };
  }, [offset, revision, context]);
  useEffect(() => {
    const controller = new AbortController(); let active = true;
    setReport(null); setReportError('');
    if (selected && isUUID(selected)) {
      void Promise.all([
        read(`api/scans/${selected}`, isDetail, controller.signal, context),
        read(`api/scans/${selected}/technical-posture`, isPosture, controller.signal, context)
      ]).then(([detail, value]) => {
        if (detail.scan_id !== selected || value.scan.scan_id !== selected)
          throw new Error('The report does not match the selected scan.');
        if (active) setReport({ id: selected, value });
      }).catch((error: Error) => { if (active) { setReportError(error.message); errors.current(error); } });
    }
    return () => { active = false; controller.abort(); };
  }, [selected, revision, context]);
  function select(id: string) {
    setSelected(id); setInput(id); setReport(null); setReportError('');
    const url = new URL(window.location.href);
    if (id) url.searchParams.set('scan', id); else url.searchParams.delete('scan');
    url.searchParams.delete('login');
    window.history.pushState(null, '', url);
  }
  function submit(event: FormEvent) { event.preventDefault(); select(input.trim().toLowerCase()); }
  const visiblePage = page?.offset === offset ? page.value : null;
  const visible = report?.id === selected ? report.value : null;

  return <div className="workspace">
    <section aria-labelledby="history"><h2 id="history">Scan history</h2>
      <p>Pages are bounded and may change while new scans arrive. Select one exact scan.</p>
      <button onClick={() => { setPage(null); setReport(null); setRevision(v => v + 1); }}>Refresh</button>
      {listError ? <p role="alert">{listError}</p> : !visiblePage ? <p role="status">Loading scan history…</p>
        : visiblePage.items.length === 0 ? <p>No scans on this page.</p> : <ul className="scans">
          {visiblePage.items.map(scan => <li key={scan.scan_id}>
            <button aria-pressed={selected === scan.scan_id} onClick={() => select(scan.scan_id)}>
              <span className="mono">{scan.scan_id}</span><span>{scan.status} · {scan.aws_account_id ?? 'Account not yet verified'}</span>
              <span>{scan.started_at}</span>
            </button></li>)}</ul>}
      <nav aria-label="Scan history pages"><button disabled={offset === 0}
        onClick={() => setOffset(v => Math.max(0, v - 25))}>Previous page</button>
        <button disabled={!visiblePage || offset + 25 >= visiblePage.total}
          onClick={() => setOffset(v => v + 25)}>Next page</button></nav>
      <form onSubmit={submit}><label htmlFor="scan-id">Open scan by UUID</label>
        <input id="scan-id" value={input} onChange={e => setInput(e.target.value)} maxLength={64} spellCheck={false} />
        <button type="submit">Open scan</button></form>
    </section>
    <section aria-labelledby="selected"><h2 id="selected">Selected scan</h2>
      {!selected ? <p>Select a scan to view its exact scope and report availability.</p>
        : !isUUID(selected) ? <p role="alert">A valid scan UUID is required.</p>
        : reportError ? <p role="alert">{reportError}</p>
        : !visible ? <p role="status">Loading selected scan…</p>
        : <><ScanContext report={visible} />{visible.availability === 'AVAILABLE'
          ? isScope(visible) ? <Investigation key={`${visible.scan.scan_id}:${context}`} scope={visible} context={context} onError={onError} />
            : <p role="alert">The investigation context is unsupported. No record has been substituted.</p>
          : <p>Investigation data is unavailable until a retained assessment bundle is available.</p>}</>}
    </section>
  </div>;
}

export function ScanContext({ report }: { report: Posture }) {
  const scan = report.scan;
  return <div><dl>
    <dt>Scan UUID</dt><dd className="mono">{scan.scan_id}</dd>
    <dt>Lifecycle</dt><dd>{scan.status}</dd>
    <dt>Collection account</dt><dd>{scan.aws_account_id ?? 'Not yet verified'}</dd>
    <dt>Requested Regions</dt><dd>{scan.requested_regions.join(', ') || 'None declared'}</dd>
    <dt>Successful Regions</dt><dd>{scan.successful_regions.join(', ') || 'None recorded'}</dd>
    <dt>Requested services</dt><dd>{scan.requested_services.join(', ') || 'None declared'}</dd>
    <dt>Successful collectors</dt><dd>{scan.successful_collectors.join(', ') || 'None recorded'}</dd>
    <dt>Catalog</dt><dd>{scan.control_catalog_id} / {scan.control_catalog_version}</dd>
    <dt>Profile</dt><dd>{scan.assessment_profile_id} / {scan.assessment_profile_version}</dd>
    <dt>Profile checksum</dt><dd className="mono">{scan.assessment_profile_checksum}</dd>
    <dt>Scanner version</dt><dd>{scan.scanner_version}</dd>
    <dt>Started</dt><dd>{scan.started_at}</dd><dt>Completed</dt><dd>{scan.completed_at ?? 'Not complete'}</dd>
    <dt>Report availability</dt><dd>{report.availability}</dd>
  </dl>
    {report.availability === 'AVAILABLE' ? <p>Retained technical results are available for this exact scan. Investigation is read-only; NIST hierarchy views are not part of 7C.</p>
      : report.availability === 'IN_PROGRESS' ? <p>The scan is unfinished. Assessment counts are unavailable, not zero.</p>
      : <p>No retained result bundle is available. This is not a passing assessment.</p>}
    {scan.status === 'PARTIAL' || scan.status === 'FAILED' ? <p className="notice">Collection has gaps or failures. Available retained results do not establish complete coverage.</p> : null}
    {scan.failure ? <p role="note">{scan.failure.code}: {scan.failure.message}</p> : null}
    {scan.scope ? <><h3>Recorded collection scope</h3><p>Enabled controls: {scan.scope.enabled_controls.join(', ') || 'None'}</p>
      <ul>{Object.entries(scan.scope.collector_outcomes).map(([name, outcome]) => <li key={name}>{name}: {outcome}</li>)}</ul></>
      : <p>Collection scope has not been retained yet.</p>}
  </div>;
}
