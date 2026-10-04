import type { ReactNode } from 'react';

export function Payload({ value, label }: { value: unknown; label: string }) {
  let truncated = false, nodes = 0;
  function bounded(v: unknown, depth = 0): unknown {
    if (++nodes > 2000 || depth > 8) { truncated = true; return '[display truncated]'; }
    if (typeof v === 'string' && v.length > 4096) { truncated = true; return v.slice(0, 4096) + '…'; }
    if (Array.isArray(v)) {
      if (v.length > 100) truncated = true;
      return v.slice(0, 100).map(x => bounded(x, depth + 1));
    }
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = Object.create(null); let count = 0;
      for (const key in v) if (Object.hasOwn(v, key)) {
        if (++count > 100) { truncated = true; break; }
        const shownKey = key.slice(0, 4096);
        if (shownKey !== key) truncated = true;
        out[shownKey] = bounded((v as Record<string, unknown>)[key], depth + 1);
      }
      return out;
    }
    return v;
  }
  const all = JSON.stringify(bounded(value), null, 2) ?? 'null';
  if (all.length > 12000) truncated = true;
  return <details><summary>{label}</summary>
    {truncated ? <p role="note">Display truncated; this is not full evidence review. Exact IDs and digests remain in the metadata.</p> : null}
    <pre>{all.slice(0, 12000)}{all.length > 12000 ? '\n…' : ''}</pre></details>;
}
export function Metadata({ rows }: { rows: [string, ReactNode][] }) {
  return <dl>{rows.map(([label, value]) => <div className="metadata-row" key={label}><dt>{label}</dt><dd>{value ?? 'Not recorded'}</dd></div>)}</dl>;
}
export function Paging({ label, offset, total, ready, change }: { label: string; offset: number;
  total: number; ready: boolean; change: (offset: number) => void }) {
  return <nav aria-label={`${label} pages`}><button disabled={offset === 0} onClick={() => change(Math.max(0, offset - 25))}>Previous {label} page</button>
    <button disabled={!ready || offset + 25 >= total} onClick={() => change(offset + 25)}>Next {label} page</button>
    <span>Offset {offset}; retrieved total {ready ? total : 'unavailable'}.</span></nav>;
}
export function ReadState({ error, ready }: { error: string; ready: boolean }) {
  return error ? <p role="alert">{error}</p> : !ready ? <p role="status">Loading investigation data…</p> : null;
}
export const mismatch = 'The returned record does not match this exact selection. Nothing has been substituted.';
