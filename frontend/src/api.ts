// Narrow runtime-validated views of app.schemas.scan and app.schemas.technical_posture.
// Authentication is enforced server-side; these checks only prevent misleading rendering.
export type Status = 'RUNNING' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
export interface Scan {
  scan_id: string; status: Status; aws_account_id: string | null;
  requested_regions: string[]; successful_regions: string[];
  requested_services: string[]; successful_collectors: string[];
  started_at: string; completed_at: string | null;
  failure: { code: string; message: string } | null;
}
export interface Detail extends Scan {
  scanner_version: string; control_catalog_id: string; control_catalog_version: string;
  assessment_profile_id: string; assessment_profile_version: string;
  assessment_profile_checksum: string; inventory_sha256: string | null;
  result_checksum: string | null;
  scope: null | { requested_collectors: string[]; collector_outcomes: Record<string, string>;
    resource_types: string[]; enabled_controls: string[] };
}
export interface ScanPage { items: Scan[]; total: number; limit: number; offset: number }
export interface Posture { scan: Detail; availability: 'AVAILABLE' | 'IN_PROGRESS' | 'UNAVAILABLE';
  schema_version: '1.0.0'; interpretation: 'TECHNICAL_CONTEXT_ONLY' }
export type Session = { authenticated: false; csrf_token: string } | {
  authenticated: true; subject: string; roles: string[]; csrf_token: string;
  session_context: string; expires_at: number; idle_expires_at: number };
export const isUUID = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === 'string');
const nullableString = (v: unknown) => v === null || typeof v === 'string';
const integer = (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

export function isScan(v: unknown): v is Scan {
  return object(v) && typeof v.scan_id === 'string' && isUUID(v.scan_id)
    && typeof v.status === 'string' && ['RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED'].includes(v.status)
    && nullableString(v.aws_account_id) && strings(v.requested_regions)
    && strings(v.successful_regions) && strings(v.requested_services)
    && strings(v.successful_collectors) && typeof v.started_at === 'string'
    && nullableString(v.completed_at) && (v.failure === null || (object(v.failure)
      && typeof v.failure.code === 'string' && typeof v.failure.message === 'string'));
}
export function isDetail(v: unknown): v is Detail {
  if (!isScan(v)) return false;
  const value = v as unknown as Record<string, unknown>;
  return ['scanner_version', 'control_catalog_id', 'control_catalog_version',
    'assessment_profile_id', 'assessment_profile_version', 'assessment_profile_checksum']
    .every(k => typeof value[k] === 'string') && nullableString(value.inventory_sha256)
    && nullableString(value.result_checksum) && (value.scope === null || (object(value.scope)
      && strings(value.scope.requested_collectors) && strings(value.scope.resource_types)
      && strings(value.scope.enabled_controls) && object(value.scope.collector_outcomes)
      && Object.values(value.scope.collector_outcomes).every(x => typeof x === 'string')));
}
export function isPage(v: unknown): v is ScanPage {
  return object(v) && Array.isArray(v.items) && v.items.every(isScan) && v.items.length <= 100
    && integer(v.total) && integer(v.offset) && integer(v.limit)
    && Number(v.limit) >= 1 && Number(v.limit) <= 100;
}
export function isPosture(v: unknown): v is Posture {
  return object(v) && isDetail(v.scan) && v.schema_version === '1.0.0'
    && v.interpretation === 'TECHNICAL_CONTEXT_ONLY'
    && typeof v.availability === 'string' && ['AVAILABLE', 'IN_PROGRESS', 'UNAVAILABLE'].includes(v.availability)
    && (v.availability === 'AVAILABLE' ? object(v.assessment_counts)
      && ['pass_count', 'fail_count', 'insufficient_evidence_count', 'not_applicable_count']
        .every(key => integer((v.assessment_counts as Record<string, unknown>)[key]))
      : v.assessment_counts === null);
}
export function isSession(v: unknown): v is Session {
  return object(v) && typeof v.csrf_token === 'string' && v.csrf_token.length > 0
    && (v.authenticated === false || (v.authenticated === true && typeof v.subject === 'string'
      && typeof v.session_context === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v.session_context)
      && strings(v.roles) && v.roles.length > 0
      && v.roles.every(role => ['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN'].includes(role))
      && typeof v.expires_at === 'number' && Number.isFinite(v.expires_at)
      && typeof v.idle_expires_at === 'number' && Number.isFinite(v.idle_expires_at)));
}
export class APIError extends Error {
  constructor(public status: number) { super(status === 401 ? 'Sign-in expired. Please sign in again.'
    : status === 404 ? 'This scan is unavailable or no longer exists.'
    : status === 409 ? 'Retained report provenance conflicts. The report cannot be displayed.'
    : 'The request could not be completed. Please retry.'); }
}
export async function read<T>(path: string, valid: (v: unknown) => v is T, signal?: AbortSignal, context?: string): Promise<T> {
  const response = await fetch(`/dashboard/${path}`, { signal, credentials: 'same-origin', cache: 'no-store',
    headers: context ? { 'X-Dashboard-Context': context } : {} });
  if (!response.ok) throw new APIError(response.status);
  const value: unknown = await response.json();
  if (!valid(value)) throw new Error('The server returned an unsupported response. Nothing has been assumed.');
  return value;
}
export async function action(path: 'login' | 'logout', csrf: string): Promise<Response> {
  const response = await fetch(`/dashboard/auth/${path}`, { method: 'POST', credentials: 'same-origin',
    cache: 'no-store', headers: { 'X-CSRF-Token': csrf } });
  if (!response.ok) throw new APIError(response.status);
  return response;
}
