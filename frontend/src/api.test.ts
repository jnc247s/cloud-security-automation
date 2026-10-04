import { describe, expect, it } from 'vitest';
import { isPage, isPosture, isScan, isSession, isUUID } from './api';

const scan = { scan_id: '11111111-1111-1111-1111-111111111111', status: 'COMPLETED',
  aws_account_id: null, requested_regions: [], successful_regions: [], requested_services: [],
  successful_collectors: [], started_at: '2026-10-04T00:00:00Z', completed_at: null,
  failure: null, scanner_version: 'test', control_catalog_id: 'test', control_catalog_version: '1.0.0',
  assessment_profile_id: 'test', assessment_profile_version: '1.0.0', assessment_profile_checksum: 'test',
  inventory_sha256: null, result_checksum: null, scope: null };
const counts = { pass_count: 0, fail_count: 0, insufficient_evidence_count: 0, not_applicable_count: 0 };
const report = { scan, schema_version: '1.0.0', interpretation: 'TECHNICAL_CONTEXT_ONLY',
  availability: 'AVAILABLE', assessment_counts: counts };

describe('bounded, fail-closed client projections', () => {
  it('does not coerce missing or malformed responses', () => {
    for (const value of [null, {}, [], 'PASS', { items: [], total: -1 }, { availability: 'AVAILABLE' }]) {
      expect(isPage(value)).toBe(false); expect(isPosture(value)).toBe(false);
    }
    expect(isPage({ items: [], total: 0, limit: 25, offset: 0 })).toBe(true);
    expect(isPage({ items: [], total: 0, limit: 101, offset: 0 })).toBe(false);
  });
  it('requires explicit authentication and recognized roles', () => {
    expect(isSession({ authenticated: false, csrf_token: 'opaque' })).toBe(true);
    expect(isSession({ authenticated: 'false', csrf_token: 'opaque' })).toBe(false);
    expect(isSession({ authenticated: true, csrf_token: 'opaque', subject: 'reader', roles: ['EXECUTE'], expires_at: 100, idle_expires_at: 50 })).toBe(false);
  });
  it('rejects URL injection and requires an exact UUID', () => {
    expect(isUUID('11111111-1111-1111-1111-111111111111')).toBe(true);
    for (const value of ['../scans', 'https://attacker.test', '', 'latest']) expect(isUUID(value)).toBe(false);
  });
  it('requires exact lifecycle and availability strings, not coerced arrays', () => {
    expect(isScan(scan)).toBe(true);
    for (const status of [['COMPLETED'], null, 0, {}]) expect(isScan({ ...scan, status })).toBe(false);
    for (const availability of [['AVAILABLE'], null, 0, {}])
      expect(isPosture({ ...report, availability })).toBe(false);
  });
  it('requires all four finite nonnegative integer counts, preserving real zeros and null availability', () => {
    expect(isPosture(report)).toBe(true);
    expect(isPosture({ ...report, availability: 'UNAVAILABLE', assessment_counts: null })).toBe(true);
    expect(isPosture({ ...report, availability: 'IN_PROGRESS', assessment_counts: null })).toBe(true);
    for (const assessment_counts of [{}, null, [], ...Object.keys(counts).flatMap(key =>
      [undefined, -1, '0', null, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]
        .map(value => ({ ...counts, [key]: value })))])
      expect(isPosture({ ...report, assessment_counts })).toBe(false);
    expect(isPosture({ ...report, availability: 'UNAVAILABLE' })).toBe(false);
  });
  it('requires authenticated session correlation without treating it as a credential', () => {
    const session = { authenticated: true, csrf_token: 'opaque', subject: 'reader', roles: ['VIEWER'],
      expires_at: 100, idle_expires_at: 50, session_context: 'A'.repeat(43) };
    expect(isSession(session)).toBe(true);
    for (const session_context of [null, undefined, '', '../api', 'A'.repeat(100)])
      expect(isSession({ ...session, session_context })).toBe(false);
  });
});
