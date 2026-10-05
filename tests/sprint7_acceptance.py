"""Whole-dashboard retained-data acceptance through real signed bearer/READ boundaries."""

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

from app.dashboard.routes import SESSION_COOKIE
from app.models import ControlAssessment, Finding
from app.models.enums import ExceptionStatus, FindingStatus
from app.models.exception import FindingException
from tests.dashboard_fixtures import dashboard_client, sign_in
from tests.sprint6_fixtures import CATALOG_CHECKSUMS, sprint6_bundle
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_technical_posture_service import persist

FULL_COUNTS = {
    "pass_count": 21,
    "fail_count": 17,
    "insufficient_evidence_count": 0,
    "not_applicable_count": 1,
}


def mapping_rows(rows):
    """Compare all provenance fields; SQLite's accepted API dates may omit the UTC offset."""
    result = {}
    for row in rows:
        verified = datetime.fromisoformat(row["verified_at"])
        if verified.tzinfo is None:
            verified = verified.replace(tzinfo=UTC)
        result[row["mapping_id"]] = {**row, "verified_at": verified.astimezone(UTC)}
    assert len(result) == len(rows)
    return result


def exercise_dashboard_story(engine, monkeypatch, tmp_path, role):
    """Seed only test data, then verify reports, evidence and live handling never write."""
    bundle = sprint6_bundle()
    with Session(engine) as db:
        full = persist(db, bundle)
        old = persist(db, scan_bundle(tags={"observed": "7e-historical-fail"}))
        persist(db, scan_bundle(public_ssh=False, tags={"observed": "7e-newer-pass"}))
        assessment = db.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == old)
        ).one()
        finding = db.get(Finding, assessment.finding_occurrence.finding_id)
        finding.status = FindingStatus.ACCEPTED_RISK
        finding.resolved_at = None
        now = datetime.now(UTC)
        db.add(
            FindingException(
                finding_id=finding.finding_id,
                resource_id=finding.resource_id,
                control_id=finding.control_id,
                reason="7E fixture: stored ACTIVE but already expired",
                approved_by="offline-test-approver",
                status=ExceptionStatus.ACTIVE,
                created_at=now - timedelta(days=3),
                expires_at=now - timedelta(days=1),
            )
        )
        db.commit()

    statements = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    with dashboard_client(engine, monkeypatch, tmp_path) as (client, issuer, boundary, executor):
        issuer.role = role
        session = sign_in(client, issuer)
        assert session["roles"] == [role]
        assert set(session).isdisjoint({"access_token", "id_token", "refresh_token"})
        token = boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False).access_token

        def read(path):
            response = client.get(f"/dashboard/api/{path}")
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            direct = client.get(f"/api/v1/{path}", headers={"Authorization": f"Bearer {token}"})
            assert direct.status_code == 200
            assert response.json() == direct.json()
            return response

        event.listen(engine, "before_cursor_execute", capture)
        try:
            report = read(f"scans/{full}/technical-posture").json()
            assert report["scan"]["scan_id"] == str(full)
            assert report["assessment_counts"] == FULL_COUNTS
            assert report["catalog"]["version"] == "0.13.0"
            assert report["catalog"]["content_checksum"] == CATALOG_CHECKSUMS["0.13.0"]
            assert (
                report["scan"]["assessment_profile_checksum"] == bundle["profile"].content_checksum
            )
            assert len(report["controls"]) == 26
            assert report["control_coverage"] == {
                "registered_count": 26,
                "enabled_count": 26,
                "disabled_count": 0,
                "assessed_count": 26,
                "unassessed_count": 0,
            }
            assert report["interpretation"] == "TECHNICAL_CONTEXT_ONLY"
            assert {"score", "compliance_percentage", "overall_result"}.isdisjoint(report)
            pages = [
                read(f"assessments?scan_id={full}&limit=25&offset={offset}").json()
                for offset in (0, 25)
            ]
            assert all(page["total"] == 39 and page["limit"] == 25 for page in pages)
            rows = [row for page in pages for row in page["items"]]
            assert len({row["assessment_id"] for row in rows}) == 39
            assert Counter(row["assessment_result"] for row in rows) == {
                "PASS": 21,
                "FAIL": 17,
                "NOT_APPLICABLE": 1,
            }
            control = next(c for c in report["controls"] if c["control_key"] == "EC2-001")
            row = next(a for a in rows if a["control_version_id"] == control["control_version_id"])
            detail = read(f"assessments/{row['assessment_id']}").json()
            assert detail["scan_id"] == str(full)
            assert mapping_rows(detail["framework_mappings"]) == mapping_rows(
                control["framework_mappings"]
            )
            definition = read(f"controls/{control['control_id']}").json()
            version = next(
                v
                for v in definition["versions"]
                if v["control_version_id"] == detail["control_version_id"]
            )
            assert version["definition_checksum"] == control["definition_checksum"]
            snapshot = read(
                f"resources/{row['resource_id']}/history?scan_id={full}&limit=25"
            ).json()
            assert snapshot["total"] == 1
            assert snapshot["items"][0]["snapshot_id"] == detail["resource_snapshot_id"]
            evidence = next(e for e in detail["evidence"] if e["payload"].get("source_proof"))
            encoded = json.dumps(
                evidence["payload"], ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            assert sha256(encoded).hexdigest() == evidence["payload_sha256"]
            citation = evidence["payload"]["source_proof"]["sources"][0]
            source = read(f"source-outcomes/{citation['source_outcome_id']}").json()
            assert source["scan_id"] == str(full)
            assert source["artifact"]["artifact_id"] == citation["artifact_id"]
            assert source["artifact"]["evidence_sha256"] == citation["evidence_sha256"]
            edge = read(f"relationships?scan_id={full}&resolution=RESOLVED&limit=25").json()[
                "items"
            ][0]
            edge_detail = read(f"relationships/{edge['observation_id']}").json()
            assert edge_detail == edge
            for side in ("source", "target"):
                endpoint = edge[side]
                history = read(
                    f"resources/{endpoint['stable_resource_id']}/history?scan_id={full}&limit=25"
                ).json()
                assert history["total"] == 1
                assert history["items"][0]["snapshot_id"] == endpoint["resource_snapshot_id"]

            historical = read(f"scans/{old}/technical-posture").json()
            assert historical["assessment_counts"] == {
                **FULL_COUNTS,
                "pass_count": 0,
                "fail_count": 1,
                "not_applicable_count": 0,
            }
            row = read(f"assessments?scan_id={old}&limit=25").json()["items"][0]
            detail = read(f"assessments/{row['assessment_id']}").json()
            history = read(f"resources/{row['resource_id']}/history?scan_id={old}&limit=25").json()
            assert history["items"][0]["tags"] == {"observed": "7e-historical-fail"}
            assert history["items"][0]["snapshot_id"] == detail["resource_snapshot_id"]
            current = read(f"findings?resource_id={row['resource_id']}&limit=25")
            assert current.json()["items"][0]["status"] == "ACCEPTED_RISK"
            exceptions = read(f"exceptions?finding_id={detail['finding_id']}&limit=25")
            stored = exceptions.json()["items"][0]
            reference = datetime.fromisoformat(exceptions.headers["x-dashboard-read-at"])
            assert reference.tzinfo == UTC
            assert stored["status"] == "ACTIVE"
            expires = datetime.fromisoformat(stored["expires_at"])
            if engine.dialect.name == "sqlite":
                expires = expires.replace(tzinfo=UTC)
            else:
                assert expires.tzinfo == UTC
            assert expires < reference
            assert read(f"assessments/{row['assessment_id']}").json() == detail
            assert read(f"scans/{old}/technical-posture").json() == historical
            assert client.get(f"/api/v1/assessments/{row['assessment_id']}").status_code == 401
            assert client.post("/dashboard/api/scans", json={}).status_code == 405
            assert executor.submissions == []
        finally:
            event.remove(engine, "before_cursor_execute", capture)
        assert statements and all(s.lstrip().upper().startswith("SELECT") for s in statements)
        with Session(engine) as db:
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(ControlAssessment)
                    .where(ControlAssessment.scan_id == full)
                )
                == 39
            )
            assert (
                db.get(ControlAssessment, UUID(row["assessment_id"])).assessment_result.value
                == "FAIL"
            )
