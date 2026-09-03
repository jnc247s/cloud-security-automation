"""Transactional persistence operations for scan and finding lifecycle state."""

import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Resource, Scan, ScanStatus
from app.models.enums import RESOLVABLE_FINDING_STATUSES
from app.schemas.finding import FindingCandidate
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope

ResourceIdentity = tuple[str, str, str, str, str, str]


class ScanLifecycleError(RuntimeError):
    """Raised when a requested scan state transition is invalid."""


class PersistenceInvariantError(RuntimeError):
    """Raised when scan inputs cannot be persisted without ambiguity."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _identity_hash(identity: ResourceIdentity) -> str:
    payload = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def _candidate_resource_identity(candidate: FindingCandidate) -> ResourceIdentity:
    return candidate.identity[1:]


def _stored_resource_identity(resource: Resource) -> ResourceIdentity:
    return (
        resource.account_id,
        resource.service,
        resource.resource_type,
        resource.scope,
        resource.region or "global",
        resource.aws_resource_id,
    )


class ScanPersistenceService:
    """Persist scan state inside the caller's SQLAlchemy transaction."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def queue_scan(self, *, account_id: str, region: str) -> Scan:
        """Create a queued scan and assign its public UUID."""

        if not account_id.strip() or not region.strip():
            raise PersistenceInvariantError("scan account_id and region must not be empty")

        scan = Scan(account_id=account_id, region=region, status=ScanStatus.QUEUED)
        self.session.add(scan)
        self.session.flush()
        return scan

    def start_scan(self, scan_uuid: UUID, *, started_at: datetime | None = None) -> Scan:
        """Transition a queued scan to running."""

        scan = self._get_scan_for_update(scan_uuid)
        self._require_status(scan, ScanStatus.QUEUED)
        scan.status = ScanStatus.RUNNING
        scan.started_at = _as_utc(started_at or _utc_now())
        self.session.flush()
        return scan

    def fail_scan(self, scan_uuid: UUID, *, failed_at: datetime | None = None) -> Scan:
        """Mark an unfinished scan failed without changing resources or findings."""

        scan = self._get_scan_for_update(scan_uuid)
        if scan.status not in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
            raise ScanLifecycleError(
                f"scan {scan_uuid} cannot transition from {scan.status.value} to FAILED"
            )
        timestamp = _as_utc(failed_at or _utc_now())
        scan.started_at = scan.started_at or timestamp
        scan.completed_at = timestamp
        scan.status = ScanStatus.FAILED
        self.session.flush()
        return scan

    def complete_scan(
        self,
        scan_uuid: UUID,
        *,
        snapshot: InventorySnapshot,
        candidates: Sequence[FindingCandidate],
        evaluated_control_ids: Iterable[str],
        completed_at: datetime | None = None,
    ) -> Scan:
        """Atomically persist one successful snapshot and reconcile finding state."""

        scan = self._get_scan_for_update(scan_uuid)
        self._require_status(scan, ScanStatus.RUNNING)
        controls = tuple(sorted(set(evaluated_control_ids)))
        self._validate_completion(scan, snapshot, candidates, controls)

        observed_at = _as_utc(snapshot.collected_at)
        finished_at = _as_utc(completed_at or _utc_now())
        resources_by_identity = self._persist_snapshot_resources(snapshot, observed_at)
        scan.resources = list(resources_by_identity.values())

        self.session.flush()
        findings_created, findings_resolved = self._reconcile_findings(
            scan=scan,
            snapshot=snapshot,
            candidates=candidates,
            evaluated_control_ids=controls,
            resources_by_identity=resources_by_identity,
            observed_at=observed_at,
        )

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = finished_at
        scan.resources_evaluated = snapshot.resource_count
        scan.controls_evaluated = len(controls)
        scan.findings_created = findings_created
        scan.findings_resolved = findings_resolved
        self.session.flush()
        return scan

    def _get_scan_for_update(self, scan_uuid: UUID) -> Scan:
        scan = self.session.scalar(
            select(Scan).where(Scan.scan_uuid == scan_uuid).with_for_update()
        )
        if scan is None:
            raise ScanLifecycleError(f"scan {scan_uuid} does not exist")
        return scan

    @staticmethod
    def _require_status(scan: Scan, expected: ScanStatus) -> None:
        if scan.status is not expected:
            raise ScanLifecycleError(
                f"scan {scan.scan_uuid} must be {expected.value}, not {scan.status.value}"
            )

    @staticmethod
    def _validate_completion(
        scan: Scan,
        snapshot: InventorySnapshot,
        candidates: Sequence[FindingCandidate],
        controls: tuple[str, ...],
    ) -> None:
        if snapshot.account_id != scan.account_id:
            raise PersistenceInvariantError("snapshot account does not match the queued scan")
        if snapshot.requested_region != scan.region:
            raise PersistenceInvariantError("snapshot region does not match the queued scan")
        if any(not control_id.strip() for control_id in controls):
            raise PersistenceInvariantError("evaluated control IDs must not be empty")

        resource_identities: set[ResourceIdentity] = set()
        for resource in snapshot.resources:
            if resource.account_id != snapshot.account_id:
                raise PersistenceInvariantError("snapshot contains a resource from another account")
            if (
                resource.scope is ResourceScope.REGIONAL
                and resource.region != snapshot.requested_region
            ):
                raise PersistenceInvariantError("snapshot contains a resource from another region")
            if resource.identity in resource_identities:
                raise PersistenceInvariantError("snapshot contains a duplicate resource identity")
            resource_identities.add(resource.identity)

        candidate_identities: set[tuple[str, str, str, str, str, str, str]] = set()
        for candidate in candidates:
            if candidate.control_id not in controls:
                raise PersistenceInvariantError(
                    "finding candidate came from an unevaluated control"
                )
            if candidate.account_id != snapshot.account_id:
                raise PersistenceInvariantError("finding candidate targets another account")
            if (
                candidate.scope is ResourceScope.REGIONAL
                and candidate.region != snapshot.requested_region
            ):
                raise PersistenceInvariantError("finding candidate targets another region")
            if candidate.identity in candidate_identities:
                raise PersistenceInvariantError("scan contains duplicate finding candidates")
            candidate_identities.add(candidate.identity)

            resource_identity = _candidate_resource_identity(candidate)
            if resource_identity not in resource_identities and not (
                candidate.resource_type == "aws_account"
                and candidate.aws_resource_id == snapshot.account_id
                and candidate.scope is ResourceScope.GLOBAL
            ):
                raise PersistenceInvariantError(
                    "finding candidate does not target a resource in the snapshot"
                )

    def _persist_snapshot_resources(
        self,
        snapshot: InventorySnapshot,
        observed_at: datetime,
    ) -> dict[ResourceIdentity, Resource]:
        persisted: dict[ResourceIdentity, Resource] = {}
        for normalized in snapshot.resources:
            persisted[normalized.identity] = self._upsert_normalized_resource(
                normalized,
                observed_at,
            )
        return persisted

    def _upsert_normalized_resource(
        self,
        normalized: NormalizedResource,
        observed_at: datetime,
    ) -> Resource:
        document = normalized.model_dump(mode="json")
        return self._upsert_resource(
            identity=normalized.identity,
            arn=normalized.arn,
            name=normalized.name,
            tags=document["tags"],
            configuration=document["configuration"],
            raw_configuration=document["raw_configuration"],
            observed_at=observed_at,
        )

    def _upsert_candidate_resource(
        self,
        candidate: FindingCandidate,
        observed_at: datetime,
    ) -> Resource:
        return self._upsert_resource(
            identity=_candidate_resource_identity(candidate),
            arn=candidate.arn,
            name=candidate.name,
            tags={},
            configuration={},
            raw_configuration={},
            observed_at=observed_at,
        )

    def _upsert_resource(
        self,
        *,
        identity: ResourceIdentity,
        arn: str | None,
        name: str | None,
        tags: dict[str, str],
        configuration: dict[str, object],
        raw_configuration: dict[str, object],
        observed_at: datetime,
    ) -> Resource:
        identity_hash = _identity_hash(identity)
        resource = self.session.scalar(
            select(Resource).where(Resource.identity_hash == identity_hash).with_for_update()
        )
        if resource is None:
            account_id, service, resource_type, scope, region_key, aws_resource_id = identity
            resource = Resource(
                identity_hash=identity_hash,
                account_id=account_id,
                service=service,
                resource_type=resource_type,
                scope=scope,
                region=None if region_key == "global" else region_key,
                aws_resource_id=aws_resource_id,
                arn=arn,
                name=name,
                tags=tags,
                configuration=configuration,
                raw_configuration=raw_configuration,
                first_seen=observed_at,
                last_seen=observed_at,
            )
            self.session.add(resource)
            self.session.flush()
            return resource

        if _stored_resource_identity(resource) != identity:
            raise PersistenceInvariantError("resource identity hash collision detected")

        previous_last_seen = _as_utc(resource.last_seen)
        resource.first_seen = min(_as_utc(resource.first_seen), observed_at)
        resource.last_seen = max(previous_last_seen, observed_at)
        if observed_at >= previous_last_seen:
            resource.arn = arn
            resource.name = name
            resource.tags = tags
            resource.configuration = configuration
            resource.raw_configuration = raw_configuration
        return resource

    def _reconcile_findings(
        self,
        *,
        scan: Scan,
        snapshot: InventorySnapshot,
        candidates: Sequence[FindingCandidate],
        evaluated_control_ids: tuple[str, ...],
        resources_by_identity: dict[ResourceIdentity, Resource],
        observed_at: datetime,
    ) -> tuple[int, int]:
        existing_rows: list[tuple[Finding, Resource]] = []
        if evaluated_control_ids:
            existing_rows = list(
                self.session.execute(
                    select(Finding, Resource)
                    .join(Resource, Finding.resource_id == Resource.id)
                    .where(
                        Resource.account_id == snapshot.account_id,
                        Finding.control_id.in_(evaluated_control_ids),
                    )
                    .with_for_update()
                ).tuples()
            )

        existing_by_pair = {
            (finding.control_id, resource.id): finding for finding, resource in existing_rows
        }
        current_pairs: set[tuple[str, int]] = set()
        findings_created = 0

        for candidate in candidates:
            resource_identity = _candidate_resource_identity(candidate)
            resource = resources_by_identity.get(resource_identity)
            if resource is None:
                resource = self._upsert_candidate_resource(candidate, observed_at)

            pair = (candidate.control_id, resource.id)
            current_pairs.add(pair)
            finding = existing_by_pair.get(pair)
            evidence = candidate.model_dump(mode="json")["evidence"]
            if finding is None:
                finding = Finding(
                    control_id=candidate.control_id,
                    resource=resource,
                    scan=scan,
                    category=candidate.category,
                    severity=candidate.severity,
                    title=candidate.title,
                    evidence=evidence,
                    impact=candidate.impact,
                    recommendation=candidate.recommendation,
                    status=FindingStatus.OPEN,
                    first_detected=observed_at,
                    last_detected=observed_at,
                )
                self.session.add(finding)
                existing_by_pair[pair] = finding
                findings_created += 1
                continue

            previous_last_detected = _as_utc(finding.last_detected)
            latest_lifecycle_at = previous_last_detected
            if finding.resolved_at is not None:
                latest_lifecycle_at = max(latest_lifecycle_at, _as_utc(finding.resolved_at))
            if observed_at >= latest_lifecycle_at:
                finding.category = candidate.category
                finding.severity = candidate.severity
                finding.title = candidate.title
                finding.evidence = evidence
                finding.impact = candidate.impact
                finding.recommendation = candidate.recommendation
                finding.last_detected = observed_at
                if finding.status is FindingStatus.RESOLVED:
                    finding.status = FindingStatus.OPEN
                    finding.resolved_at = None

        findings_resolved = 0
        for finding, resource in existing_rows:
            pair = (finding.control_id, resource.id)
            in_scan_scope = resource.scope == ResourceScope.GLOBAL.value or (
                resource.scope == ResourceScope.REGIONAL.value
                and resource.region == snapshot.requested_region
            )
            if (
                in_scan_scope
                and pair not in current_pairs
                and finding.status in RESOLVABLE_FINDING_STATUSES
                and observed_at >= _as_utc(finding.last_detected)
            ):
                finding.status = FindingStatus.RESOLVED
                finding.resolved_at = observed_at
                findings_resolved += 1

        return findings_created, findings_resolved
