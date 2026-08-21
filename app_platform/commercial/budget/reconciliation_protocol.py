"""Durable drift evidence and staged repair for commercial Redis budgets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .reconciliation_authority import (
    BudgetCostAuthorityAudit,
    audit_budget_cost_authority,
)
from .rebuild_protocol import (
    BudgetRebuildCommand,
    BudgetRebuildProtocol,
    BudgetRebuildProtocolError,
)
from .rebuild_store import CommercialBudgetRebuildRedisStore
from .reconciliation_store import (
    BudgetRedisManifestObservation,
    CommercialBudgetReconciliationRedisUnstable,
    CommercialBudgetReconciliationRedisStore,
)
from .redis_store import MAX_SAFE_REDIS_INTEGER, CommercialReservationRedisError


SafePositiveInt = Annotated[StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)]
_POLICY_BUCKETS = ("model", "technical")
_GENERATION_ONE_DIGEST = "sha256:" + "0" * 64
_REDIS_REPAIR_GRACE = timedelta(days=1)


class BudgetReconciliationProtocolError(RuntimeError):
    """Budget reconciliation could not produce trustworthy durable evidence."""


class BudgetReconciliationFinding(StrictCommercialModel):
    code: StableCode
    severity: Literal["warning", "error", "critical"]
    owner: StableCode
    path: Annotated[StrictStr, Field(min_length=1, max_length=512)]
    expected: str | int | bool | None
    observed: str | int | bool | None
    suggested_repair: StableCode


class BudgetReconciliationCommand(StrictCommercialModel):
    budget_period_id: SafePositiveInt
    idempotency_key: StableCode
    mode: Literal["dry_run", "repair"] = "dry_run"
    actor_id: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    repair_authorization_evidence_id: UUID | None = None

    @model_validator(mode="after")
    def _repair_authority(self):
        if (self.mode == "repair") is not (
            self.repair_authorization_evidence_id is not None
        ):
            raise ValueError("repair mode requires one dry-run evidence authority")
        return self


class BudgetReconciliationResult(StrictCommercialModel):
    evidence_id: UUID
    budget_period_id: SafePositiveInt
    agreement_terms_id: SafePositiveInt
    idempotency_key: StableCode
    mode: Literal["dry_run", "repair"]
    status: Literal["green", "drift", "repaired", "blocked"]
    expected_generation: SafePositiveInt
    observed_generation: SafePositiveInt | None
    expected_snapshot_sha256: Sha256Digest
    observed_snapshot_sha256: Sha256Digest
    pre_repair_findings: tuple[BudgetReconciliationFinding, ...]
    post_repair_expected_generation: SafePositiveInt | None
    post_repair_observed_generation: SafePositiveInt | None
    post_repair_expected_snapshot_sha256: Sha256Digest | None
    post_repair_observed_snapshot_sha256: Sha256Digest | None
    post_repair_findings: tuple[BudgetReconciliationFinding, ...]
    rebuild_event_id: UUID | None
    repair_authorization_evidence_id: UUID | None
    actor_id: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    occurred_at: AwareDatetime
    durable_replayed: StrictBool


@dataclass(frozen=True)
class _Snapshot:
    agreement_terms_id: int
    expected_generation: int
    expected_sha256: str
    observation: BudgetRedisManifestObservation
    findings: tuple[BudgetReconciliationFinding, ...]
    repairable: bool
    authority: dict[str, Any]
    cost_audit: BudgetCostAuthorityAudit
    source_watermark: dict[str, Any]


class BudgetReconciliationProtocol:
    def __init__(
        self,
        connection: Any,
        redis_store: CommercialBudgetReconciliationRedisStore,
        rebuild_store: CommercialBudgetRebuildRedisStore,
        *,
        flags: CommercialFlags,
        clock,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetReconciliationProtocolError(
                "budget reconciliation requires transactional PostgreSQL"
            )
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
            and flags.commercial_budget_reconciliation_enabled
        ):
            raise BudgetReconciliationProtocolError(
                "budget reconciliation requires enforcement mode"
            )
        self._connection = connection
        self._redis = redis_store
        self._rebuild = BudgetRebuildProtocol(
            connection,
            rebuild_store,
            flags=flags,
            clock=clock,
        )
        self._clock = clock
        self._auto_repair_enabled = (
            flags.commercial_budget_reconciliation_auto_repair_enabled
        )

    def reconcile(
        self, command: BudgetReconciliationCommand
    ) -> BudgetReconciliationResult:
        try:
            raw = (
                command.model_dump()
                if isinstance(command, StrictCommercialModel)
                else command
            )
            command = BudgetReconciliationCommand.model_validate(raw)
        except Exception as error:
            raise BudgetReconciliationProtocolError(
                "budget reconciliation command is invalid"
            ) from error
        self._require_idle()
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.budget.reconciliation-command.v1",
                "command": command.model_dump(mode="python"),
            }
        )
        now = self._now()
        try:
            existing = self._lock_evidence(command, command_sha256)
            if existing is not None:
                self._connection.commit()
                return existing
            if command.mode == "repair":
                if not self._auto_repair_enabled:
                    raise BudgetReconciliationProtocolError(
                        "budget reconciliation auto-repair is disabled"
                    )
                self._lock_repair_authorization(command)
            pre = self._snapshot(command, now=now)
            if not pre.findings:
                return self._record(
                    command,
                    command_sha256=command_sha256,
                    status="green",
                    pre=pre,
                    now=now,
                )
            if command.mode == "dry_run" or not pre.repairable:
                return self._record(
                    command,
                    command_sha256=command_sha256,
                    status="drift" if pre.repairable else "blocked",
                    pre=pre,
                    now=now,
                )
            # Keep the accepted-usage, adjustment, period, and reservation locks
            # through CAS cutover so new durable cost cannot race the repair.
            repair_key = self._repair_key(command_sha256)
            rebuild_result = None
            repair_command = BudgetRebuildCommand(
                budget_period_id=command.budget_period_id,
                idempotency_key=repair_key,
                reason_code="budget.reconciliation_repair",
            )
            try:
                rebuild_result = self._rebuild._rebuild_from_locked_authority(
                    repair_command,
                    pre.authority,
                    now=now,
                    commit=False,
                )
            except (BudgetRebuildProtocolError, CommercialReservationRedisError):
                self._connection.rollback()
                self._require_idle()
                existing = self._lock_evidence(command, command_sha256)
                if existing is not None:
                    self._connection.commit()
                    return existing
                # The failed rebuild transaction released every row lock. Reclaim
                # the predecessor before consuming it with terminal blocked
                # evidence so another repair cannot race this failure record.
                self._lock_repair_authorization(command)
                failed = pre.findings + (
                    self._finding(
                        code="budget.repair_failed",
                        path="repair",
                        expected="generation_rebuild",
                        observed="failed",
                        severity="critical",
                        suggested="budget.repair_retry",
                    ),
                )
                pre = _Snapshot(
                    agreement_terms_id=pre.agreement_terms_id,
                    expected_generation=pre.expected_generation,
                    expected_sha256=pre.expected_sha256,
                    observation=pre.observation,
                    findings=failed,
                    repairable=False,
                    authority=pre.authority,
                    cost_audit=pre.cost_audit,
                    source_watermark=pre.source_watermark,
                )
                return self._record(
                    command,
                    command_sha256=command_sha256,
                    status="blocked",
                    pre=pre,
                    now=now,
                    metadata={"repair_failure": "budget.rebuild_failed"},
                )

            # The rebuild event, period/reservation generation updates, repair
            # predecessor lock, and final reconciliation evidence remain in one
            # PostgreSQL transaction. A crash after Redis CAS rolls all durable
            # writes back, leaving the same predecessor safe to retry.
            post = self._snapshot(command, now=self._now())
            rebuild_event_id = uuid5(
                NAMESPACE_URL,
                f"budget-rebuild:{command.budget_period_id}:{repair_key}",
            )
            status = "repaired" if not post.findings else "blocked"
            return self._record(
                command,
                command_sha256=command_sha256,
                status=status,
                pre=pre,
                post=post,
                rebuild_event_id=rebuild_event_id,
                now=now,
                metadata={
                    "repair_idempotency_key": repair_key,
                    "repair_target_generation": rebuild_result.target_generation,
                    "repair_snapshot_sha256": rebuild_result.snapshot_sha256,
                },
            )
        except CommercialReservationRedisError as error:
            self._connection.rollback()
            raise BudgetReconciliationProtocolError(
                "budget reconciliation Redis operation is unavailable"
            ) from error
        except Exception:
            self._connection.rollback()
            raise

    def _snapshot(self, command, *, now: datetime) -> _Snapshot:
        authority_command = BudgetRebuildCommand(
            budget_period_id=command.budget_period_id,
            idempotency_key=command.idempotency_key,
        )
        authority = self._rebuild._lock_authority(
            authority_command,
            now=now,
            allow_blockers=True,
            check_replay=False,
        )
        source_watermark = self._source_watermark(command.budget_period_id)
        expected_generation = authority["expected_generation"]
        reservation_ids = tuple(UUID(str(row[0])) for row in authority["reservations"])
        blockers: list[BudgetReconciliationFinding] = []
        if authority["has_unresolved_settlement_attempt"]:
            blockers.append(
                self._finding(
                    code="budget.durable_settlement_attempt_unresolved",
                    path="durable.settlement_attempts",
                    expected="resolved",
                    observed="unresolved",
                    severity="critical",
                    suggested="budget.settlement_attempt_resolve",
                )
            )
        for reservation_id in authority["pending_reservation_ids"]:
            blockers.append(
                self._finding(
                    code="budget.durable_reservation_pending",
                    path=f"durable.reservations.{reservation_id}.state",
                    expected="terminal_or_active",
                    observed="pending",
                    severity="critical",
                    suggested="budget.reservation_recover",
                )
            )

        cost_audit = audit_budget_cost_authority(
            self._connection,
            budget_period_id=command.budget_period_id,
            agreement_terms_id=authority["agreement_terms_id"],
        )
        for anomaly in cost_audit.anomalies:
            blockers.append(
                self._finding(
                    code=anomaly.code,
                    path=anomaly.path,
                    expected=anomaly.expected,
                    observed=anomaly.observed,
                    severity="critical",
                    suggested="budget.settlement_recover",
                )
            )

        expected = self._authority_only_snapshot(authority, cost_audit)
        build = None
        if not blockers:
            try:
                provenance = self._generation_provenance(
                    command.budget_period_id,
                    expected_generation,
                )
                if provenance is None:
                    blockers.append(
                        self._finding(
                            code="budget.generation_provenance_missing",
                            path="durable.generation_provenance",
                            expected=expected_generation,
                            observed=None,
                            severity="critical",
                            suggested="budget.authority_investigate",
                        )
                    )
                else:
                    build = self._rebuild._build_command(
                        authority_command,
                        authority,
                        expected_generation=expected_generation,
                        target_generation=expected_generation + 1,
                        now=now,
                    )
                    expected = self._expected_manifest(
                        authority,
                        build,
                        provenance=provenance,
                        cost_audit=cost_audit,
                        now=now,
                    )
            except (BudgetRebuildProtocolError, ValueError):
                blockers.append(
                    self._finding(
                        code="budget.authority_invalid",
                        path="durable.budget_authority",
                        expected="rebuildable",
                        observed="invalid",
                        severity="critical",
                        suggested="budget.authority_investigate",
                    )
                )

        try:
            observation = self._redis.observe(
                agreement_terms_id=authority["agreement_terms_id"],
                period_id=command.budget_period_id,
                expected_generation=expected_generation,
                reservation_ids=reservation_ids,
            )
        except CommercialBudgetReconciliationRedisUnstable:
            observation = self._unavailable_observation(
                authority["agreement_terms_id"],
                command.budget_period_id,
                expected_generation,
            )
            blockers.append(
                self._finding(
                    code="budget.redis_snapshot_unstable",
                    path="redis.manifest",
                    expected="stable_generation",
                    observed="pointer_churn",
                    severity="critical",
                    suggested="budget.redis_investigate",
                )
            )
        except CommercialReservationRedisError:
            observation = self._unavailable_observation(
                authority["agreement_terms_id"],
                command.budget_period_id,
                expected_generation,
            )
            blockers.append(
                self._finding(
                    code="budget.redis_unavailable",
                    path="redis.manifest",
                    expected="available",
                    observed="unavailable",
                    severity="critical",
                    suggested="budget.redis_restore",
                )
            )
        findings = list(blockers)
        if not blockers:
            findings.extend(self._compare(expected, observation))
        return _Snapshot(
            agreement_terms_id=authority["agreement_terms_id"],
            expected_generation=expected_generation,
            expected_sha256=canonical_sha256(expected),
            observation=observation,
            findings=tuple(findings),
            repairable=not blockers,
            authority=authority,
            cost_audit=cost_audit,
            source_watermark=source_watermark,
        )

    def _expected_manifest(
        self, authority, build, *, provenance, cost_audit, now
    ):
        holds = {
            (str(reservation_id), bucket): int(amount)
            for reservation_id, bucket, amount in authority["holds"]
        }
        rows = {str(row[0]): row for row in authority["reservations"]}
        reservations = {}
        for rebuilt in build.reservations:
            row = rows[str(rebuilt.reservation_id)]
            active = bool(rebuilt.active)
            if not active and row[5] + _REDIS_REPAIR_GRACE < now:
                continue
            initial_buckets = tuple(row[7])
            reservations[str(rebuilt.reservation_id)] = {
                "reservation_id": str(rebuilt.reservation_id),
                "payload_digest": rebuilt.payload_sha256,
                "lease_token": str(rebuilt.lease_token),
                "lease_version": str(
                    rebuilt.lease_version - (1 if rebuilt.active else 0)
                ),
                "generation": str(authority["expected_generation"]),
                "state": rebuilt.state,
                "active": "1" if rebuilt.active else "0",
                "initial_buckets": list(initial_buckets),
                "holds": {
                    bucket: str(
                        holds.get((str(rebuilt.reservation_id), bucket), 0)
                    )
                    for bucket in _POLICY_BUCKETS
                },
            }
        metadata = {
            "generation": str(authority["expected_generation"]),
            "expected_generation": str(provenance["expected_generation"]),
            "snapshot_sha256": provenance["snapshot_sha256"],
            "state": "ready",
        }
        if provenance["reservation_count"] is not None:
            metadata["reservation_count"] = str(provenance["reservation_count"])
        return {
            "schema": "commercial.budget.expected-redis-manifest.v1",
            "agreement_terms_id": authority["agreement_terms_id"],
            "budget_period_id": build.budget_period_id,
            "generation": authority["expected_generation"],
            "pointer": {
                "generation": str(authority["expected_generation"]),
                "snapshot_sha256": provenance["snapshot_sha256"],
            },
            "generation_metadata": metadata,
            "active_reservations": str(build.active_reservations),
            "late_child_consumed_microusd": str(authority["late_consumed"]),
            "policy": {
                "budget_policy_id": str(authority["budget_policy_id"]),
                "generation": str(authority["expected_generation"]),
                "max_concurrency": str(authority["max_concurrency"]),
                "max_unreserved_delta": str(authority["max_unreserved_delta"]),
                "late_allowance": str(authority["late_allowance"]),
                "max_overdraft": str(authority["max_overdraft"]),
                "bucket_count": "2",
                "bucket:1": "model",
                "bucket:2": "technical",
                "limit:model": str(authority["limits"]["model"]),
                "limit:technical": str(authority["limits"]["technical"]),
            },
            "buckets": {
                item.budget_bucket: str(item.amount_microusd)
                for item in build.buckets
            },
            "durable_cost_authority": {
                "eligible_usage_count": cost_audit.eligible_usage_count,
                "current_management_total_microusd": (
                    cost_audit.current_management_total_microusd
                ),
                "applied_settlement_total_microusd": (
                    cost_audit.applied_settlement_total_microusd
                ),
                "late_child_total_microusd": cost_audit.late_child_total_microusd,
            },
            "reservations": reservations,
        }

    @staticmethod
    def _authority_only_snapshot(authority, cost_audit):
        return {
            "schema": "commercial.budget.blocked-authority.v1",
            "agreement_terms_id": authority["agreement_terms_id"],
            "budget_period_id": authority["budget_period_id"],
            "generation": authority["expected_generation"],
            "late_child_consumed_microusd": authority["late_consumed"],
            "durable_cost_authority": {
                "eligible_usage_count": cost_audit.eligible_usage_count,
                "current_management_total_microusd": (
                    cost_audit.current_management_total_microusd
                ),
                "applied_settlement_total_microusd": (
                    cost_audit.applied_settlement_total_microusd
                ),
                "late_child_total_microusd": cost_audit.late_child_total_microusd,
            },
            "reservation_ids": [str(row[0]) for row in authority["reservations"]],
        }

    def _generation_provenance(self, period_id: int, generation: int):
        if generation == 1:
            return {
                "expected_generation": 1,
                "snapshot_sha256": _GENERATION_ONE_DIGEST,
                "reservation_count": None,
            }
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT metadata
                  FROM commercial_budget_events
                 WHERE budget_period_id = %s
                   AND reservation_id IS NULL
                   AND event_kind = 'rebuild'
                   AND metadata->>'target_generation' = %s
                 ORDER BY id DESC LIMIT 1
                """,
                (period_id, str(generation)),
            )
            row = cursor.fetchone()
        if row is None or not isinstance(row[0], dict):
            return None
        metadata = row[0]
        digest = metadata.get("snapshot_sha256")
        expected = metadata.get("expected_generation")
        target = metadata.get("target_generation")
        count = metadata.get("reservation_count")
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or type(expected) is not int
            or type(target) is not int
            or type(count) is not int
            or expected <= 0
            or target != generation
            or count < 0
        ):
            return None
        return {
            "expected_generation": expected,
            "snapshot_sha256": digest,
            "reservation_count": count,
        }

    def _compare(self, expected, observed):
        findings: list[BudgetReconciliationFinding] = []
        for field, value in expected["pointer"].items():
            self._compare_value(
                findings,
                code="budget.redis_pointer_mismatch",
                path=f"redis.pointer.{field}",
                expected=value,
                observed=observed.pointer.get(field),
            )
        for field, value in expected["generation_metadata"].items():
            self._compare_value(
                findings,
                code="budget.redis_generation_metadata_mismatch",
                path=f"redis.generation_metadata.{field}",
                expected=value,
                observed=observed.generation_metadata.get(field),
            )
        self._compare_value(
            findings,
            code="budget.redis_active_count_mismatch",
            path="redis.active_reservations",
            expected=expected["active_reservations"],
            observed=observed.active_reservations,
        )
        self._compare_value(
            findings,
            code="budget.redis_late_child_mismatch",
            path="redis.late_child_consumed_microusd",
            expected=expected["late_child_consumed_microusd"],
            observed=observed.late_child_consumed_microusd,
        )
        for field, value in expected["policy"].items():
            self._compare_value(
                findings,
                code="budget.redis_policy_mismatch",
                path=f"redis.policy.{field}",
                expected=value,
                observed=observed.policy.get(field),
            )
        for bucket, value in expected["buckets"].items():
            self._compare_value(
                findings,
                code="budget.redis_counter_mismatch",
                path=f"redis.buckets.{bucket}",
                expected=value,
                observed=observed.buckets.get(bucket),
            )
        for identity, reservation in expected["reservations"].items():
            actual = observed.reservations.get(identity, {})
            if not actual:
                findings.append(
                    self._finding(
                        code="budget.redis_reservation_missing",
                        path=f"redis.reservations.{identity}",
                        expected="present",
                        observed="missing",
                    )
                )
                continue
            for field in (
                "reservation_id",
                "payload_digest",
                "lease_version",
                "generation",
                "state",
                "active",
            ):
                self._compare_value(
                    findings,
                    code="budget.redis_reservation_mismatch",
                    path=f"redis.reservations.{identity}.{field}",
                    expected=reservation[field],
                    observed=actual.get(field),
                )
            if actual.get("lease_token") != reservation["lease_token"]:
                findings.append(
                    self._finding(
                        code="budget.redis_reservation_mismatch",
                        path=f"redis.reservations.{identity}.lease_token",
                        expected="redacted:expected",
                        observed="redacted:mismatch",
                    )
                )
            for bucket, value in reservation["holds"].items():
                actual_hold = actual.get(f"hold:{bucket}")
                if actual_hold is None and value == "0":
                    actual_hold = "0"
                self._compare_value(
                    findings,
                    code="budget.redis_reservation_hold_mismatch",
                    path=f"redis.reservations.{identity}.hold:{bucket}",
                    expected=value,
                    observed=actual_hold,
                )
            count = _canonical_nonnegative(actual.get("bucket_count"))
            actual_buckets = (
                tuple(actual.get(f"bucket:{index}") for index in range(1, count + 1))
                if count is not None and count <= 2
                else ()
            )
            allowed = {
                tuple(reservation["initial_buckets"]),
                _POLICY_BUCKETS,
            }
            if actual_buckets not in allowed:
                findings.append(
                    self._finding(
                        code="budget.redis_reservation_bucket_mismatch",
                        path=f"redis.reservations.{identity}.buckets",
                        expected="|".join(",".join(item) for item in sorted(allowed)),
                        observed=",".join(str(item) for item in actual_buckets),
                    )
                )
        return tuple(findings)

    def _compare_value(self, findings, *, code, path, expected, observed):
        if observed != expected:
            findings.append(
                self._finding(
                    code=code,
                    path=path,
                    expected=expected,
                    observed=observed,
                )
            )

    @staticmethod
    def _finding(
        *,
        code,
        path,
        expected,
        observed,
        severity="critical",
        suggested="budget.generation_rebuild",
    ):
        return BudgetReconciliationFinding(
            code=code,
            severity=severity,
            owner="commercial.platform",
            path=path,
            expected=expected,
            observed=observed,
            suggested_repair=suggested,
        )

    @staticmethod
    def _unavailable_observation(agreement_terms_id, period_id, generation):
        body = {
            "schema": "commercial.budget.redis-observation-unavailable.v1",
            "agreement_terms_id": agreement_terms_id,
            "budget_period_id": period_id,
            "candidate_generation": generation,
        }
        return BudgetRedisManifestObservation(
            agreement_terms_id=agreement_terms_id,
            budget_period_id=period_id,
            candidate_generation=generation,
            observed_generation=None,
            pointer={},
            generation_metadata={},
            active_reservations=None,
            late_child_consumed_microusd=None,
            policy={},
            buckets={"model": None, "technical": None},
            reservations={},
            snapshot_sha256=canonical_sha256(body),
        )

    def _lock_evidence(self, command, command_sha256):
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (
                    f"budget-reconciliation:{command.budget_period_id}:"
                    f"{command.idempotency_key}",
                ),
            )
            cursor.execute(
                self._evidence_select()
                + " WHERE budget_period_id = %s AND idempotency_key = %s",
                (command.budget_period_id, command.idempotency_key),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        if row[5] != command_sha256:
            raise BudgetReconciliationProtocolError(
                "budget reconciliation replay conflicts with durable evidence"
            )
        return self._result(row, durable_replayed=True)

    def _lock_repair_authorization(self, command):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT mode, status
                  FROM commercial_budget_reconciliation_evidence
                 WHERE evidence_id = %s
                   AND budget_period_id = %s
                 FOR UPDATE
                """,
                (
                    str(command.repair_authorization_evidence_id),
                    command.budget_period_id,
                ),
            )
            authority = cursor.fetchone()
            cursor.execute(
                """
                SELECT 1
                  FROM commercial_budget_reconciliation_evidence
                 WHERE repair_authorization_evidence_id = %s
                 LIMIT 1
                """,
                (str(command.repair_authorization_evidence_id),),
            )
            already_consumed = cursor.fetchone()
        if authority != ("dry_run", "drift") or already_consumed is not None:
            raise BudgetReconciliationProtocolError(
                "budget repair lacks unused dry-run drift authority"
            )

    def _record(
        self,
        command,
        *,
        command_sha256,
        status,
        pre,
        now,
        post=None,
        rebuild_event_id=None,
        metadata=None,
    ):
        evidence_id = uuid5(
            NAMESPACE_URL,
            f"budget-reconciliation:{command.budget_period_id}:"
            f"{command.idempotency_key}",
        )
        pre_findings = [item.model_dump(mode="json") for item in pre.findings]
        post_findings = (
            [item.model_dump(mode="json") for item in post.findings]
            if post is not None
            else []
        )
        source_watermark = (
            post.source_watermark if post is not None else pre.source_watermark
        )
        if self._source_watermark(command.budget_period_id) != source_watermark:
            raise BudgetReconciliationProtocolError(
                "budget reconciliation source authority changed during observation"
            )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_budget_reconciliation_evidence (
                    evidence_id, budget_period_id, agreement_terms_id,
                    idempotency_key, command_sha256, mode, status,
                    expected_generation, observed_generation,
                    expected_snapshot_sha256, observed_snapshot_sha256,
                    post_repair_expected_generation,
                    post_repair_observed_generation,
                    post_repair_expected_snapshot_sha256,
                    post_repair_observed_snapshot_sha256,
                    pre_repair_findings, post_repair_findings,
                    rebuild_event_id, repair_authorization_evidence_id,
                    actor_id, occurred_at, metadata
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s,
                    %s, %s, %s::jsonb
                )
                ON CONFLICT (budget_period_id, idempotency_key) DO NOTHING
                """,
                (
                    str(evidence_id),
                    command.budget_period_id,
                    pre.agreement_terms_id,
                    command.idempotency_key,
                    command_sha256,
                    command.mode,
                    status,
                    pre.expected_generation,
                    pre.observation.observed_generation,
                    pre.expected_sha256,
                    pre.observation.snapshot_sha256,
                    post.expected_generation if post else None,
                    post.observation.observed_generation if post else None,
                    post.expected_sha256 if post else None,
                    post.observation.snapshot_sha256 if post else None,
                    json.dumps(pre_findings, sort_keys=True, separators=(",", ":")),
                    json.dumps(post_findings, sort_keys=True, separators=(",", ":")),
                    str(rebuild_event_id) if rebuild_event_id else None,
                    (
                        str(command.repair_authorization_evidence_id)
                        if command.repair_authorization_evidence_id
                        else None
                    ),
                    command.actor_id,
                    now,
                    json.dumps(
                        {
                            **(metadata or {}),
                            "schema": "commercial.budget.reconciliation-evidence.v2",
                            "source_watermark": source_watermark,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            cursor.execute(
                self._evidence_select() + " WHERE evidence_id = %s",
                (str(evidence_id),),
            )
            row = cursor.fetchone()
        if row is None or row[5] != command_sha256:
            raise BudgetReconciliationProtocolError(
                "budget reconciliation evidence write conflicted"
            )
        self._connection.commit()
        return self._result(row, durable_replayed=False)

    @staticmethod
    def _evidence_select():
        return """
            SELECT evidence_id, budget_period_id, agreement_terms_id,
                   idempotency_key, mode, command_sha256, status,
                   expected_generation, observed_generation,
                   expected_snapshot_sha256, observed_snapshot_sha256,
                   pre_repair_findings,
                   post_repair_expected_generation,
                   post_repair_observed_generation,
                   post_repair_expected_snapshot_sha256,
                   post_repair_observed_snapshot_sha256,
                   post_repair_findings, rebuild_event_id, actor_id, occurred_at
                   , repair_authorization_evidence_id
              FROM commercial_budget_reconciliation_evidence
        """

    @staticmethod
    def _result(row, *, durable_replayed):
        return BudgetReconciliationResult(
            evidence_id=row[0],
            budget_period_id=row[1],
            agreement_terms_id=row[2],
            idempotency_key=row[3],
            mode=row[4],
            status=row[6],
            expected_generation=row[7],
            observed_generation=row[8],
            expected_snapshot_sha256=row[9],
            observed_snapshot_sha256=row[10],
            pre_repair_findings=tuple(row[11]),
            post_repair_expected_generation=row[12],
            post_repair_observed_generation=row[13],
            post_repair_expected_snapshot_sha256=row[14],
            post_repair_observed_snapshot_sha256=row[15],
            post_repair_findings=tuple(row[16]),
            rebuild_event_id=row[17],
            actor_id=row[18],
            occurred_at=row[19],
            repair_authorization_evidence_id=row[20],
            durable_replayed=durable_replayed,
        )

    @staticmethod
    def _repair_key(command_sha256):
        return "reconcile.repair." + command_sha256.removeprefix("sha256:")[:32]

    def _source_watermark(self, budget_period_id: int) -> dict[str, Any]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT commercial_budget_reconciliation_source_watermark(%s)",
                (budget_period_id,),
            )
            source_watermark = cursor.fetchone()[0]
        if not isinstance(source_watermark, dict):
            raise BudgetReconciliationProtocolError(
                "budget reconciliation source watermark is unavailable"
            )
        return source_watermark

    def _now(self):
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise BudgetReconciliationProtocolError(
                "budget reconciliation clock must be timezone-aware"
            )
        return now

    def _require_idle(self):
        status_reader = getattr(self._connection, "get_transaction_status", None)
        status = status_reader() if callable(status_reader) else getattr(
            getattr(self._connection, "info", None), "transaction_status", 0
        )
        if status != 0:
            raise BudgetReconciliationProtocolError(
                "budget reconciliation requires a dedicated idle PostgreSQL connection"
            )


def _canonical_nonnegative(value: str | None) -> int | None:
    if (
        value is None
        or not value.isdigit()
        or (value != "0" and value.startswith("0"))
        or len(value) > len(str(MAX_SAFE_REDIS_INTEGER))
        or (
            len(value) == len(str(MAX_SAFE_REDIS_INTEGER))
            and value > str(MAX_SAFE_REDIS_INTEGER)
        )
    ):
        return None
    return int(value)
