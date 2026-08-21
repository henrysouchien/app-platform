"""Fresh post-repair Stripe monetary reconciliation and convergence evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import json
import secrets
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, PrivateAttr, StrictBool

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..authority import CommercialRole
from ..authority_store import load_named_operator
from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel, canonical_sha256
from ..reconciliation import (
    CommercialReconciliationService,
    StripeMonetaryReconciliationCommand,
)
from .stripe_reconciliation import (
    StripeMonetaryObservation,
    StripeMonetaryReconciliationExpectation,
    load_stripe_reconciliation_authority,
)


StripeRepairKind = Literal["processor_fee", "movement", "invoice"]
_PROCESS_ATTESTATION_KEY = secrets.token_bytes(32)
_PROCESS_ATTESTATION_CAPABILITY = object()


class StripeRepairReconciliationError(RuntimeError):
    """A repair or its post-repair provider evidence cannot be proven current."""


class StripeRepairReconciliationPreparation(StrictCommercialModel):
    repair_kind: StripeRepairKind
    repair_execution_id: UUID
    repair_request_id: UUID
    source_finding_id: UUID
    source_fingerprint_sha256: Sha256Digest
    source_subject_type: str = Field(min_length=1, max_length=127)
    source_subject_id: str = Field(min_length=1, max_length=512)
    environment: Literal["dev", "staging", "prod"]
    billing_environment: Literal["test", "live"]
    commercial_account_id: int = Field(gt=0)
    repair_executed_at: AwareDatetime
    monetary_expectation: StripeMonetaryReconciliationExpectation
    subscription_ids_by_agreement: dict[UUID, str]


class StripeRepairReconciliationResult(StrictCommercialModel):
    proof_id: UUID
    repair_kind: StripeRepairKind
    repair_execution_id: UUID
    repair_request_id: UUID
    source_finding_id: UUID
    reconciliation_run_id: UUID
    source_resolution_id: UUID | None = None
    commercial_account_id: int = Field(gt=0)
    outcome: Literal["converged", "finding"]
    successor_finding_ids: tuple[UUID, ...]
    provider_observation_sha256: Sha256Digest
    provider_observed_at: AwareDatetime
    recorded_at: AwareDatetime
    durable_replayed: StrictBool = False


class StripeRepairReconciliationObservation(StrictCommercialModel):
    provider_observation: StripeMonetaryObservation
    database_attestation_document: dict
    database_attestation_key_id: UUID
    database_attestation_sha256: Sha256Digest
    _process_attestation: str | None = PrivateAttr(default=None)

    @classmethod
    def _from_provider(
        cls,
        *,
        provider_observation: StripeMonetaryObservation,
        database_attestation_document: dict,
        database_attestation_key_id: UUID,
        database_attestation_sha256: str,
        repair_execution_id: UUID,
        capability: object,
    ) -> "StripeRepairReconciliationObservation":
        if capability is not _PROCESS_ATTESTATION_CAPABILITY:
            raise StripeRepairReconciliationError(
                "Stripe post-repair provider authority is invalid"
            )
        result = cls(
            provider_observation=provider_observation,
            database_attestation_document=database_attestation_document,
            database_attestation_key_id=database_attestation_key_id,
            database_attestation_sha256=database_attestation_sha256,
        )
        result._process_attestation = hmac.digest(
            _PROCESS_ATTESTATION_KEY,
            result._attestation_body(repair_execution_id),
            "sha256",
        ).hex()
        return result

    def has_provider_attestation(self, repair_execution_id: UUID) -> bool:
        expected = hmac.digest(
            _PROCESS_ATTESTATION_KEY,
            self._attestation_body(repair_execution_id),
            "sha256",
        ).hex()
        return self._process_attestation is not None and hmac.compare_digest(
            self._process_attestation, expected
        )

    def _attestation_body(self, repair_execution_id: UUID) -> bytes:
        return (
            f"{repair_execution_id}|{self.provider_observation.content_sha256}|"
            f"{self.provider_observation.observed_at.isoformat()}"
        ).encode("ascii")


class StripeRepairReconciliationProvider:
    """Fetch a fresh complete account observation after a repair has committed."""

    def __init__(
        self,
        provider: Any,
        *,
        connection: Any,
        attestation_connection: Any,
    ) -> None:
        self._provider = provider
        self._connection = connection
        self._attestation_connection = attestation_connection

    def observe(
        self, preparation: StripeRepairReconciliationPreparation
    ) -> StripeRepairReconciliationObservation:
        status = getattr(self._connection, "get_transaction_status", None)
        attestation_status = getattr(
            self._attestation_connection, "get_transaction_status", None
        )
        if status is None or status() != 0:
            raise StripeRepairReconciliationError(
                "Stripe post-repair provider I/O requires an idle connection"
            )
        if (
            attestation_status is None
            or attestation_status() != 0
            or not bool(getattr(self._attestation_connection, "autocommit", False))
        ):
            raise StripeRepairReconciliationError(
                "Stripe post-repair attestation requires an idle connection"
            )
        observation = self._provider.observe(
            preparation.monetary_expectation,
            subscription_ids_by_agreement=preparation.subscription_ids_by_agreement,
        )
        if (
            observation.evidence_completeness != "complete"
            or not observation.has_provider_attestation()
            or observation.environment != preparation.billing_environment
            or observation.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
            or observation.observed_at <= preparation.repair_executed_at
        ):
            raise StripeRepairReconciliationError(
                "Stripe post-repair provider evidence is invalid"
            )
        provider_json = observation.model_dump(mode="json")
        document = {
            "schema": "commercial.stripe-repair-reconciliation-attestation.v1",
            "repair_kind": preparation.repair_kind,
            "repair_execution_id": str(preparation.repair_execution_id),
            "repair_request_id": str(preparation.repair_request_id),
            "source_finding_id": str(preparation.source_finding_id),
            "runtime_environment": preparation.environment,
            "billing_environment": preparation.billing_environment,
            "commercial_account_id": preparation.commercial_account_id,
            "observation_content_sha256": observation.content_sha256,
            "observed_at": provider_json["observed_at"],
        }
        cursor = self._attestation_connection.cursor()
        try:
            cursor.execute(
                """SELECT attestation_document, key_id, attestation_sha256
                     FROM commercial_attest_stripe_repair_snapshot(
                         %s::jsonb, %s::jsonb
                     )""",
                (json.dumps(document, sort_keys=True), json.dumps(provider_json)),
            )
            attestation = cursor.fetchone()
        finally:
            cursor.close()
        if attestation is None:
            raise StripeRepairReconciliationError(
                "Stripe post-repair database attestation is unavailable"
            )
        return StripeRepairReconciliationObservation._from_provider(
            provider_observation=observation,
            database_attestation_document=attestation[0],
            database_attestation_key_id=UUID(str(attestation[1])),
            database_attestation_sha256=str(attestation[2]),
            repair_execution_id=preparation.repair_execution_id,
            capability=_PROCESS_ATTESTATION_CAPABILITY,
        )


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class StripeRepairReconciliationService:
    """Persist an explicit fresh reconciliation proof for one committed repair."""

    _TABLES: dict[StripeRepairKind, str] = {
        "processor_fee": "commercial_stripe_monetary_repair_executions",
        "movement": "commercial_stripe_movement_repair_executions",
        "invoice": "commercial_stripe_invoice_repair_executions",
    }

    def __init__(self, connection: Any, *, flags: CommercialFlags, clock=None) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not (
            flags.commercial_control_enabled
            and flags.commercial_reconciliation_enabled
            and flags.stripe_billing_enabled
        ):
            raise StripeRepairReconciliationError(
                "Stripe post-repair reconciliation is disabled"
            )

    @_atomic
    def load_replay_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        repair_kind: StripeRepairKind,
        repair_execution_id: UUID,
    ) -> StripeRepairReconciliationResult | None:
        """Return a prior proof after rechecking viewer authority."""

        self._require_viewer(operator_user_id, runtime_environment)
        result = self._load_proof(repair_kind, repair_execution_id)
        return (
            result.model_copy(update={"durable_replayed": True})
            if result is not None
            else None
        )

    @_atomic
    def prepare_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        repair_kind: StripeRepairKind,
        repair_execution_id: UUID,
    ) -> StripeRepairReconciliationPreparation:
        self._require_viewer(operator_user_id, runtime_environment)
        row = self._load_repair(repair_kind, repair_execution_id, lock=True)
        if row is None:
            raise StripeRepairReconciliationError(
                "Stripe repair execution is unavailable"
            )
        authority = load_stripe_reconciliation_authority(
            self._connection,
            commercial_account_id=int(row[4]),
            environment=row[6],
        )
        if authority.monetary is None:
            raise StripeRepairReconciliationError(
                "Stripe post-repair monetary authority is unavailable"
            )
        return StripeRepairReconciliationPreparation(
            repair_kind=repair_kind,
            repair_execution_id=row[0],
            repair_request_id=row[1],
            source_finding_id=row[2],
            source_fingerprint_sha256=row[3],
            commercial_account_id=int(row[4]),
            environment=row[5],
            billing_environment=row[6],
            repair_executed_at=row[7],
            source_subject_type=row[8],
            source_subject_id=row[9],
            monetary_expectation=authority.monetary,
            subscription_ids_by_agreement=authority.subscription_ids_by_agreement,
        )

    @_atomic
    def record_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        preparation: StripeRepairReconciliationPreparation,
        observation: StripeRepairReconciliationObservation,
    ) -> StripeRepairReconciliationResult:
        self._require_viewer(operator_user_id, runtime_environment)
        self._advisory_lock(preparation)
        replay = self._load_proof(
            preparation.repair_kind, preparation.repair_execution_id
        )
        if replay is not None:
            return replay.model_copy(update={"durable_replayed": True})
        repair = self._load_repair(
            preparation.repair_kind,
            preparation.repair_execution_id,
            lock=True,
        )
        if repair is None or self._preparation_identity(
            preparation
        ) != self._repair_identity(repair):
            raise StripeRepairReconciliationError(
                "Stripe post-repair preparation is stale"
            )
        now = self._clock()
        provider_observation = observation.provider_observation
        if (
            not observation.has_provider_attestation(preparation.repair_execution_id)
            or provider_observation.evidence_completeness != "complete"
            or not provider_observation.has_provider_attestation()
            or provider_observation.environment != preparation.billing_environment
            or provider_observation.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
            or provider_observation.observed_at <= preparation.repair_executed_at
            or provider_observation.observed_at < now - timedelta(minutes=15)
            or provider_observation.observed_at > now + timedelta(minutes=5)
        ):
            raise StripeRepairReconciliationError(
                "Stripe post-repair observation is not fresh"
            )
        reconciliation = CommercialReconciliationService(
            self._connection, flags=self._flags
        )
        run = reconciliation.reconcile_stripe_monetary_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=runtime_environment,
            command=StripeMonetaryReconciliationCommand(
                idempotency_key=self._run_idempotency_key(preparation),
                commercial_account_id=preparation.commercial_account_id,
                reason_code="stripe.repair.post_reconciliation",
            ),
            observation=provider_observation,
        )
        successors = tuple(
            finding
            for finding in run.findings
            if finding.subject_type == preparation.source_subject_type
            and finding.subject_id == preparation.source_subject_id
        )
        outcome: Literal["converged", "finding"] = (
            "finding" if successors else "converged"
        )
        source_resolution_id = None
        if not any(
            finding.fingerprint_sha256 == preparation.source_fingerprint_sha256
            for finding in run.findings
        ):
            source_resolution_id = self._resolve_source_finding(
                operator_user_id=operator_user_id,
                preparation=preparation,
            )
        proof_id = uuid4()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_stripe_repair_reconciliation_proofs (
                       proof_id, repair_kind, repair_execution_id,
                       repair_request_id, source_finding_id,
                       commercial_account_id, environment, billing_environment,
                       reconciliation_run_id, source_resolution_id,
                       provider_observation_sha256, provider_observation_json,
                       provider_observed_at, provider_attestation_document,
                       provider_attestation_key_id,
                       provider_attestation_sha256, outcome, actor_user_id
                   ) VALUES (
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                   )
                   RETURNING recorded_at""",
                (
                    str(proof_id),
                    preparation.repair_kind,
                    str(preparation.repair_execution_id),
                    str(preparation.repair_request_id),
                    str(preparation.source_finding_id),
                    preparation.commercial_account_id,
                    runtime_environment,
                    preparation.billing_environment,
                    str(run.run_id),
                    (
                        str(source_resolution_id)
                        if source_resolution_id is not None
                        else None
                    ),
                    provider_observation.content_sha256,
                    json.dumps(provider_observation.model_dump(mode="json")),
                    provider_observation.observed_at,
                    json.dumps(observation.database_attestation_document),
                    str(observation.database_attestation_key_id),
                    observation.database_attestation_sha256,
                    outcome,
                    operator_user_id,
                ),
            )
            recorded_at = cursor.fetchone()[0]
            for finding in successors:
                cursor.execute(
                    """INSERT INTO
                           commercial_stripe_repair_reconciliation_findings (
                               proof_id, finding_id
                           ) VALUES (%s,%s)""",
                    (str(proof_id), str(finding.finding_id)),
                )
        finally:
            cursor.close()
        return StripeRepairReconciliationResult(
            proof_id=proof_id,
            repair_kind=preparation.repair_kind,
            repair_execution_id=preparation.repair_execution_id,
            repair_request_id=preparation.repair_request_id,
            source_finding_id=preparation.source_finding_id,
            reconciliation_run_id=run.run_id,
            source_resolution_id=source_resolution_id,
            commercial_account_id=preparation.commercial_account_id,
            outcome=outcome,
            successor_finding_ids=tuple(item.finding_id for item in successors),
            provider_observation_sha256=provider_observation.content_sha256,
            provider_observed_at=provider_observation.observed_at,
            recorded_at=recorded_at,
        )

    def _load_repair(
        self,
        repair_kind: StripeRepairKind,
        execution_id: UUID,
        *,
        lock: bool,
    ):
        table = self._TABLES[repair_kind]
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""SELECT execution.execution_id, execution.request_id,
                           execution.source_finding_id,
                           finding.fingerprint_sha256,
                           execution.commercial_account_id,
                           execution.environment, execution.billing_environment,
                           execution.executed_at, finding.subject_type,
                           finding.subject_id
                      FROM {table} execution
                      JOIN commercial_reconciliation_findings finding
                        ON finding.finding_id = execution.source_finding_id
                     WHERE execution.execution_id = %s
                     {"FOR KEY SHARE OF execution, finding" if lock else ""}""",
                (str(execution_id),),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def _preparation_identity(preparation: StripeRepairReconciliationPreparation):
        return (
            str(preparation.repair_execution_id),
            str(preparation.repair_request_id),
            str(preparation.source_finding_id),
            str(preparation.source_fingerprint_sha256),
            preparation.commercial_account_id,
            str(preparation.environment),
            str(preparation.billing_environment),
            preparation.repair_executed_at,
            str(preparation.source_subject_type),
            str(preparation.source_subject_id),
        )

    @staticmethod
    def _repair_identity(row):
        return (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            int(row[4]),
            str(row[5]),
            str(row[6]),
            row[7],
            str(row[8]),
            str(row[9]),
        )

    def _load_proof(self, repair_kind: StripeRepairKind, execution_id: UUID):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT proof.proof_id, proof.repair_kind,
                          proof.repair_execution_id, proof.repair_request_id,
                          proof.source_finding_id, proof.reconciliation_run_id,
                          proof.source_resolution_id,
                          proof.commercial_account_id, proof.outcome,
                          proof.provider_observation_sha256,
                          proof.provider_observed_at, proof.recorded_at,
                          COALESCE(array_agg(successor.finding_id)
                              FILTER (WHERE successor.finding_id IS NOT NULL),
                              '{}'::UUID[])
                     FROM commercial_stripe_repair_reconciliation_proofs proof
                LEFT JOIN commercial_stripe_repair_reconciliation_findings successor
                       ON successor.proof_id = proof.proof_id
                    WHERE proof.repair_kind = %s
                      AND proof.repair_execution_id = %s
                 GROUP BY proof.proof_id""",
                (repair_kind, str(execution_id)),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        successor_values = row[12]
        if isinstance(successor_values, str):
            successor_values = tuple(
                value for value in successor_values.strip("{}").split(",") if value
            )
        return StripeRepairReconciliationResult(
            proof_id=row[0],
            repair_kind=row[1],
            repair_execution_id=row[2],
            repair_request_id=row[3],
            source_finding_id=row[4],
            reconciliation_run_id=row[5],
            source_resolution_id=row[6],
            commercial_account_id=int(row[7]),
            outcome=row[8],
            provider_observation_sha256=row[9],
            provider_observed_at=row[10],
            recorded_at=row[11],
            successor_finding_ids=tuple(successor_values),
        )

    def _require_viewer(self, user_id: int, environment: str) -> None:
        if environment != self._flags.environment:
            raise StripeRepairReconciliationError(
                "Stripe post-repair reconciliation environment mismatch"
            )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            deployment = cursor.fetchone()
        finally:
            cursor.close()
        operator = load_named_operator(
            self._connection, user_id=user_id, environment=environment
        )
        if (
            deployment is None
            or deployment[0] != environment
            or CommercialRole.COMMERCIAL_VIEWER not in operator.roles
            or CommercialRole.COMMERCIAL_ADMIN not in operator.roles
        ):
            raise StripeRepairReconciliationError(
                "Stripe post-repair reconciliation operator is unauthorized"
            )

    def _resolve_source_finding(
        self,
        *,
        operator_user_id: int,
        preparation: StripeRepairReconciliationPreparation,
    ) -> UUID:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT fingerprint_sha256
                     FROM commercial_reconciliation_current_findings
                    WHERE environment = %s
                      AND suite_code = 'stripe_monetary.v1'
                      AND scope_type = 'account' AND scope_id = %s
                      AND finding_id = %s AND resolution_state = 'open'""",
                (
                    preparation.environment,
                    str(preparation.commercial_account_id),
                    str(preparation.source_finding_id),
                ),
            )
            source = cursor.fetchone()
        finally:
            cursor.close()
        if source is None or source[0] != preparation.source_fingerprint_sha256:
            raise StripeRepairReconciliationError(
                "Stripe post-repair source finding is not current"
            )
        idempotency_key = self._resolution_idempotency_key(preparation)
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.stripe-repair-reconciliation-resolution.v1",
                "environment": preparation.environment,
                "repair_kind": preparation.repair_kind,
                "repair_execution_id": str(preparation.repair_execution_id),
                "source_finding_id": str(preparation.source_finding_id),
                "commercial_account_id": preparation.commercial_account_id,
                "resolution_kind": "resolved",
                "reason_code": "stripe.repair.post_reconciliation",
            }
        )
        resolution_id = uuid4()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=preparation.commercial_account_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.reconciliation.resolve.resolved",
                target_type="commercial_reconciliation_finding",
                target_id=str(preparation.source_finding_id),
                reason_code="stripe.repair.post_reconciliation",
                after={
                    "account_id": preparation.commercial_account_id,
                    "content_sha256": command_sha256,
                    "environment": preparation.environment,
                    "role": "commercial_admin",
                    "result_code": "applied",
                },
                request_id=str(preparation.repair_request_id),
            ),
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_reconciliation_resolutions (
                       resolution_id, source_finding_id, environment,
                       suite_code, scope_type, scope_id, fingerprint_sha256,
                       idempotency_key, command_sha256, resolution_kind,
                       reason_code, actor_user_id, audit_event_id, resolved_at
                   ) VALUES (
                       %s,%s,%s,'stripe_monetary.v1','account',%s,%s,%s,%s,
                       'resolved','stripe.repair.post_reconciliation',%s,%s,
                       statement_timestamp()
                   )""",
                (
                    str(resolution_id),
                    str(preparation.source_finding_id),
                    preparation.environment,
                    str(preparation.commercial_account_id),
                    preparation.source_fingerprint_sha256,
                    idempotency_key,
                    command_sha256,
                    operator_user_id,
                    str(audit_event_id),
                ),
            )
        finally:
            cursor.close()
        return resolution_id

    def _advisory_lock(
        self, preparation: StripeRepairReconciliationPreparation
    ) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (
                    "commercial_stripe_repair_reconciliation",
                    f"{preparation.repair_kind}:{preparation.repair_execution_id}",
                ),
            )
        finally:
            cursor.close()

    @staticmethod
    def _run_idempotency_key(
        preparation: StripeRepairReconciliationPreparation,
    ) -> str:
        return (
            f"stripe-repair-post:{preparation.repair_kind}:"
            f"{preparation.repair_execution_id}"
        )

    @staticmethod
    def _resolution_idempotency_key(
        preparation: StripeRepairReconciliationPreparation,
    ) -> str:
        return (
            f"stripe-repair-resolve:{preparation.repair_kind}:"
            f"{preparation.repair_execution_id}"
        )

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError(
                "Stripe post-repair reconciliation requires a transaction"
            )
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_stripe_repair_reconciliation")
            try:
                result = operation()
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_stripe_repair_reconciliation"
                )
                cursor.execute(
                    "RELEASE SAVEPOINT commercial_stripe_repair_reconciliation"
                )
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_repair_reconciliation")
            return result
        finally:
            cursor.close()


__all__ = [
    "StripeRepairReconciliationError",
    "StripeRepairReconciliationObservation",
    "StripeRepairReconciliationPreparation",
    "StripeRepairReconciliationProvider",
    "StripeRepairReconciliationResult",
    "StripeRepairReconciliationService",
]
