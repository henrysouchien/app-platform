"""Production orchestration for approved Stripe repair and convergence proof."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import os
from typing import Any, Callable, ContextManager, Literal, Mapping
from uuid import UUID

import psycopg2

from ..flags import CommercialFlags
from .stripe_config import build_stripe_client, load_stripe_runtime_configuration
from .stripe_invoice_repairs import (
    StripeInvoiceRepairProvider,
    StripeInvoiceRepairService,
)
from .stripe_monetary_repairs import (
    StripeProcessorFeeRepairProvider,
    StripeProcessorFeeRepairService,
)
from .stripe_movement_repairs import (
    StripeMovementRepairProvider,
    StripeMovementRepairService,
)
from .stripe_projection_provider import StripeProjectionProvider
from .stripe_reconciliation import StripeSdkMonetaryReconciliationProvider
from .stripe_repair_reconciliation import (
    StripeRepairReconciliationProvider,
    StripeRepairReconciliationService,
)
from .stripe_repairs import (
    StripeSubscriptionRepairProvider,
    StripeSubscriptionRepairService,
)


OBSERVER_DATABASE_URL_ENV = "COMMERCIAL_STRIPE_REPAIR_OBSERVER_DATABASE_URL"
RepairKind = Literal["subscription", "processor_fee", "movement", "invoice"]
ObserverConnectionFactory = Callable[[], ContextManager[Any]]


class StripeRepairWorkflowError(RuntimeError):
    """The deployable repair workflow is unavailable or incorrectly isolated."""


@contextmanager
def get_stripe_repair_observer_connection(*, env: Mapping[str, str] = os.environ):
    """Open the separately credentialed, autocommit-only attestation connection."""

    database_url = (env.get(OBSERVER_DATABASE_URL_ENV) or "").strip()
    if not database_url:
        raise StripeRepairWorkflowError(
            f"{OBSERVER_DATABASE_URL_ENV} is required for Stripe repair"
        )
    connection = None
    try:
        connection = psycopg2.connect(
            database_url,
            application_name="hank-stripe-repair-observer",
            connect_timeout=5,
        )
        connection.autocommit = True
    except Exception:
        raise StripeRepairWorkflowError(
            "Stripe repair observer connection is unavailable"
        ) from None
    try:
        yield connection
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _one_row(connection: Any, query: str, parameters: tuple[Any, ...] = ()) -> tuple:
    cursor = connection.cursor()
    try:
        cursor.execute(query, parameters)
        row = cursor.fetchone()
    finally:
        cursor.close()
    if row is None:
        raise StripeRepairWorkflowError(
            "Stripe repair database authority is unavailable"
        )
    return tuple(row.values()) if isinstance(row, Mapping) else tuple(row)


def _validate_database_identities(writer: Any, observer: Any) -> None:
    if bool(getattr(writer, "autocommit", False)):
        raise StripeRepairWorkflowError("Stripe repair writer must be transactional")
    if not bool(getattr(observer, "autocommit", False)):
        raise StripeRepairWorkflowError("Stripe repair observer must use autocommit")

    writer_facts = _one_row(
        writer,
        """SELECT current_user,
                  has_function_privilege(
                      current_user,
                      'commercial_attest_stripe_repair_snapshot(jsonb,jsonb)',
                      'EXECUTE'
                  ),
                  has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'SELECT'
                  ) OR has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'INSERT'
                  ) OR has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'UPDATE'
                  ) OR has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'DELETE'
                  ) OR has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'TRUNCATE'
                  ) OR has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'REFERENCES'
                  ) OR has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'TRIGGER'
                  ),
                  has_function_privilege(
                      current_user,
                      'commercial_verify_stripe_repair_attestation(jsonb,uuid,text)',
                      'EXECUTE'
                  ),
                  role.rolsuper OR role.rolinherit IS FALSE
                      OR role.rolcreaterole OR role.rolcreatedb
                      OR role.rolreplication OR role.rolbypassrls
             FROM pg_catalog.pg_roles role
            WHERE role.rolname = current_user""",
    )
    observer_facts = _one_row(
        observer,
        """SELECT current_user,
                  has_function_privilege(
                      current_user,
                      'commercial_attest_stripe_repair_snapshot(jsonb,jsonb)',
                      'EXECUTE'
                  ),
                  has_table_privilege(
                      current_user,
                      'commercial_stripe_repair_attestation_keys', 'SELECT'
                  ),
                  has_schema_privilege(current_user, current_schema(), 'CREATE'),
                  EXISTS (
                      SELECT 1
                        FROM pg_catalog.pg_class relation
                        JOIN pg_catalog.pg_namespace namespace
                          ON namespace.oid = relation.relnamespace
                       WHERE namespace.nspname = current_schema()
                         AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                         AND (
                             has_table_privilege(current_user, relation.oid, 'SELECT')
                             OR has_table_privilege(current_user, relation.oid, 'INSERT')
                             OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                             OR has_table_privilege(current_user, relation.oid, 'DELETE')
                             OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                             OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                             OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                         )
                  ),
                  EXISTS (
                      SELECT 1
                        FROM pg_catalog.pg_class sequence
                        JOIN pg_catalog.pg_namespace namespace
                          ON namespace.oid = sequence.relnamespace
                       WHERE namespace.nspname = current_schema()
                         AND sequence.relkind = 'S'
                         AND (
                             has_sequence_privilege(current_user, sequence.oid, 'USAGE')
                             OR has_sequence_privilege(current_user, sequence.oid, 'SELECT')
                             OR has_sequence_privilege(current_user, sequence.oid, 'UPDATE')
                         )
                  ),
                  EXISTS (
                      SELECT 1
                        FROM pg_catalog.pg_proc function
                        JOIN pg_catalog.pg_namespace namespace
                          ON namespace.oid = function.pronamespace
                       WHERE namespace.nspname = current_schema()
                         AND function.prosecdef
                         AND function.oid <> to_regprocedure(
                             'commercial_attest_stripe_repair_snapshot(jsonb,jsonb)'
                         )
                         AND has_function_privilege(
                             current_user, function.oid, 'EXECUTE'
                         )
                  ),
                  role.rolsuper OR role.rolinherit IS FALSE
                      OR role.rolcreaterole OR role.rolcreatedb
                      OR role.rolreplication OR role.rolbypassrls
             FROM pg_catalog.pg_roles role
            WHERE role.rolname = current_user""",
    )
    if (
        writer_facts[0] == observer_facts[0]
        or bool(writer_facts[1])
        or bool(writer_facts[2])
        or not bool(writer_facts[3])
        or bool(writer_facts[4])
        or not bool(observer_facts[1])
        or any(bool(value) for value in observer_facts[2:])
    ):
        raise StripeRepairWorkflowError(
            "Stripe repair database identities violate least privilege"
        )


def _repair_kind(writer: Any, *, request_id: UUID, environment: str) -> RepairKind:
    row = _one_row(
        writer,
        """SELECT intent.repair_code, intent.subject_type, intent.subject_id
               FROM commercial_change_requests request
               JOIN commercial_stripe_repair_intents intent
                 ON request.target_type = 'commercial_stripe_repair_intent'
                AND request.target_id = intent.intent_id::TEXT
              WHERE request.request_id = %s
                AND request.environment = %s
                AND intent.environment = %s""",
        (str(request_id), environment, environment),
    )
    repair_code, subject_type, subject_id = (str(value) for value in row)
    if repair_code == "stripe.subscription_projection_repair":
        kind: RepairKind = "subscription"
    elif repair_code == "stripe.invoice_projection_repair":
        kind = "invoice"
    elif (
        repair_code == "stripe.money_movement_projection_repair"
        and subject_type == "stripe_movement"
    ):
        kind = (
            "processor_fee"
            if subject_id.startswith("balance_transaction:")
            and subject_id.endswith(":processor_fee")
            else "movement"
        )
    else:
        raise StripeRepairWorkflowError("Approved Stripe repair kind is unsupported")
    return kind


def execute_stripe_repair_workflow(
    *,
    writer: Any,
    observer: Any,
    flags: CommercialFlags,
    operator_user_id: int,
    runtime_environment: str,
    step_up_event_id: UUID,
    request_id: UUID,
    clock: Callable[[], datetime],
    env: Mapping[str, str] = os.environ,
) -> dict[str, Any]:
    """Execute an approved repair and, for monetary facts, prove convergence."""

    _validate_database_identities(writer, observer)
    kind = _repair_kind(writer, request_id=request_id, environment=runtime_environment)
    writer.commit()

    providers: tuple[Any, Any] | None = None

    def load_providers() -> tuple[Any, Any]:
        nonlocal providers
        if providers is None:
            runtime = load_stripe_runtime_configuration(flags, env=env)
            client = build_stripe_client(runtime)
            projection = StripeProjectionProvider(
                client, deployment=runtime.deployment, clock=clock
            )
            monetary = StripeSdkMonetaryReconciliationProvider(
                client,
                projection_provider=projection,
                deployment=runtime.deployment,
                clock=clock,
            )
            providers = (projection, monetary)
        return providers

    service_types: dict[RepairKind, type] = {
        "subscription": StripeSubscriptionRepairService,
        "processor_fee": StripeProcessorFeeRepairService,
        "movement": StripeMovementRepairService,
        "invoice": StripeInvoiceRepairService,
    }
    provider_types: dict[RepairKind, type] = {
        "subscription": StripeSubscriptionRepairProvider,
        "processor_fee": StripeProcessorFeeRepairProvider,
        "movement": StripeMovementRepairProvider,
        "invoice": StripeInvoiceRepairProvider,
    }
    repair_service = service_types[kind](writer, flags=flags, clock=clock)
    operator_arguments = {
        "operator_user_id": operator_user_id,
        "runtime_environment": runtime_environment,
        "step_up_event_id": step_up_event_id,
        "request_id": request_id,
    }
    result = repair_service.load_replay_as_operator(**operator_arguments)
    if result is None:
        preparation = repair_service.prepare_as_operator(**operator_arguments)
    writer.commit()

    if result is None:
        projection, monetary = load_providers()
        source_provider = projection if kind == "subscription" else monetary
        observation = provider_types[kind](
            source_provider, connection=writer, attestation_connection=observer
        ).observe(preparation)
        result = repair_service.execute_as_operator(
            **operator_arguments,
            observation=observation,
        )
        writer.commit()

    public_result = result.model_dump(mode="json")
    proof_result = None
    if kind != "subscription":
        proof_service = StripeRepairReconciliationService(
            writer, flags=flags, clock=clock
        )
        proof_arguments = {
            "operator_user_id": operator_user_id,
            "runtime_environment": runtime_environment,
            "repair_kind": kind,
            "repair_execution_id": result.execution_id,
        }
        proof = proof_service.load_replay_as_operator(**proof_arguments)
        if proof is None:
            proof_preparation = proof_service.prepare_as_operator(**proof_arguments)
        writer.commit()
        if proof is None:
            _projection, monetary = load_providers()
            proof_observation = StripeRepairReconciliationProvider(
                monetary, connection=writer, attestation_connection=observer
            ).observe(proof_preparation)
            proof = proof_service.record_as_operator(
                operator_user_id=operator_user_id,
                runtime_environment=runtime_environment,
                preparation=proof_preparation,
                observation=proof_observation,
            )
            writer.commit()
        proof_result = proof.model_dump(mode="json")

    requires_attention = bool(
        proof_result is not None and proof_result.get("outcome") == "finding"
    )
    return {
        "request_id": str(request_id),
        "repair_kind": kind,
        "workflow_status": ("requires_attention" if requires_attention else "complete"),
        "durability": "repair_and_available_proof_committed",
        "repair": public_result,
        "post_repair_reconciliation": proof_result,
    }


__all__ = [
    "OBSERVER_DATABASE_URL_ENV",
    "ObserverConnectionFactory",
    "StripeRepairWorkflowError",
    "execute_stripe_repair_workflow",
    "get_stripe_repair_observer_connection",
]
