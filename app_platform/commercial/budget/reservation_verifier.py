"""PostgreSQL proof that metered usage belongs to a live budget reservation."""

from __future__ import annotations

from typing import Mapping
from uuid import NAMESPACE_URL, UUID, uuid5

from ..usage.contract import (
    CommercialUsageEvent,
    CommercialUsageEventV2,
    CommercialUsageEventV3,
)
from ..usage.ingest import (
    ReservationUsageEvidence,
    RetryableUsageIngestError,
    TerminalUsageIngestError,
)


_ACTIVE_STATES = frozenset({"reserved", "partially_settled", "overdrawn"})
_LATE_RECOVERY_STATES = _ACTIVE_STATES | frozenset({"settled", "released", "expired"})


class PostgresReservationUsageVerifier:
    """Lock and validate the durable reservation before usage can settle."""

    def verify(
        self,
        connection,
        event: CommercialUsageEvent,
    ) -> ReservationUsageEvidence:
        try:
            reservation_id = UUID(str(event.reservation_id or ""))
            execution_context_id = UUID(str(event.execution_context_id))
            workflow_run_id = UUID(str(event.workflow_run_id))
        except (TypeError, ValueError):
            raise TerminalUsageIngestError(
                "usage.invalid_reservation_lineage"
            ) from None

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT reservation.execution_context_id,
                       reservation.workflow_run_id,
                       reservation.request_id,
                       reservation.state,
                       reservation.authorized_work_start_deadline,
                       reservation.expires_at,
                       reservation.late_child_accept_until,
                       reservation.lease_version,
                       workflow.started_at
                  FROM commercial_budget_reservations reservation
                  JOIN commercial_workflow_runs workflow
                    ON workflow.id = %s
                   AND workflow.execution_context_id = reservation.execution_context_id
                 WHERE reservation.id = %s
                 FOR SHARE OF reservation, workflow
                """,
                (str(workflow_run_id), str(reservation_id)),
            )
            row = cursor.fetchone()
        if row is None:
            raise TerminalUsageIngestError("usage.reservation_not_found")
        if isinstance(row, Mapping):
            facts = (
                row["execution_context_id"],
                row["workflow_run_id"],
                row["request_id"],
                row["state"],
                row["authorized_work_start_deadline"],
                row["expires_at"],
                row["late_child_accept_until"],
                row["lease_version"],
                row["started_at"],
            )
        else:
            facts = row
        (
            stored_context_id,
            stored_workflow_id,
            stored_request_id,
            state,
            work_start_deadline,
            expires_at,
            late_child_accept_until,
            lease_version,
            operation_started_at,
        ) = facts

        has_attempt_authority = isinstance(event, CommercialUsageEventV2) or (
            isinstance(event, CommercialUsageEventV3)
            and event.workflow_attempt_group_id is not None
        )

        if (
            UUID(str(stored_context_id)) != execution_context_id
            or (has_attempt_authority and stored_workflow_id is None)
            or (
                stored_workflow_id is not None
                and UUID(str(stored_workflow_id)) != workflow_run_id
            )
            or stored_request_id != event.request_id
            or operation_started_at > work_start_deadline
        ):
            raise TerminalUsageIngestError("usage.reservation_lineage_mismatch")
        if state == "pending":
            raise RetryableUsageIngestError("usage.reservation_not_ready")
        if event.occurred_at > late_child_accept_until:
            raise TerminalUsageIngestError("usage.reservation_late_window_expired")
        is_late_child = event.occurred_at >= expires_at
        allowed_states = _LATE_RECOVERY_STATES if is_late_child else _ACTIVE_STATES
        if state not in allowed_states:
            raise TerminalUsageIngestError("usage.reservation_inactive")

        settlement_binding_id = "budget-settlement:" + str(
            uuid5(
                NAMESPACE_URL,
                (
                    f"{reservation_id}:{event.source_product}:"
                    f"{event.source_event_id}:cost-revision:0"
                ),
            )
        )
        if lease_version <= 0:  # defensive against a corrupted legacy row
            raise RetryableUsageIngestError("usage.reservation_fence_unavailable")
        return ReservationUsageEvidence(
            operation_started_at=operation_started_at,
            settlement_binding_id=settlement_binding_id,
        )


__all__ = ["PostgresReservationUsageVerifier"]
