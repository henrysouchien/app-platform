"""Authorized, transaction-scoped activation of commercial policy snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import (
    CommercialAction,
    record_change_execution,
)
from .authority_store import PostgresChangeRequestStore, load_named_operator
from .catalog import CommercialCatalogBundle
from .models import NonEmptyStr, StrictCommercialModel, canonical_sha256


class CatalogActivationResult(StrictCommercialModel):
    catalog_identity: NonEmptyStr
    activated_policy_identities: tuple[NonEmptyStr, ...]
    audit_event_id: UUID
    change_request_id: UUID


class DatabaseCursor(Protocol):
    def execute(self, query: str, params: tuple[Any, ...]) -> None: ...

    def fetchone(self) -> Any: ...

    def close(self) -> None: ...


class DatabaseConnection(Protocol):
    autocommit: bool

    def cursor(self) -> DatabaseCursor: ...


def assert_catalog_activatable(bundle: CommercialCatalogBundle) -> None:
    """Reject deployment inputs that are intentionally still marked as draft."""

    bundle.validate_snapshot_coherence()
    bundle.validate()
    if "draft" in bundle.catalog_snapshot.version.lower():
        raise ValueError("draft catalog versions cannot be activated")


def _activation_snapshots(bundle: CommercialCatalogBundle) -> list[Any]:
    return [
        bundle.catalog_snapshot,
        *(
            snapshot
            for snapshot in bundle.policy_snapshots.values()
            if snapshot.policy_kind != "rate"
            or getattr(
                bundle.policy_bodies.get(
                    (snapshot.policy_kind, snapshot.policy_code, snapshot.version)
                ),
                "state",
                None,
            )
            == "active"
        ),
    ]


def catalog_activation_digest(bundle: CommercialCatalogBundle) -> str:
    """Digest the exact ordered identities/content an approval authorizes."""

    assert_catalog_activatable(bundle)
    facts = sorted(
        (
            snapshot.policy_kind,
            snapshot.policy_code,
            snapshot.version,
            snapshot.content_sha256,
        )
        for snapshot in _activation_snapshots(bundle)
    )
    return canonical_sha256({"policy_snapshots": facts})


def _row_values(row: Any) -> tuple[str, Any, str]:
    if isinstance(row, dict):
        return row["content_sha256"], row["body_json"], row["state"]
    return row[0], row[1], row[2]


def _insert_policy_snapshots(
    connection: DatabaseConnection,
    bundle: CommercialCatalogBundle,
    *,
    operator_user_id: int,
) -> tuple[str, ...]:
    identities: list[str] = []
    cursor = connection.cursor()
    try:
        for snapshot in _activation_snapshots(bundle):
            identity = (
                f"{snapshot.policy_kind}:{snapshot.policy_code}:{snapshot.version}"
            )
            identities.append(identity)
            body_json = json.dumps(
                snapshot.body,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            cursor.execute(
                """
                INSERT INTO commercial_policy_versions (
                    policy_kind, policy_code, version, content_sha256,
                    body_json, state, activated_at, created_by
                ) VALUES (%s, %s, %s, %s, %s::jsonb, 'active', NOW(), %s)
                ON CONFLICT (policy_kind, policy_code, version) DO NOTHING
                RETURNING id
                """,
                (
                    snapshot.policy_kind,
                    snapshot.policy_code,
                    snapshot.version,
                    snapshot.content_sha256,
                    body_json,
                    str(operator_user_id),
                ),
            )
            if cursor.fetchone() is not None:
                continue
            cursor.execute(
                """
                SELECT content_sha256, body_json, state
                FROM commercial_policy_versions
                WHERE policy_kind = %s AND policy_code = %s AND version = %s
                """,
                (snapshot.policy_kind, snapshot.policy_code, snapshot.version),
            )
            existing = cursor.fetchone()
            if existing is None:
                raise RuntimeError("policy insert conflict could not be reloaded")
            digest, body, state = _row_values(existing)
            if isinstance(body, str):
                body = json.loads(body)
            if (
                digest != snapshot.content_sha256
                or canonical_sha256(body) != snapshot.content_sha256
                or state != "active"
            ):
                raise ValueError(f"activated policy identity conflict: {identity}")
    finally:
        cursor.close()
    return tuple(identities)


def activate_commercial_catalog(
    connection: DatabaseConnection,
    bundle: CommercialCatalogBundle,
    *,
    change_request_id: UUID,
    operator_user_id: int,
    step_up_event_id: UUID,
    runtime_environment: Literal["dev", "staging", "prod"],
    now: datetime | None = None,
) -> CatalogActivationResult:
    """Activate an approved bundle inside the caller's existing transaction."""

    if getattr(connection, "autocommit", False):
        raise ValueError("catalog activation requires autocommit disabled")
    assert_catalog_activatable(bundle)
    store = PostgresChangeRequestStore(connection)
    request = store.get(change_request_id)
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT environment FROM commercial_deployment_context WHERE singleton"
        )
        deployment_row = cursor.fetchone()
    finally:
        cursor.close()
    deployment_environment = deployment_row[0] if deployment_row else None
    expected_target = (
        f"{bundle.catalog_snapshot.policy_code}:{bundle.catalog_snapshot.version}"
    )
    if (
        request is None
        or deployment_environment != runtime_environment
        or request.environment != runtime_environment
        or request.state != "approved"
        or request.action != CommercialAction.LIVE_POLICY_ACTIVATION
        or request.target_type != "commercial_policy_bundle"
        or request.target_id != expected_target
        or request.payload_sha256 != catalog_activation_digest(bundle)
    ):
        raise ValueError(
            "approved change request does not authorize this policy bundle"
        )
    operator = load_named_operator(
        connection,
        user_id=operator_user_id,
        environment=runtime_environment,
        step_up_event_id=step_up_event_id,
    )

    identities = _insert_policy_snapshots(
        connection,
        bundle,
        operator_user_id=operator.user_id,
    )
    audit_event_id = uuid4()
    insert_commercial_audit_event(
        connection,
        CommercialAuditEvent(
            event_id=audit_event_id,
            actor_type="admin",
            actor_id=str(operator.user_id),
            action="commercial.policy_bundle.activate",
            target_type="commercial_policy_bundle",
            target_id=expected_target,
            reason_code=request.reason_code,
            after={
                "policy_identities": list(identities),
                "policy_count": len(identities),
                "request_id": str(request.request_id),
            },
            request_id=str(request.request_id),
        ),
    )
    record_change_execution(
        request.request_id,
        store=store,
        operator=operator,
        succeeded=True,
        result_code="activated",
        audit_event_id=audit_event_id,
        now=now or datetime.now(timezone.utc),
    )
    return CatalogActivationResult(
        catalog_identity=(
            f"{bundle.catalog_snapshot.policy_code}@{bundle.catalog_snapshot.version}"
        ),
        activated_policy_identities=identities,
        audit_event_id=audit_event_id,
        change_request_id=request.request_id,
    )


__all__ = [
    "CatalogActivationResult",
    "activate_commercial_catalog",
    "assert_catalog_activatable",
    "catalog_activation_digest",
]
