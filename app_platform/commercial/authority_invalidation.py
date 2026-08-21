"""Durable resumable commercial authority invalidation feed."""

from __future__ import annotations

import json
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from .models import AdditiveResponseCommercialModel, StrictCommercialModel


AUTHORITY_INVALIDATION_CHANNEL = "commercial_authority_invalidation"
_EVENT_CORE_FIELDS = frozenset(
    {
        "sequence_id",
        "environment",
        "kind",
        "commercial_account_id",
        "entitlement_revision",
        "context_id",
        "token_id",
        "occurred_at",
    }
)


class CommercialAuthorityInvalidationCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    kind: Literal["context", "token", "entitlement", "agreement", "emergency"]
    commercial_account_id: int = Field(gt=0)
    entitlement_revision: int = Field(gt=0)
    context_id: UUID | None = None
    token_id: UUID | None = None

    @model_validator(mode="after")
    def _identity(self):
        if self.kind == "context" and self.context_id is None:
            raise ValueError("context invalidation requires context identity")
        if self.kind == "token" and self.token_id is None:
            raise ValueError("token invalidation requires token identity")
        return self


class CommercialAuthorityInvalidationEventV1(AdditiveResponseCommercialModel):
    __pydantic_extra__: dict[str, JsonValue] = Field(init=False)
    sequence_id: int = Field(gt=0)
    environment: Literal["dev", "staging", "prod"]
    kind: Literal["context", "token", "entitlement", "agreement", "emergency"]
    commercial_account_id: int = Field(gt=0)
    entitlement_revision: int = Field(gt=0)
    context_id: UUID | None
    token_id: UUID | None
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def _identity(self):
        if self.kind == "context" and self.context_id is None:
            raise ValueError("context invalidation requires context identity")
        if self.kind == "token" and self.token_id is None:
            raise ValueError("token invalidation requires token identity")
        return self


class CommercialAuthorityInvalidationFeedV1(AdditiveResponseCommercialModel):
    __pydantic_extra__: dict[str, JsonValue] = Field(init=False)
    schema_version: Literal[1]
    events: tuple[CommercialAuthorityInvalidationEventV1, ...]
    next_sequence: int = Field(ge=0)
    high_water_sequence: int = Field(ge=0)


def publish_authority_invalidation(
    connection: Any,
    command: CommercialAuthorityInvalidationCommand,
) -> CommercialAuthorityInvalidationEventV1:
    payload = command.model_dump(mode="json", exclude_none=True)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO commercial_authority_invalidations (
                environment, invalidation_kind, commercial_account_id,
                entitlement_revision, context_id, token_id, payload_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            RETURNING sequence_id, occurred_at
            """,
            (
                command.environment,
                command.kind,
                command.commercial_account_id,
                command.entitlement_revision,
                str(command.context_id) if command.context_id else None,
                str(command.token_id) if command.token_id else None,
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
            ),
        )
        sequence_id, occurred_at = cursor.fetchone()
        delivered = CommercialAuthorityInvalidationEventV1(
            sequence_id=int(sequence_id),
            occurred_at=occurred_at,
            **command.model_dump(mode="python"),
        )
        cursor.execute(
            "SELECT pg_notify(%s, %s)",
            (
                AUTHORITY_INVALIDATION_CHANNEL,
                delivered.model_dump_json(exclude_none=True),
            ),
        )
    return delivered


def read_authority_invalidations(
    connection: Any,
    *,
    environment: Literal["dev", "staging", "prod"],
    after_sequence: int,
    limit: int = 100,
) -> tuple[CommercialAuthorityInvalidationEventV1, ...]:
    if after_sequence < 0 or not 1 <= limit <= 1000:
        raise ValueError("invalidation cursor bounds are invalid")
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT sequence_id, environment, invalidation_kind,
                   commercial_account_id, entitlement_revision,
                   context_id, token_id, occurred_at, payload_json
              FROM commercial_authority_invalidations
             WHERE environment = %s AND sequence_id > %s
             ORDER BY sequence_id LIMIT %s
            """,
            (environment, after_sequence, limit),
        )
        rows = cursor.fetchall()
    return tuple(
        CommercialAuthorityInvalidationEventV1(
            **_non_core_payload(row[8]),
            sequence_id=int(row[0]),
            environment=row[1],
            kind=row[2],
            commercial_account_id=int(row[3]),
            entitlement_revision=int(row[4]),
            context_id=UUID(str(row[5])) if row[5] else None,
            token_id=UUID(str(row[6])) if row[6] else None,
            occurred_at=row[7],
        )
        for row in rows
    )


def _non_core_payload(stored_payload: Any) -> dict[str, Any]:
    if isinstance(stored_payload, str):
        stored_payload = json.loads(stored_payload)
    if not isinstance(stored_payload, dict):
        raise ValueError("stored invalidation payload must be a JSON object")
    return {
        key: value
        for key, value in stored_payload.items()
        if key not in _EVENT_CORE_FIELDS
    }


__all__ = [
    "AUTHORITY_INVALIDATION_CHANNEL",
    "CommercialAuthorityInvalidationCommand",
    "CommercialAuthorityInvalidationEventV1",
    "CommercialAuthorityInvalidationFeedV1",
    "publish_authority_invalidation",
    "read_authority_invalidations",
]
