"""Deterministic JSON Schema export for commercial V1 contracts."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pydantic import BaseModel

from .authority_invalidation import CommercialAuthorityInvalidationFeedV1
from .models import (
    BudgetDecisionV1,
    CommercialClaimV1,
    CommercialPolicySnapshotV1,
    UsageAcceptanceV1,
)
from .usage.contract import CommercialUsageEventV1, CommercialUsageEventV2
from .work_authorization import CommercialWorkAuthorizationV1


SCHEMA_BASE_ID = "https://hank.investments/schemas/commercial"
COMMERCIAL_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "commercial-authority-invalidation-feed-v1.schema.json": (
        CommercialAuthorityInvalidationFeedV1
    ),
    "commercial-claim.schema.json": CommercialClaimV1,
    "commercial-usage-event.schema.json": CommercialUsageEventV1,
    "commercial-usage-event-v2.schema.json": CommercialUsageEventV2,
    "commercial-usage-acceptance.schema.json": UsageAcceptanceV1,
    "commercial-budget-decision.schema.json": BudgetDecisionV1,
    "commercial-policy-snapshot.schema.json": CommercialPolicySnapshotV1,
    "commercial-work-authorization.schema.json": CommercialWorkAuthorizationV1,
}


def commercial_schema_document(filename: str, model: type[BaseModel]) -> dict[str, Any]:
    schema = model.model_json_schema(mode="validation", ref_template="#/$defs/{model}")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{SCHEMA_BASE_ID}/{filename}",
        **schema,
    }


def iter_commercial_schema_documents() -> Iterator[tuple[str, dict[str, Any]]]:
    for filename, model in COMMERCIAL_SCHEMA_MODELS.items():
        yield filename, commercial_schema_document(filename, model)


__all__ = [
    "COMMERCIAL_SCHEMA_MODELS",
    "SCHEMA_BASE_ID",
    "commercial_schema_document",
    "iter_commercial_schema_documents",
]
