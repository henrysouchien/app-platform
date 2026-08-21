"""Typed commercial account and membership records."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, Field, JsonValue, StrictInt, StrictStr

from .models import NonEmptyStr, StrictCommercialModel


class CommercialAccountKind(StrEnum):
    INDIVIDUAL = "individual"
    FIRM = "firm"


class CommercialAccountState(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class CommercialMemberRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    BILLING = "billing"
    MEMBER = "member"


class CommercialMemberState(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REMOVED = "removed"


class CommercialAccountRecord(StrictCommercialModel):
    id: Annotated[StrictInt, Field(gt=0)]
    public_id: UUID
    kind: CommercialAccountKind
    display_name: NonEmptyStr
    state: CommercialAccountState
    billing_currency: Annotated[StrictStr, Field(pattern=r"^[A-Z]{3}$")]
    display_timezone: NonEmptyStr
    metadata: dict[str, JsonValue]
    created_at: AwareDatetime
    updated_at: AwareDatetime


class CommercialMembershipRecord(StrictCommercialModel):
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    user_id: Annotated[StrictInt, Field(gt=0)]
    role: CommercialMemberRole
    state: CommercialMemberState
    joined_at: AwareDatetime | None
    created_at: AwareDatetime
    updated_at: AwareDatetime


class VisibleCommercialAccount(StrictCommercialModel):
    account: CommercialAccountRecord
    membership: CommercialMembershipRecord


__all__ = [
    "CommercialAccountKind",
    "CommercialAccountRecord",
    "CommercialAccountState",
    "CommercialMemberRole",
    "CommercialMembershipRecord",
    "CommercialMemberState",
    "VisibleCommercialAccount",
]
