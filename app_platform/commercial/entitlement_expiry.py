"""Time-fenced account entitlement expiry projection."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import AwareDatetime, Field, StrictInt

from .entitlement_store import (
    AccountProjectionRequest,
    EntitlementExpiryFence,
    EntitlementProjectionFenceSuperseded,
    persist_account_entitlements,
)
from .flags import CommercialFlags
from .models import StrictCommercialModel


PositiveInt = Annotated[StrictInt, Field(gt=0)]


class EntitlementExpiryCandidate(StrictCommercialModel):
    commercial_account_id: PositiveInt
    observed_revision: PositiveInt
    observed_boundary_at: AwareDatetime


class EntitlementExpiryResult(StrictCommercialModel):
    commercial_account_id: PositiveInt
    disposition: str
    revision: PositiveInt | None = None
    changed: bool = False


class PostgresEntitlementExpiryProtocol:
    """Find and reproject account revisions whose active facts crossed an end boundary."""

    def __init__(self, connection: object, *, flags: CommercialFlags, clock) -> None:
        self._connection = connection
        self._flags = flags
        self._clock = clock

    def find_due(
        self, *, partition: str, limit: int
    ) -> tuple[EntitlementExpiryCandidate, ...]:
        if not partition.isdigit() or partition.startswith("0") or len(partition) > 16:
            raise ValueError("entitlement expiry partition is invalid")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("entitlement expiry limit is invalid")
        now = self._now()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial.entitlement.expiry:{partition}",),
            )
            if not bool(cursor.fetchone()[0]):
                self._connection.rollback()  # type: ignore[attr-defined]
                return ()
            cursor.execute(
                """
                SELECT entitlement.commercial_account_id, revision.revision,
                       MIN(entitlement.effective_until) AS boundary_at
                  FROM commercial_entitlements entitlement
                  JOIN commercial_entitlement_revisions revision
                    ON revision.commercial_account_id = entitlement.commercial_account_id
                   AND revision.revision = entitlement.entitlement_revision
                 WHERE entitlement.status = 'active'
                   AND entitlement.effective_until IS NOT NULL
                   AND entitlement.effective_until <= %s
                 GROUP BY entitlement.commercial_account_id, revision.revision
                 ORDER BY boundary_at, entitlement.commercial_account_id
                 LIMIT %s
                """,
                (now, limit),
            )
            rows = cursor.fetchall()
            self._connection.commit()  # type: ignore[attr-defined]
            return tuple(
                EntitlementExpiryCandidate(
                    commercial_account_id=row[0],
                    observed_revision=row[1],
                    observed_boundary_at=row[2],
                )
                for row in rows
            )
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def expire(self, candidate: EntitlementExpiryCandidate) -> EntitlementExpiryResult:
        now = self._now()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            projection = persist_account_entitlements(
                self._connection,
                flags=self._flags,
                request=AccountProjectionRequest(
                    commercial_account_id=candidate.commercial_account_id,
                    projected_at=now,
                ),
                expiry_fence=EntitlementExpiryFence(
                    observed_revision=candidate.observed_revision,
                    observed_boundary_at=candidate.observed_boundary_at,
                ),
            )
            self._connection.commit()  # type: ignore[attr-defined]
            return EntitlementExpiryResult(
                commercial_account_id=candidate.commercial_account_id,
                disposition="projected",
                revision=projection.revision,
                changed=projection.changed,
            )
        except EntitlementProjectionFenceSuperseded:
            self._connection.rollback()  # type: ignore[attr-defined]
            return EntitlementExpiryResult(
                commercial_account_id=candidate.commercial_account_id,
                disposition="superseded",
            )
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("entitlement expiry clock must be aware")
        return now


__all__ = [
    "EntitlementExpiryCandidate",
    "EntitlementExpiryResult",
    "PostgresEntitlementExpiryProtocol",
]
