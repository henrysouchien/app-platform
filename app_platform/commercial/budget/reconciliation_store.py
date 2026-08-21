"""Read one Redis commercial-budget generation as an atomic manifest."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from pydantic import Field, StrictInt

from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel, canonical_sha256
from .redis_store import MAX_SAFE_REDIS_INTEGER, CommercialReservationRedisError


SafePositiveInt = Annotated[StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)]


class BudgetRedisManifestObservation(StrictCommercialModel):
    agreement_terms_id: SafePositiveInt
    budget_period_id: SafePositiveInt
    candidate_generation: SafePositiveInt
    observed_generation: SafePositiveInt | None
    pointer: dict[str, str]
    generation_metadata: dict[str, str]
    active_reservations: str | None
    late_child_consumed_microusd: str | None
    policy: dict[str, str]
    buckets: dict[str, str | None]
    reservations: dict[str, dict[str, str]]
    snapshot_sha256: Sha256Digest


class CommercialBudgetReconciliationRedisUnstable(
    CommercialReservationRedisError
):
    """The stable pointer changed too often to bind one manifest safely."""


class CommercialBudgetReconciliationRedisStore:
    """Observe one hash-slot with MULTI/EXEC so no mixed manifest is returned."""

    def __init__(self, client: Any, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
            and flags.commercial_budget_reconciliation_enabled
        ):
            raise CommercialReservationRedisError(
                "budget reconciliation requires enforcement mode"
            )
        self._client = client

    def observe(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        expected_generation: int,
        reservation_ids: tuple[UUID, ...],
    ) -> BudgetRedisManifestObservation:
        if (
            min(agreement_terms_id, period_id, expected_generation) <= 0
            or expected_generation > MAX_SAFE_REDIS_INTEGER
            or len(reservation_ids) != len(set(reservation_ids))
        ):
            raise ValueError("budget reconciliation manifest identity is invalid")
        ordered_ids = tuple(sorted(reservation_ids, key=str))
        pointer_key = self._pointer_key(agreement_terms_id, period_id)
        try:
            pointer_generation = self._client.hget(pointer_key, "generation")
            candidate = _canonical_positive(pointer_generation) or expected_generation
            values: list[Any] | tuple[Any, ...] = ()
            # A legitimate writer is serialized by PostgreSQL, but retrying here also
            # gives a coherent result if an out-of-band actor changes the pointer.
            stable = False
            for attempt in range(3):
                keys = self._manifest_keys(
                    agreement_terms_id,
                    period_id,
                    candidate,
                    ordered_ids,
                )
                pipeline = self._client.pipeline(transaction=True)
                pipeline.hgetall(pointer_key)
                pipeline.hgetall(keys[0])
                pipeline.get(keys[1])
                pipeline.get(keys[2])
                pipeline.hgetall(keys[3])
                pipeline.get(keys[4])
                pipeline.get(keys[5])
                for key in keys[6:]:
                    pipeline.hgetall(key)
                values = pipeline.execute()
                pointer = _hash(values[0])
                observed = _canonical_positive(pointer.get("generation"))
                if observed is None or observed == candidate:
                    stable = True
                    break
                if attempt < 2:
                    candidate = observed
            if not stable:
                raise CommercialBudgetReconciliationRedisUnstable(
                    "budget reconciliation Redis generation is unstable"
                )
        except CommercialBudgetReconciliationRedisUnstable:
            raise
        except Exception as error:
            raise CommercialReservationRedisError(
                "budget reconciliation Redis manifest is unavailable"
            ) from error

        pointer = _hash(values[0])
        reservations = {
            str(identity): _hash(raw)
            for identity, raw in zip(ordered_ids, values[7:], strict=True)
        }
        body = {
            "schema": "commercial.budget.redis-observation.v1",
            "agreement_terms_id": agreement_terms_id,
            "budget_period_id": period_id,
            "candidate_generation": candidate,
            "pointer": pointer,
            "generation_metadata": _hash(values[1]),
            "active_reservations": _text(values[2]),
            "late_child_consumed_microusd": _text(values[3]),
            "policy": _hash(values[4]),
            "buckets": {
                "model": _text(values[5]),
                "technical": _text(values[6]),
            },
            "reservations": reservations,
        }
        return BudgetRedisManifestObservation(
            agreement_terms_id=agreement_terms_id,
            budget_period_id=period_id,
            candidate_generation=candidate,
            observed_generation=_canonical_positive(pointer.get("generation")),
            pointer=pointer,
            generation_metadata=body["generation_metadata"],
            active_reservations=body["active_reservations"],
            late_child_consumed_microusd=body["late_child_consumed_microusd"],
            policy=body["policy"],
            buckets=body["buckets"],
            reservations=reservations,
            snapshot_sha256=canonical_sha256(body),
        )

    @staticmethod
    def _pointer_key(agreement_terms_id: int, period_id: int) -> str:
        tag = f"commercial:enforce:{agreement_terms_id}:{period_id}"
        return f"budget:spend:v2:{{{tag}}}:generation"

    @staticmethod
    def _manifest_keys(
        agreement_terms_id: int,
        period_id: int,
        generation: int,
        reservation_ids: tuple[UUID, ...],
    ) -> tuple[str, ...]:
        tag = f"commercial:enforce:{agreement_terms_id}:{period_id}"
        prefix = f"budget:spend:v2:{{{tag}}}:g{generation}"
        return (
            f"{prefix}:generation",
            f"{prefix}:active",
            f"{prefix}:late-child-used",
            f"{prefix}:policy",
            f"{prefix}:bucket:model",
            f"{prefix}:bucket:technical",
            *(f"{prefix}:reservation:{identity}" for identity in reservation_ids),
        )


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return "hex:" + value.hex()
    if isinstance(value, str):
        return value
    return str(value)


def _hash(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple)) and len(value) % 2 == 0:
        items = zip(value[::2], value[1::2], strict=True)
    else:
        return {"__malformed__": _text(value) or "null"}
    normalized: dict[str, str] = {}
    for key, item in items:
        normalized[_text(key) or "null"] = _text(item) or "null"
    return dict(sorted(normalized.items()))


def _canonical_positive(value: Any) -> int | None:
    raw = _text(value)
    if (
        raw is None
        or not raw.isdigit()
        or raw.startswith("0")
        or len(raw) > len(str(MAX_SAFE_REDIS_INTEGER))
        or (
            len(raw) == len(str(MAX_SAFE_REDIS_INTEGER))
            and raw > str(MAX_SAFE_REDIS_INTEGER)
        )
    ):
        return None
    return int(raw)
