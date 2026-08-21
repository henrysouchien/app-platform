"""Versioned Decimal-only provider rate snapshots and cost calculation."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP, localcontext
from enum import StrEnum
import json
from typing import Annotated, Any, Literal, Mapping

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    TypeAdapter,
    field_validator,
    model_validator,
)

from .models import NonEmptyStr, Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .models import MAX_SIGNED_BIGINT, NonNegativeBigInt


_ZERO = Decimal("0")
_MILLION = Decimal("1000000")
_MICRO_USD = Decimal("1000000")
_AWARE_DATETIME = TypeAdapter(AwareDatetime)
_MAX_RATE_PRECISION = 38
_MAX_RATE_SCALE = 18
_MAX_RATE_INTEGER_DIGITS = 20
_MAX_UNIT_KINDS = 100
_CALCULATION_PRECISION = 128


def validate_rate_decimal(
    value: object, *, positive: bool = False, label: str = "rate decimal"
) -> Decimal:
    """Validate the NUMERIC(38,18)-compatible activated-rate contract."""

    if isinstance(value, Decimal):
        parsed = value
    elif isinstance(value, str):
        parsed = Decimal(value)
    else:
        raise ValueError(f"{label} must be a decimal string")
    if not parsed.is_finite() or parsed < _ZERO or (positive and parsed <= _ZERO):
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{label} must be finite and {qualifier}")
    sign, digits, exponent = parsed.as_tuple()
    del sign
    precision = len(digits)
    scale = max(0, -exponent)
    integer_digits = 1 if parsed == 0 else max(0, parsed.adjusted() + 1)
    if (
        precision > _MAX_RATE_PRECISION
        or scale > _MAX_RATE_SCALE
        or integer_digits > _MAX_RATE_INTEGER_DIGITS
    ):
        raise ValueError(f"{label} exceeds NUMERIC(38,18) bounds")
    return parsed


class PricingState(StrEnum):
    PRICED = "priced"
    UNKNOWN_RATE = "unknown_rate"


class UnknownRateAction(StrEnum):
    BLOCK = "block"
    RECORD = "record"


class RateQuoteOverflowError(ValueError):
    """A deterministic quote exceeds the supported signed ledger range."""


class RateAlias(StrictCommercialModel):
    alias: NonEmptyStr
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None

    @model_validator(mode="after")
    def _ordered(self) -> "RateAlias":
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("rate alias effective range is empty")
        return self


class ProviderRateEntry(StrictCommercialModel):
    canonical_operation: StableCode
    aliases: tuple[RateAlias, ...] = ()
    input_currency_per_million: Decimal = "0"  # type: ignore[assignment]
    output_currency_per_million: Decimal = "0"  # type: ignore[assignment]
    cache_write_currency_per_million: Decimal = "0"  # type: ignore[assignment]
    cache_read_currency_per_million: Decimal = "0"  # type: ignore[assignment]
    batch_multiplier: Decimal = "1"  # type: ignore[assignment]
    unit_currency: dict[StableCode, Decimal] = Field(default_factory=dict)
    reasoning_token_semantics: Literal["observed_subset_of_billable_output"] = (
        "observed_subset_of_billable_output"
    )
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None
    source_reference: NonEmptyStr
    approved_by: NonEmptyStr

    @field_validator(
        "input_currency_per_million",
        "output_currency_per_million",
        "cache_write_currency_per_million",
        "cache_read_currency_per_million",
        "batch_multiplier",
        mode="before",
    )
    @classmethod
    def _decimal_string(cls, value: object) -> Decimal:
        return validate_rate_decimal(value)

    @field_validator("unit_currency", mode="before")
    @classmethod
    def _unit_decimal_strings(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("unit rates must be an object")
        if len(value) > _MAX_UNIT_KINDS:
            raise ValueError("unit rate kinds exceed the bounded maximum")
        parsed: dict[str, Decimal] = {}
        for key, item in value.items():
            parsed[str(key)] = validate_rate_decimal(item, label="unit rate decimal")
        return parsed

    @model_validator(mode="after")
    def _valid_entry(self) -> "ProviderRateEntry":
        if self.batch_multiplier > Decimal("1"):
            raise ValueError("batch multiplier cannot exceed one")
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("rate effective range is empty")
        if not any(
            value > _ZERO
            for value in (
                self.input_currency_per_million,
                self.output_currency_per_million,
                self.cache_write_currency_per_million,
                self.cache_read_currency_per_million,
                *self.unit_currency.values(),
            )
        ):
            raise ValueError("active rate entry cannot price every unit at zero")
        for alias in self.aliases:
            if alias.effective_from < self.effective_from or (
                self.effective_until is not None
                and (alias.effective_until is None or alias.effective_until > self.effective_until)
            ):
                raise ValueError("rate alias must be bounded by its entry")
        return self


class ProviderRateTable(StrictCommercialModel):
    provider: StableCode
    entries: tuple[ProviderRateEntry, ...]

    @model_validator(mode="after")
    def _unique_operations(self) -> "ProviderRateTable":
        operations = [entry.canonical_operation for entry in self.entries]
        if not operations or len(operations) != len(set(operations)):
            raise ValueError("provider rate operations must be non-empty and unique")
        identities: dict[str, list[tuple[datetime, datetime | None]]] = {}
        for entry in self.entries:
            identities.setdefault(entry.canonical_operation, []).append(
                (entry.effective_from, entry.effective_until)
            )
            for alias in entry.aliases:
                identities.setdefault(alias.alias, []).append(
                    (alias.effective_from, alias.effective_until)
                )
        for identity, ranges in identities.items():
            ordered = sorted(ranges, key=lambda item: item[0])
            if any(
                previous[1] is None or current[0] < previous[1]
                for previous, current in zip(ordered, ordered[1:])
            ):
                raise ValueError(f"provider rate identity is ambiguous: {identity}")
        return self


class RateSnapshot(StrictCommercialModel):
    schema_version: Literal[1] = 1
    policy_code: StableCode
    version: NonEmptyStr
    source_policy_content_sha256: Sha256Digest
    currency: Literal["USD"] = "USD"
    source_currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")] = "USD"
    normalization_exchange_rate_to_usd: Decimal = "1"  # type: ignore[assignment]
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None
    providers: tuple[ProviderRateTable, ...]
    unknown_hank_funded_action: Literal[UnknownRateAction.BLOCK] = UnknownRateAction.BLOCK
    unknown_customer_paid_action: UnknownRateAction = UnknownRateAction.RECORD
    customer_paid_work_class_actions: dict[StableCode, UnknownRateAction] = Field(
        default_factory=dict
    )
    content_sha256: Sha256Digest

    @field_validator("normalization_exchange_rate_to_usd", mode="before")
    @classmethod
    def _exchange_decimal_string(cls, value: object) -> Decimal:
        return validate_rate_decimal(
            value, positive=True, label="normalization exchange rate"
        )

    @model_validator(mode="after")
    def _valid_snapshot(self) -> "RateSnapshot":
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("rate snapshot effective range is empty")
        if self.source_currency == "USD" and self.normalization_exchange_rate_to_usd != Decimal("1"):
            raise ValueError("USD rate snapshots require a normalization exchange rate of one")
        names = [provider.provider for provider in self.providers]
        if not names or len(names) != len(set(names)):
            raise ValueError("rate snapshot providers must be non-empty and unique")
        for provider in self.providers:
            for entry in provider.entries:
                if entry.effective_from < self.effective_from or (
                    self.effective_until is not None
                    and (
                        entry.effective_until is None
                        or entry.effective_until > self.effective_until
                    )
                ):
                    raise ValueError("provider rate entry must be bounded by its snapshot")
        body = self.model_dump(mode="python", exclude={"content_sha256"})
        if self.content_sha256 != canonical_sha256(body):
            raise ValueError("rate snapshot digest does not match its immutable facts")
        return self


class RateUsage(StrictCommercialModel):
    uncached_input_tokens: NonNegativeBigInt = 0
    billable_output_tokens: NonNegativeBigInt = 0
    reasoning_tokens_observed: NonNegativeBigInt | None = None
    cache_write_tokens: NonNegativeBigInt = 0
    cache_read_tokens: NonNegativeBigInt = 0
    is_batch: StrictBool = False
    units: dict[StableCode, Decimal] = Field(default_factory=dict)

    @field_validator("units", mode="before")
    @classmethod
    def _decimal_unit_quantities(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("rate usage units must be an object")
        parsed: dict[str, Decimal] = {}
        for key, raw in value.items():
            if isinstance(raw, bool) or not isinstance(raw, (int, str, Decimal)):
                raise ValueError("rate usage unit quantities must be decimal-safe")
            quantity = Decimal(raw) if isinstance(raw, str) else Decimal(str(raw))
            if not quantity.is_finite() or quantity < 0:
                raise ValueError("rate usage unit quantities must be non-negative")
            _, digits, exponent = quantity.as_tuple()
            scale = max(0, -exponent)
            integer_digits = 1 if quantity == 0 else max(0, quantity.adjusted() + 1)
            if len(digits) > 20 or scale > 6 or integer_digits > 14:
                raise ValueError("rate usage unit quantity exceeds NUMERIC(20,6)")
            parsed[str(key)] = quantity
        return parsed

    @model_validator(mode="after")
    def _reasoning_is_observed_subset(self) -> "RateUsage":
        if (
            self.reasoning_tokens_observed is not None
            and self.reasoning_tokens_observed > self.billable_output_tokens
        ):
            raise ValueError(
                "reasoning tokens are an observed subset of billable output"
            )
        return self


class RateQuote(StrictCommercialModel):
    pricing_state: PricingState
    provider: StableCode
    requested_operation: NonEmptyStr
    resolved_operation: StableCode | None = None
    rate_policy_code: StableCode
    rate_version: NonEmptyStr
    exact_cost_usd: Decimal | None = None
    rounded_cost_microusd: NonNegativeBigInt | None = None
    unknown_action: UnknownRateAction | None = None

    @model_validator(mode="after")
    def _coherent_quote(self) -> "RateQuote":
        if self.pricing_state is PricingState.PRICED:
            if (
                self.resolved_operation is None
                or self.exact_cost_usd is None
                or self.rounded_cost_microusd is None
                or self.unknown_action is not None
            ):
                raise ValueError("priced rate quote is incomplete")
        elif (
            self.exact_cost_usd is not None
            or self.rounded_cost_microusd is not None
            or self.unknown_action is None
        ):
            raise ValueError("unknown rate quote cannot contain a cost")
        return self


def build_rate_snapshot(**facts: object) -> RateSnapshot:
    payload = dict(facts)
    payload.setdefault("schema_version", 1)
    payload.setdefault("currency", "USD")
    payload.setdefault("source_currency", "USD")
    payload.setdefault("normalization_exchange_rate_to_usd", "1")
    payload.setdefault("effective_until", None)
    payload.setdefault("unknown_hank_funded_action", UnknownRateAction.BLOCK)
    payload.setdefault("unknown_customer_paid_action", UnknownRateAction.RECORD)
    payload.setdefault("customer_paid_work_class_actions", {})
    payload["effective_from"] = _AWARE_DATETIME.validate_python(payload["effective_from"])
    if payload["effective_until"] is not None:
        payload["effective_until"] = _AWARE_DATETIME.validate_python(
            payload["effective_until"]
        )
    payload["normalization_exchange_rate_to_usd"] = (
        RateSnapshot._exchange_decimal_string(payload["normalization_exchange_rate_to_usd"])
    )
    payload["providers"] = tuple(
        item if isinstance(item, ProviderRateTable) else ProviderRateTable.model_validate(item)
        for item in payload.get("providers", ())  # type: ignore[arg-type]
    )
    payload["content_sha256"] = canonical_sha256(payload)
    return RateSnapshot.model_validate(payload)


def export_rate_snapshot_json(snapshot: RateSnapshot) -> str:
    """Export the exact gateway-facing snapshot with decimal values as strings."""

    return json.dumps(
        snapshot.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def load_rate_snapshot_json(payload: str) -> RateSnapshot:
    """Validate a gateway-facing snapshot and its immutable content digest."""

    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("rate snapshot JSON must be an object")
    return RateSnapshot.model_validate(value)


class PostgresRateSnapshotRepository:
    """Load one activated immutable rate policy without mutating durable facts."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def load_active(
        self, *, policy_id: int, effective_at: datetime
    ) -> RateSnapshot | None:
        if effective_at.tzinfo is None:
            raise ValueError("rate lookup time must be timezone-aware")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT policy_code, version, content_sha256, body_json
                  FROM commercial_policy_versions
                 WHERE id = %s AND policy_kind = 'rate' AND state = 'active'
                """,
                (policy_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if isinstance(row, Mapping):
            policy_code = row["policy_code"]
            version = row["version"]
            content_sha256 = row["content_sha256"]
            raw_body = row["body_json"]
        else:
            policy_code, version, content_sha256, raw_body = row
        body = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
        if not isinstance(body, dict) or canonical_sha256(body) != content_sha256:
            raise ValueError("durable rate policy content hash mismatch")
        if body.get("state") != "active":
            raise ValueError("activated rate policy body is not active")
        facts = {key: value for key, value in body.items() if key != "state"}
        snapshot = build_rate_snapshot(
            policy_code=policy_code,
            version=version,
            source_policy_content_sha256=content_sha256,
            **facts,
        )
        if not _active(snapshot.effective_from, snapshot.effective_until, effective_at):
            return None
        return snapshot


def quote_usage(
    snapshot: RateSnapshot,
    *,
    provider: str,
    operation: str,
    usage: RateUsage,
    occurred_at: datetime,
    payer_class: Literal["customer_paid", "hank_paid", "hank_shadow_priced"],
    work_class: StableCode,
) -> RateQuote:
    if occurred_at.tzinfo is None:
        raise ValueError("usage occurrence time must be timezone-aware")
    entry = _resolve_entry(snapshot, provider=provider, operation=operation, at=occurred_at)
    if entry is None:
        action = _unknown_action(snapshot, payer_class=payer_class, work_class=work_class)
        return RateQuote(
            pricing_state=PricingState.UNKNOWN_RATE,
            provider=provider,
            requested_operation=operation,
            rate_policy_code=snapshot.policy_code,
            rate_version=snapshot.version,
            unknown_action=action,
        )
    unknown_units = set(usage.units) - set(entry.unit_currency)
    if unknown_units:
        return RateQuote(
            pricing_state=PricingState.UNKNOWN_RATE,
            provider=provider,
            requested_operation=operation,
            resolved_operation=entry.canonical_operation,
            rate_policy_code=snapshot.policy_code,
            rate_version=snapshot.version,
            unknown_action=_unknown_action(
                snapshot, payer_class=payer_class, work_class=work_class
            ),
        )
    with localcontext() as context:
        context.prec = _CALCULATION_PRECISION
        token_cost = (
            Decimal(usage.uncached_input_tokens) * entry.input_currency_per_million
            + Decimal(usage.billable_output_tokens) * entry.output_currency_per_million
            + Decimal(usage.cache_write_tokens) * entry.cache_write_currency_per_million
            + Decimal(usage.cache_read_tokens) * entry.cache_read_currency_per_million
        ) / _MILLION
        unit_cost = sum(
            (
                Decimal(quantity) * entry.unit_currency[code]
                for code, quantity in usage.units.items()
            ),
            start=_ZERO,
        )
        exact_source_currency = token_cost * (
            entry.batch_multiplier if usage.is_batch else Decimal("1")
        ) + unit_cost
        exact = (
            exact_source_currency * snapshot.normalization_exchange_rate_to_usd
        )
        rounded = int((exact * _MICRO_USD).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        if rounded > MAX_SIGNED_BIGINT:
            raise RateQuoteOverflowError("rate quote exceeds signed BIGINT ledger capacity")
    return RateQuote(
        pricing_state=PricingState.PRICED,
        provider=provider,
        requested_operation=operation,
        resolved_operation=entry.canonical_operation,
        rate_policy_code=snapshot.policy_code,
        rate_version=snapshot.version,
        exact_cost_usd=exact,
        rounded_cost_microusd=rounded,
    )


def _resolve_entry(
    snapshot: RateSnapshot, *, provider: str, operation: str, at: datetime
) -> ProviderRateEntry | None:
    if at.tzinfo is None or not _active(snapshot.effective_from, snapshot.effective_until, at):
        return None
    table = next((item for item in snapshot.providers if item.provider == provider), None)
    if table is None:
        return None
    matches = []
    for entry in table.entries:
        if not _active(entry.effective_from, entry.effective_until, at):
            continue
        if entry.canonical_operation == operation or any(
            alias.alias == operation
            and _active(alias.effective_from, alias.effective_until, at)
            for alias in entry.aliases
        ):
            matches.append(entry)
    if len(matches) > 1:
        raise ValueError("rate snapshot resolves an ambiguous provider operation")
    return matches[0] if matches else None


def _active(start: datetime, end: datetime | None, at: datetime) -> bool:
    return start <= at and (end is None or at < end)


def _unknown_action(
    snapshot: RateSnapshot, *, payer_class: str, work_class: str
) -> UnknownRateAction:
    if payer_class != "customer_paid":
        return UnknownRateAction.BLOCK
    return snapshot.customer_paid_work_class_actions.get(
        work_class, snapshot.unknown_customer_paid_action
    )


__all__ = [
    "PricingState",
    "PostgresRateSnapshotRepository",
    "ProviderRateEntry",
    "ProviderRateTable",
    "RateAlias",
    "RateQuote",
    "RateQuoteOverflowError",
    "RateSnapshot",
    "RateUsage",
    "UnknownRateAction",
    "build_rate_snapshot",
    "export_rate_snapshot_json",
    "load_rate_snapshot_json",
    "quote_usage",
    "validate_rate_decimal",
]
