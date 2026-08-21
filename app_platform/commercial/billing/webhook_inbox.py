"""Verified raw-byte Stripe webhook receipt into the durable commercial inbox."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Literal, TypeVar

from pydantic import Field, StrictBool, StrictInt
from psycopg2 import Error as PostgresError

from ..models import MAX_SIGNED_BIGINT, MIN_SIGNED_BIGINT, StrictCommercialModel
from .stripe_config import (
    STRIPE_API_VERSION,
    STRIPE_SDK_VERSION,
    StripeConfigurationError,
    StripeRuntimeConfiguration,
    validate_stripe_runtime_configuration,
)


STRIPE_WEBHOOK_TOLERANCE_SECONDS = 300
MAX_STRIPE_WEBHOOK_PAYLOAD_BYTES = 1_000_000
MAX_STRIPE_SIGNATURE_HEADER_BYTES = 16_384
_STRIPE_EVENT_ID = re.compile(r"^evt_[A-Za-z0-9]{6,251}$")
_STRIPE_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9._]{0,254}$")
_STRIPE_API_VERSION = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[a-z]+$")
_MAX_TIMESTAMP_EPOCH = 253_402_300_799
_ResultT = TypeVar("_ResultT")


class StripeWebhookErrorCode(StrEnum):
    INVALID_REQUEST = "stripe_webhook_invalid_request"
    INVALID_SIGNATURE = "stripe_webhook_invalid_signature"
    SIGNATURE_TIMESTAMP_OUTSIDE_TOLERANCE = (
        "stripe_webhook_signature_timestamp_outside_tolerance"
    )
    INVALID_EVENT = "stripe_webhook_invalid_event"
    ENVIRONMENT_MISMATCH = "stripe_webhook_environment_mismatch"


class StripeWebhookVerificationError(ValueError):
    """Safe verification failure that never carries raw payload or signature data."""

    def __init__(self, code: StripeWebhookErrorCode) -> None:
        self.code = code
        super().__init__("Stripe webhook verification failed")


class StripeWebhookPersistenceError(RuntimeError):
    """Payload-free durable-receipt failure safe for transport handling and logs."""

    code = "stripe_webhook_persistence_failed"
    public_message = "Stripe webhook receipt is temporarily unavailable."
    retryable = True

    def __init__(self) -> None:
        super().__init__(self.public_message)

    def to_public_payload(self, *, request_id: str | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "message": self.public_message,
            "retryable": self.retryable,
        }
        if request_id is not None:
            payload["request_id"] = request_id
        return payload


@dataclass(frozen=True, slots=True)
class VerifiedStripeWebhook:
    environment: Literal["test", "live"]
    external_event_id: str
    event_type: str
    event_api_version: str
    event_created_at: datetime
    livemode: bool
    payload_sha256: str
    payload_json_text: str = field(repr=False)
    raw_payload_bytes: int
    signature_timestamp_at: datetime
    signature_header_sha256: str
    supported_api_version: bool


class StripeWebhookReceiptResult(StrictCommercialModel):
    webhook_event_id: StrictInt = Field(gt=0)
    disposition: Literal["accepted", "duplicate", "conflict"]
    integrity_state: Literal["verified", "quarantined"]
    processing_state: Literal[
        "received", "processing", "applied", "ignored", "retryable", "dead"
    ]
    conflict_id: StrictInt | None = Field(default=None, gt=0)
    supported_api_version: StrictBool
    durable_replayed: StrictBool = False


def _row_value(row: object, index: int, name: str) -> Any:
    if isinstance(row, Mapping):
        return row[name]
    return row[index]  # type: ignore[index]


def _verification_failure(
    code: StripeWebhookErrorCode,
) -> StripeWebhookVerificationError:
    return StripeWebhookVerificationError(code)


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)
        result[key] = value
    return result


def _reject_non_json_constant(_: str) -> None:
    raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)


def _strict_json_int(value: str) -> int:
    parsed = int(value)
    if not MIN_SIGNED_BIGINT <= parsed <= MAX_SIGNED_BIGINT:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)
    return parsed


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)
    return parsed


def _signature_timestamp(signature_header: str) -> int:
    timestamps: list[str] = []
    has_v1 = False
    for component in signature_header.split(","):
        key, separator, value = component.partition("=")
        if not separator or not key or not value:
            raise _verification_failure(StripeWebhookErrorCode.INVALID_SIGNATURE)
        if key == "t":
            timestamps.append(value)
        elif key == "v1":
            has_v1 = True
    if len(timestamps) != 1 or not has_v1:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_SIGNATURE)
    try:
        timestamp = int(timestamps[0])
    except ValueError:
        raise _verification_failure(
            StripeWebhookErrorCode.INVALID_SIGNATURE
        ) from None
    if timestamp <= 0 or timestamp > _MAX_TIMESTAMP_EPOCH:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_SIGNATURE)
    return timestamp


def _aware_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Stripe webhook verification clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def verify_stripe_webhook(
    *,
    raw_payload: bytes,
    signature_header: str,
    configuration: StripeRuntimeConfiguration,
    now_at: datetime | None = None,
) -> VerifiedStripeWebhook:
    """Verify exact request bytes and return only signed, environment-bound facts."""

    validate_stripe_runtime_configuration(configuration)
    if type(raw_payload) is not bytes or not raw_payload:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_REQUEST)
    if len(raw_payload) > MAX_STRIPE_WEBHOOK_PAYLOAD_BYTES:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_REQUEST)
    if type(signature_header) is not str or not signature_header:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_REQUEST)
    try:
        signature_header_bytes = signature_header.encode("ascii")
    except UnicodeEncodeError:
        raise _verification_failure(
            StripeWebhookErrorCode.INVALID_SIGNATURE
        ) from None
    if len(signature_header_bytes) > MAX_STRIPE_SIGNATURE_HEADER_BYTES:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_REQUEST)
    try:
        decoded = raw_payload.decode("utf-8")
    except UnicodeDecodeError:
        raise _verification_failure(
            StripeWebhookErrorCode.INVALID_SIGNATURE
        ) from None

    signature_epoch = _signature_timestamp(signature_header)
    verified_at = _aware_utc(now_at)

    try:
        import stripe
    except ImportError:
        raise StripeConfigurationError("Stripe SDK is unavailable") from None

    if stripe.VERSION != STRIPE_SDK_VERSION:
        raise StripeConfigurationError(
            "installed Stripe SDK version does not match pin"
        )
    try:
        stripe.WebhookSignature.verify_header(
            decoded,
            signature_header,
            configuration.webhook_signing_secret.get_secret_value(),
            tolerance=None,
        )
    except stripe.error.SignatureVerificationError:
        raise _verification_failure(
            StripeWebhookErrorCode.INVALID_SIGNATURE
        ) from None
    if abs(verified_at.timestamp() - signature_epoch) > (
        STRIPE_WEBHOOK_TOLERANCE_SECONDS
    ):
        raise _verification_failure(
            StripeWebhookErrorCode.SIGNATURE_TIMESTAMP_OUTSIDE_TOLERANCE
        )

    try:
        payload = json.loads(
            decoded,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_non_json_constant,
            parse_float=_strict_json_float,
            parse_int=_strict_json_int,
        )
    except StripeWebhookVerificationError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT) from None
    if not isinstance(payload, dict):
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)

    external_event_id = payload.get("id")
    event_type = payload.get("type")
    event_api_version = payload.get("api_version")
    event_created_epoch = payload.get("created")
    livemode = payload.get("livemode")
    if (
        payload.get("object") != "event"
        or not isinstance(external_event_id, str)
        or _STRIPE_EVENT_ID.fullmatch(external_event_id) is None
        or not isinstance(event_type, str)
        or _STRIPE_EVENT_TYPE.fullmatch(event_type) is None
        or not isinstance(event_api_version, str)
        or _STRIPE_API_VERSION.fullmatch(event_api_version) is None
        or type(event_created_epoch) is not int
        or event_created_epoch < 0
        or type(livemode) is not bool
        or not isinstance(payload.get("data"), dict)
    ):
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)
    try:
        event_created_at = datetime.fromtimestamp(
            event_created_epoch, tz=timezone.utc
        )
    except (OverflowError, OSError, ValueError):
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT) from None
    if event_created_at > verified_at.replace(microsecond=0) + _FIVE_MINUTES:
        raise _verification_failure(StripeWebhookErrorCode.INVALID_EVENT)

    environment: Literal["test", "live"] = "live" if livemode else "test"
    if environment != configuration.deployment.billing_environment:
        raise _verification_failure(StripeWebhookErrorCode.ENVIRONMENT_MISMATCH)
    return VerifiedStripeWebhook(
        environment=environment,
        external_event_id=external_event_id,
        event_type=event_type,
        event_api_version=event_api_version,
        event_created_at=event_created_at,
        livemode=livemode,
        payload_sha256="sha256:" + hashlib.sha256(raw_payload).hexdigest(),
        payload_json_text=decoded,
        raw_payload_bytes=len(raw_payload),
        signature_timestamp_at=datetime.fromtimestamp(
            signature_epoch, tz=timezone.utc
        ),
        signature_header_sha256=(
            "sha256:" + hashlib.sha256(signature_header_bytes).hexdigest()
        ),
        supported_api_version=event_api_version == STRIPE_API_VERSION,
    )


_FIVE_MINUTES = timedelta(minutes=5)


class PostgresStripeWebhookInbox:
    """Classify a delivery atomically inside the caller-owned transaction.

    The transport caller must commit the outer transaction before acknowledging Stripe.
    """

    def __init__(
        self,
        connection: object,
        *,
        configuration: StripeRuntimeConfiguration,
    ) -> None:
        validate_stripe_runtime_configuration(configuration)
        self._connection = connection
        self._configuration = configuration

    def receive(
        self,
        *,
        raw_payload: bytes,
        signature_header: str,
    ) -> StripeWebhookReceiptResult:
        self._require_transaction()
        verified = verify_stripe_webhook(
            raw_payload=raw_payload,
            signature_header=signature_header,
            configuration=self._configuration,
        )
        persistence_error: StripeWebhookPersistenceError | None = None
        result: StripeWebhookReceiptResult | None = None
        try:
            result = self._run_atomic(lambda: self._receive_verified(verified))
        except PostgresError:
            persistence_error = StripeWebhookPersistenceError()
        if persistence_error is not None:
            # Raise after leaving the psycopg exception context so raw DETAIL/query data
            # is not reachable through __cause__, __context__, or traceback chaining.
            # Scrub this frame too: error reporters commonly capture frame locals.
            del raw_payload, signature_header, verified, result, self
            raise persistence_error from None
        if result is None:
            raise RuntimeError("Stripe webhook receipt returned no result")
        return result

    def _receive_verified(
        self, event: VerifiedStripeWebhook
    ) -> StripeWebhookReceiptResult:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_webhook_events (
                    provider, environment, external_event_id, event_type,
                    event_api_version, event_created_at, livemode,
                    payload_sha256, payload_json, raw_payload_bytes,
                    signature_timestamp_at, signature_header_sha256
                ) VALUES (
                    'stripe', %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s
                )
                ON CONFLICT (provider, environment, external_event_id) DO NOTHING
                RETURNING id
                """,
                (
                    event.environment,
                    event.external_event_id,
                    event.event_type,
                    event.event_api_version,
                    event.event_created_at,
                    event.livemode,
                    event.payload_sha256,
                    event.payload_json_text,
                    event.raw_payload_bytes,
                    event.signature_timestamp_at,
                    event.signature_header_sha256,
                ),
            )
            inserted = cursor.fetchone()
            if inserted is not None:
                webhook_event_id = int(_row_value(inserted, 0, "id"))
                processing_state = "received"
                if not event.supported_api_version:
                    cursor.execute(
                        """
                        UPDATE commercial_webhook_events
                           SET processing_state = 'dead',
                               last_error_code = 'stripe.unsupported_api_version'
                         WHERE id = %s
                        """,
                        (webhook_event_id,),
                    )
                    processing_state = "dead"
                return StripeWebhookReceiptResult(
                    webhook_event_id=webhook_event_id,
                    disposition="accepted",
                    integrity_state="verified",
                    processing_state=processing_state,
                    supported_api_version=event.supported_api_version,
                )

            cursor.execute(
                """
                SELECT id, payload_sha256, integrity_state, processing_state,
                       event_api_version
                  FROM commercial_webhook_events
                 WHERE provider = 'stripe' AND environment = %s
                   AND external_event_id = %s
                 FOR UPDATE
                """,
                (event.environment, event.external_event_id),
            )
            canonical = cursor.fetchone()
            if canonical is None:
                raise RuntimeError("Stripe webhook identity conflict disappeared")
            webhook_event_id = int(_row_value(canonical, 0, "id"))
            if _row_value(canonical, 1, "payload_sha256") == event.payload_sha256:
                return StripeWebhookReceiptResult(
                    webhook_event_id=webhook_event_id,
                    disposition="duplicate",
                    integrity_state=_row_value(canonical, 2, "integrity_state"),
                    processing_state=_row_value(canonical, 3, "processing_state"),
                    supported_api_version=(
                        _row_value(canonical, 4, "event_api_version")
                        == STRIPE_API_VERSION
                    ),
                    durable_replayed=True,
                )

            cursor.execute(
                """
                INSERT INTO commercial_webhook_event_conflicts (
                    webhook_event_id, provider, environment, external_event_id,
                    observed_event_type, observed_event_api_version,
                    observed_event_created_at, observed_livemode,
                    observed_payload_sha256, observed_payload_json,
                    observed_raw_payload_bytes, observed_signature_timestamp_at,
                    observed_signature_header_sha256
                ) VALUES (
                    %s, 'stripe', %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s
                )
                ON CONFLICT (webhook_event_id, observed_payload_sha256) DO NOTHING
                RETURNING id
                """,
                (
                    webhook_event_id,
                    event.environment,
                    event.external_event_id,
                    event.event_type,
                    event.event_api_version,
                    event.event_created_at,
                    event.livemode,
                    event.payload_sha256,
                    event.payload_json_text,
                    event.raw_payload_bytes,
                    event.signature_timestamp_at,
                    event.signature_header_sha256,
                ),
            )
            conflict = cursor.fetchone()
            durable_replayed = conflict is None
            if conflict is None:
                cursor.execute(
                    """
                    SELECT id FROM commercial_webhook_event_conflicts
                     WHERE webhook_event_id = %s AND observed_payload_sha256 = %s
                    """,
                    (webhook_event_id, event.payload_sha256),
                )
                conflict = cursor.fetchone()
            if conflict is None:
                raise RuntimeError("Stripe webhook conflict evidence disappeared")
            cursor.execute(
                """
                SELECT integrity_state, processing_state
                  FROM commercial_webhook_events WHERE id = %s
                """,
                (webhook_event_id,),
            )
            state = cursor.fetchone()
            if state is None:
                raise RuntimeError("Stripe webhook canonical event disappeared")
            return StripeWebhookReceiptResult(
                webhook_event_id=webhook_event_id,
                disposition="conflict",
                integrity_state=_row_value(state, 0, "integrity_state"),
                processing_state=_row_value(state, 1, "processing_state"),
                conflict_id=int(_row_value(conflict, 0, "id")),
                supported_api_version=event.supported_api_version,
                durable_replayed=durable_replayed,
            )
        finally:
            cursor.close()

    def _run_atomic(self, operation: Callable[[], _ResultT]) -> _ResultT:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_webhook_receipt")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_webhook_receipt")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_webhook_receipt")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_webhook_receipt")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe webhook receipt requires a transaction")


__all__ = [
    "MAX_STRIPE_SIGNATURE_HEADER_BYTES",
    "MAX_STRIPE_WEBHOOK_PAYLOAD_BYTES",
    "PostgresStripeWebhookInbox",
    "STRIPE_WEBHOOK_TOLERANCE_SECONDS",
    "StripeWebhookErrorCode",
    "StripeWebhookPersistenceError",
    "StripeWebhookReceiptResult",
    "StripeWebhookVerificationError",
    "VerifiedStripeWebhook",
    "verify_stripe_webhook",
]
