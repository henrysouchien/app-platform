"""HMAC authentication and durable replay protection for usage ingestion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
from typing import Callable, Mapping, Protocol


INGEST_PATH = "/internal/commercial/usage-events:batch"
RECONCILIATION_INGEST_PATH = "/internal/commercial/usage-reconciliation:batch"
_KEY_ID = re.compile(r"^[a-zA-Z0-9._:-]{1,128}$")
_NONCE = re.compile(r"^[a-zA-Z0-9._:-]{1,128}$")
_ENVIRONMENTS = frozenset({"dev", "staging", "prod"})


class UsageIngestAuthenticationError(ValueError):
    """Terminal authentication failure with a stable, non-secret reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class CommercialUsageProducerKey:
    key_id: str
    secret: bytes = field(repr=False)
    environment: str
    source_products: tuple[str, ...]
    active_from: datetime
    active_until: datetime | None = None

    def __post_init__(self) -> None:
        if (
            not _KEY_ID.fullmatch(self.key_id)
            or not isinstance(self.secret, bytes)
            or len(self.secret) < 32
            or self.environment not in _ENVIRONMENTS
            or not self.source_products
            or len(set(self.source_products)) != len(self.source_products)
            or any(not _KEY_ID.fullmatch(item) for item in self.source_products)
            or self.active_from.tzinfo is None
            or (self.active_until is not None and self.active_until.tzinfo is None)
            or (self.active_until is not None and self.active_until <= self.active_from)
        ):
            raise ValueError("commercial usage producer key configuration is invalid")


@dataclass(frozen=True)
class AuthenticatedUsageProducer:
    key_id: str
    environment: str
    source_products: tuple[str, ...]
    request_timestamp: datetime
    nonce: str
    body_sha256: str


class UsageNonceStore(Protocol):
    def claim(
        self,
        *,
        key_id: str,
        nonce: str,
        environment: str,
        request_timestamp: datetime,
        body_sha256: str,
        expires_at: datetime,
    ) -> bool: ...


class PostgresUsageNonceStore:
    """Claim nonces in an independent short transaction before ingest work begins."""

    def __init__(self, connection_factory: Callable[[], object]) -> None:
        self._connection_factory = connection_factory

    def claim(
        self,
        *,
        key_id: str,
        nonce: str,
        environment: str,
        request_timestamp: datetime,
        body_sha256: str,
        expires_at: datetime,
    ) -> bool:
        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM commercial_usage_ingest_nonces
                     WHERE ctid IN (
                         SELECT ctid FROM commercial_usage_ingest_nonces
                          WHERE expires_at < NOW()
                          ORDER BY expires_at
                          LIMIT 1000
                     )
                    """
                )
                cursor.execute(
                    """
                    INSERT INTO commercial_usage_ingest_nonces (
                        producer_key_id, nonce, environment, request_timestamp,
                        body_sha256, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (producer_key_id, nonce) DO NOTHING
                    RETURNING nonce
                    """,
                    (key_id, nonce, environment, request_timestamp, body_sha256, expires_at),
                )
                claimed = cursor.fetchone() is not None
            connection.commit()
            return claimed
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def signature_message(
    *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{digest}".encode("utf-8")


class CommercialUsageRequestAuthenticator:
    def __init__(
        self,
        *,
        keys: tuple[CommercialUsageProducerKey, ...],
        nonce_store: UsageNonceStore,
        environment: str,
        max_clock_skew: timedelta = timedelta(minutes=5),
        nonce_ttl: timedelta = timedelta(minutes=10),
        max_body_bytes: int = 1_000_000,
        signed_path: str = INGEST_PATH,
    ) -> None:
        if (
            environment not in _ENVIRONMENTS
            or not keys
            or len({key.key_id for key in keys}) != len(keys)
            or max_clock_skew <= timedelta(0)
            or nonce_ttl <= max_clock_skew
            or max_body_bytes <= 0
            or not signed_path.startswith("/")
        ):
            raise ValueError("commercial usage authenticator configuration is invalid")
        self._keys = {key.key_id: key for key in keys}
        self._nonce_store = nonce_store
        self._environment = environment
        self._max_clock_skew = max_clock_skew
        self._nonce_ttl = nonce_ttl
        self._max_body_bytes = max_body_bytes
        self._signed_path = signed_path

    def authenticate(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        now: datetime,
    ) -> AuthenticatedUsageProducer:
        if now.tzinfo is None:
            raise ValueError("commercial usage authentication clock must be timezone-aware")
        if method.upper() != "POST" or path != self._signed_path:
            raise UsageIngestAuthenticationError("usage_auth.invalid_target")
        if len(body) > self._max_body_bytes:
            raise UsageIngestAuthenticationError("usage_auth.body_too_large")
        normalized = {name.lower(): value.strip() for name, value in headers.items()}
        key_id = normalized.get("x-hank-service-key-id", "")
        timestamp_text = normalized.get("x-hank-request-timestamp", "")
        nonce = normalized.get("x-hank-request-nonce", "")
        signature = normalized.get("x-hank-request-signature", "")
        key = self._keys.get(key_id)
        if key is None or not _NONCE.fullmatch(nonce):
            raise UsageIngestAuthenticationError("usage_auth.invalid_credentials")
        try:
            timestamp = datetime.fromtimestamp(int(timestamp_text), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            raise UsageIngestAuthenticationError("usage_auth.invalid_timestamp") from None
        now_utc = now.astimezone(timezone.utc)
        if abs(now_utc - timestamp) > self._max_clock_skew:
            raise UsageIngestAuthenticationError("usage_auth.stale_timestamp")
        if (
            key.environment != self._environment
            or timestamp < key.active_from.astimezone(timezone.utc)
            or (key.active_until is not None
                and timestamp >= key.active_until.astimezone(timezone.utc))
        ):
            raise UsageIngestAuthenticationError("usage_auth.inactive_key")
        expected = hmac.new(
            key.secret,
            signature_message(
                method=method,
                path=path,
                timestamp=timestamp_text,
                nonce=nonce,
                body=body,
            ),
            hashlib.sha256,
        ).hexdigest()
        if not signature.startswith("v1=") or not hmac.compare_digest(signature[3:], expected):
            raise UsageIngestAuthenticationError("usage_auth.invalid_signature")
        body_sha256 = "sha256:" + hashlib.sha256(body).hexdigest()
        if not self._nonce_store.claim(
            key_id=key_id,
            nonce=nonce,
            environment=self._environment,
            request_timestamp=timestamp,
            body_sha256=body_sha256,
            expires_at=now_utc + self._nonce_ttl,
        ):
            raise UsageIngestAuthenticationError("usage_auth.replayed_nonce")
        return AuthenticatedUsageProducer(
            key_id=key_id,
            environment=self._environment,
            source_products=key.source_products,
            request_timestamp=timestamp,
            nonce=nonce,
            body_sha256=body_sha256,
        )


__all__ = [
    "AuthenticatedUsageProducer",
    "CommercialUsageProducerKey",
    "CommercialUsageRequestAuthenticator",
    "INGEST_PATH",
    "PostgresUsageNonceStore",
    "RECONCILIATION_INGEST_PATH",
    "UsageIngestAuthenticationError",
    "signature_message",
]
