"""Short-lived identity assertions for gateway web-session initialization."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import json
import os
import re
import time
from typing import Mapping
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt


SUBJECT_ASSERTION_ALGORITHM = "EdDSA"
SUBJECT_ASSERTION_ISSUER = "risk-module-web-auth"
SUBJECT_ASSERTION_AUDIENCE = "agent-gateway-session-init"
SUBJECT_ASSERTION_PRIVATE_KEY_ENV = "GATEWAY_SUBJECT_ASSERTION_ED25519_PRIVATE_KEY"
SUBJECT_ASSERTION_KEY_ID_ENV = "GATEWAY_SUBJECT_ASSERTION_ED25519_KEY_ID"
SUBJECT_ASSERTION_PUBLIC_KEYS_ENV = "GATEWAY_SUBJECT_ASSERTION_ED25519_PUBLIC_KEYS"
SUBJECT_ASSERTION_LIFETIME_SECONDS = 60
_KEY_ID = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_SUBJECT = re.compile(r"^[1-9][0-9]*$")


class SubjectAssertionConfigError(ValueError):
    """Subject assertion signing authority is absent or malformed."""


def _decode_private_seed(value: object) -> bytes:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SubjectAssertionConfigError(
            f"{SUBJECT_ASSERTION_PRIVATE_KEY_ENV} must be a base64url Ed25519 private seed"
        )
    try:
        raw = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError, binascii.Error) as exc:
        raise SubjectAssertionConfigError(
            f"{SUBJECT_ASSERTION_PRIVATE_KEY_ENV} must be a base64url Ed25519 private seed"
        ) from exc
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if len(raw) != 32 or canonical != value:
        raise SubjectAssertionConfigError(
            f"{SUBJECT_ASSERTION_PRIVATE_KEY_ENV} must be a base64url Ed25519 private seed"
        )
    return raw


def _normalize_key_id(value: object) -> str:
    key_id = str(value or "").strip()
    if not _KEY_ID.fullmatch(key_id):
        raise SubjectAssertionConfigError(
            f"{SUBJECT_ASSERTION_KEY_ID_ENV} must be a stable lowercase key id"
        )
    return key_id


def _normalize_subject(value: object) -> str:
    subject = str(value or "").strip()
    if not _SUBJECT.fullmatch(subject):
        raise ValueError("gateway subject must be a positive canonical numeric user id")
    return subject


def _normalize_email(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("gateway subject email must be a string or null")
    normalized = value.strip().lower()
    if not normalized or len(normalized) > 320:
        raise ValueError("gateway subject email must be non-empty when supplied")
    return normalized


def _canonical_uuid(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field_name} must be a canonical UUID") from exc
    canonical = str(parsed)
    if canonical != value:
        raise ValueError(f"{field_name} must be a canonical UUID")
    return canonical


@dataclass(frozen=True, slots=True)
class GatewaySubjectAssertionIssuer:
    """Issue one audience-bound Ed25519 JWT for a gateway init request."""

    private_key: Ed25519PrivateKey = field(repr=False)
    key_id: str
    lifetime_seconds: int = SUBJECT_ASSERTION_LIFETIME_SECONDS

    def __post_init__(self) -> None:
        _normalize_key_id(self.key_id)
        if not 1 <= self.lifetime_seconds <= 90:
            raise ValueError("subject assertion lifetime must be between 1 and 90 seconds")

    def issue(
        self,
        *,
        user_id: str,
        email: str | None,
        request_id: str,
        channel: str,
        now: int | None = None,
    ) -> str:
        subject = _normalize_subject(user_id)
        normalized_email = _normalize_email(email)
        normalized_request_id = _canonical_uuid(request_id, field_name="request_id")
        if str(channel or "").strip().lower() != "web":
            raise ValueError("subject assertions are restricted to the web channel")
        issued_at = int(time.time()) if now is None else now
        if type(issued_at) is not int:
            raise ValueError("subject assertion issue time must be an integer")
        claims = {
            "schema_version": 1,
            "iss": SUBJECT_ASSERTION_ISSUER,
            "aud": SUBJECT_ASSERTION_AUDIENCE,
            "sub": subject,
            "email": normalized_email,
            "channel": "web",
            "request_id": normalized_request_id,
            "iat": issued_at,
            "exp": issued_at + self.lifetime_seconds,
            "jti": str(uuid4()),
        }
        return jwt.encode(
            claims,
            self.private_key,
            algorithm=SUBJECT_ASSERTION_ALGORITHM,
            headers={"kid": self.key_id, "typ": "JWT"},
        )

    def public_keys_json(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return json.dumps({self.key_id: encoded}, sort_keys=True, separators=(",", ":"))


def load_subject_assertion_issuer(
    env: Mapping[str, str] = os.environ,
    *,
    required: bool = False,
) -> GatewaySubjectAssertionIssuer | None:
    encoded_seed = str(env.get(SUBJECT_ASSERTION_PRIVATE_KEY_ENV) or "").strip()
    raw_key_id = str(env.get(SUBJECT_ASSERTION_KEY_ID_ENV) or "").strip()
    if not encoded_seed and not raw_key_id:
        if required:
            raise SubjectAssertionConfigError("gateway subject assertion authority is required")
        return None
    if not encoded_seed or not raw_key_id:
        raise SubjectAssertionConfigError("gateway subject assertion authority is incomplete")
    private_key = Ed25519PrivateKey.from_private_bytes(_decode_private_seed(encoded_seed))
    return GatewaySubjectAssertionIssuer(
        private_key=private_key,
        key_id=_normalize_key_id(raw_key_id),
    )


__all__ = [
    "GatewaySubjectAssertionIssuer",
    "SUBJECT_ASSERTION_AUDIENCE",
    "SUBJECT_ASSERTION_KEY_ID_ENV",
    "SUBJECT_ASSERTION_PRIVATE_KEY_ENV",
    "SUBJECT_ASSERTION_PUBLIC_KEYS_ENV",
    "SubjectAssertionConfigError",
    "load_subject_assertion_issuer",
]
