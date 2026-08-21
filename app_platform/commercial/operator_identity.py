"""Short-lived signed identity assertions for non-browser commercial operators."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from typing import Literal, Mapping
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import AwareDatetime, Field, StrictInt, model_validator

from .models import NonEmptyStr, StrictCommercialModel

ASSERTION_AUDIENCE = "hank-commercial-operator-cli"
ASSERTION_MAX_LIFETIME = timedelta(minutes=5)


class OperatorIdentityError(ValueError):
    pass


class OperatorIdentityAssertion(StrictCommercialModel):
    schema_version: Literal[1] = 1
    issuer: NonEmptyStr
    audience: Literal["hank-commercial-operator-cli"] = ASSERTION_AUDIENCE
    subject_user_id: StrictInt = Field(gt=0)
    environment: Literal["dev", "staging", "prod"]
    session_id: UUID
    nonce: UUID
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def _short_lived(self) -> "OperatorIdentityAssertion":
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > ASSERTION_MAX_LIFETIME:
            raise ValueError("operator assertion lifetime must be positive and at most five minutes")
        return self


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise OperatorIdentityError("operator assertion encoding is invalid") from exc


def load_operator_assertion_public_key(
    env: Mapping[str, str] = os.environ,
) -> Ed25519PublicKey:
    encoded = env.get("COMMERCIAL_OPERATOR_ASSERTION_PUBLIC_KEY", "").strip()
    try:
        raw = _b64decode(encoded)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (OperatorIdentityError, ValueError) as exc:
        raise OperatorIdentityError(
            "COMMERCIAL_OPERATOR_ASSERTION_PUBLIC_KEY must be a base64url Ed25519 public key"
        ) from exc


def sign_operator_assertion(
    assertion: OperatorIdentityAssertion, *, private_key: Ed25519PrivateKey
) -> str:
    payload = json.dumps(
        assertion.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = _b64encode(payload)
    signature = private_key.sign(encoded.encode("ascii"))
    return f"v1.{encoded}.{_b64encode(signature)}"


def verify_operator_assertion(
    token: str,
    *,
    public_key: Ed25519PublicKey,
    environment: Literal["dev", "staging", "prod"],
    now: datetime | None = None,
) -> OperatorIdentityAssertion:
    try:
        version, payload, encoded_signature = token.strip().split(".", 2)
    except ValueError as exc:
        raise OperatorIdentityError("operator assertion format is invalid") from exc
    if version != "v1":
        raise OperatorIdentityError("operator assertion verification failed")
    try:
        public_key.verify(_b64decode(encoded_signature), payload.encode("ascii"))
    except (InvalidSignature, ValueError):
        raise OperatorIdentityError("operator assertion verification failed")
    try:
        assertion = OperatorIdentityAssertion.model_validate_json(_b64decode(payload))
    except ValueError as exc:
        raise OperatorIdentityError("operator assertion claims are invalid") from exc
    checked_at = now or datetime.now(timezone.utc)
    if assertion.environment != environment:
        raise OperatorIdentityError("operator assertion environment does not match")
    if assertion.issued_at > checked_at + timedelta(seconds=30):
        raise OperatorIdentityError("operator assertion is not valid yet")
    if assertion.expires_at <= checked_at:
        raise OperatorIdentityError("operator assertion has expired")
    return assertion


__all__ = [
    "ASSERTION_AUDIENCE",
    "OperatorIdentityAssertion",
    "OperatorIdentityError",
    "load_operator_assertion_public_key",
    "sign_operator_assertion",
    "verify_operator_assertion",
]
