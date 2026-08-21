from __future__ import annotations

import base64
import json
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt
import pytest

from app_platform.gateway.subject_assertion import (
    GatewaySubjectAssertionIssuer,
    SUBJECT_ASSERTION_AUDIENCE,
    SUBJECT_ASSERTION_ISSUER,
    SUBJECT_ASSERTION_KEY_ID_ENV,
    SUBJECT_ASSERTION_PRIVATE_KEY_ENV,
    SubjectAssertionConfigError,
    load_subject_assertion_issuer,
)


def _private_value() -> str:
    return base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")


def test_issuer_mints_exact_short_lived_subject_claims() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    issuer = GatewaySubjectAssertionIssuer(private_key, "risk-web-v1")
    request_id = str(uuid4())

    token = issuer.issue(
        user_id="101",
        email=" USER@example.com ",
        request_id=request_id,
        channel="web",
        now=1_900_000_000,
    )

    header = jwt.get_unverified_header(token)
    claims = jwt.decode(
        token,
        private_key.public_key(),
        algorithms=["EdDSA"],
        audience=SUBJECT_ASSERTION_AUDIENCE,
        issuer=SUBJECT_ASSERTION_ISSUER,
        options={"verify_exp": False, "verify_iat": False},
    )
    assert header == {"alg": "EdDSA", "kid": "risk-web-v1", "typ": "JWT"}
    assert claims["sub"] == "101"
    assert claims["email"] == "user@example.com"
    assert claims["channel"] == "web"
    assert claims["request_id"] == request_id
    assert claims["iat"] == 1_900_000_000
    assert claims["exp"] == 1_900_000_060
    assert set(claims) == {
        "schema_version", "iss", "aud", "sub", "email", "channel",
        "request_id", "iat", "exp", "jti",
    }
    assert json.loads(issuer.public_keys_json()).keys() == {"risk-web-v1"}


def test_load_issuer_requires_a_complete_canonical_authority() -> None:
    assert load_subject_assertion_issuer({}, required=False) is None
    with pytest.raises(SubjectAssertionConfigError, match="required"):
        load_subject_assertion_issuer({}, required=True)
    with pytest.raises(SubjectAssertionConfigError, match="incomplete"):
        load_subject_assertion_issuer(
            {SUBJECT_ASSERTION_PRIVATE_KEY_ENV: _private_value()}
        )

    issuer = load_subject_assertion_issuer(
        {
            SUBJECT_ASSERTION_PRIVATE_KEY_ENV: _private_value(),
            SUBJECT_ASSERTION_KEY_ID_ENV: "risk-web-v1",
        },
        required=True,
    )
    assert issuer is not None


@pytest.mark.parametrize("user_id", ["", "0", "01", "alice"])
def test_issuer_rejects_noncanonical_subjects(user_id: str) -> None:
    issuer = GatewaySubjectAssertionIssuer(
        Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        "risk-web-v1",
    )
    with pytest.raises(ValueError, match="positive canonical"):
        issuer.issue(
            user_id=user_id,
            email=None,
            request_id=str(uuid4()),
            channel="web",
        )
