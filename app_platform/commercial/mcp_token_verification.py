"""Constant-shape MCP bearer verification with safe use/failure evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Protocol
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictStr

from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_token_codec import McpTokenPepperRing
from .models import Sha256Digest, StableCode, StrictCommercialModel


class McpTokenVerificationAttempt(StrictCommercialModel):
    token: Annotated[StrictStr, Field(min_length=1, max_length=512, repr=False)]
    attempt_fingerprint: Sha256Digest
    source_ip_hash: Sha256Digest | None = None


class McpTokenVerificationResult(StrictCommercialModel):
    token_id: UUID
    commercial_account_id: Annotated[int, Field(gt=0)]
    user_id: Annotated[int, Field(gt=0)]
    agreement_id: Annotated[int, Field(gt=0)]
    surface_code: StableCode
    requested_scopes: tuple[StableCode, ...]
    entitlement_revision: Annotated[int, Field(gt=0)]
    verified_at: AwareDatetime
    use_audit_event_id: UUID


class McpTokenVerificationLimiter(Protocol):
    """Required abuse-control seam; implementations must fail closed."""

    def preflight(self, *, attempt_fingerprint: str, now: datetime) -> bool: ...

    def record_failure(self, *, attempt_fingerprint: str, now: datetime) -> bool: ...


@dataclass(frozen=True, slots=True)
class _VerificationOutcome:
    result: McpTokenVerificationResult | None = None
    error: CommercialError | None = None


@dataclass(frozen=True, slots=True)
class _LockedAuthority:
    account_status: str | None
    member_status: str | None
    agreement_surface_code: str | None
    agreement_state: str | None
    service_start_at: datetime | None
    service_end_at: datetime | None
    entitlement_revision: int | None


class McpTokenVerifier:
    """Verify a bearer, current tenant tuple, and record safe evidence atomically."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        pepper_ring: McpTokenPepperRing,
        limiter: McpTokenVerificationLimiter,
    ) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._pepper_ring = pepper_ring
        self._limiter = limiter

    def verify(
        self,
        *,
        runtime_environment: str,
        attempt: McpTokenVerificationAttempt,
    ) -> McpTokenVerificationResult:
        self._require_clean_transaction()
        try:
            outcome = self._prepare(runtime_environment, attempt)
            self._connection.commit()  # type: ignore[attr-defined]
        except BaseException:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        if outcome.error is not None:
            raise outcome.error
        if outcome.result is None:
            raise RuntimeError("MCP token verification produced no outcome")
        return outcome.result

    def _prepare(
        self,
        runtime_environment: str,
        attempt: McpTokenVerificationAttempt,
    ) -> _VerificationOutcome:
        self._require_enabled(runtime_environment)
        attempt_time = self._server_now()
        allowed = self._limiter.preflight(
            attempt_fingerprint=attempt.attempt_fingerprint,
            now=attempt_time,
        )
        if not isinstance(allowed, bool):
            raise RuntimeError("MCP token verification limiter returned an invalid decision")
        if not allowed:
            self._pepper_ring.verify_unknown(attempt.token)
            self._insert_failure_audit(reason_code="token.rate_limited")
            return _VerificationOutcome(
                error=CommercialError(CommercialErrorCode.RATE_LIMIT_EXCEEDED)
            )

        prefix = self._pepper_ring.parse_prefix(attempt.token)
        row = self._load_token_by_prefix(prefix or "!invalid-prefix!")
        if prefix is None or row is None:
            self._pepper_ring.verify_unknown(attempt.token)
            return self._record_invalid_auth(attempt, attempt_time)

        values = tuple(row)
        token_id = UUID(str(values[0]))
        account_id = int(values[1])
        user_id = int(values[2])
        agreement_id = int(values[3])
        surface_code = str(values[4])
        if not self._pepper_ring.verify(
            attempt.token,
            expected_prefix=str(values[5]),
            salt=bytes(values[7]),
            expected_digest=bytes(values[6]),
            digest_version=int(values[8]),
            pepper_version=int(values[9]),
        ):
            return self._record_invalid_auth(attempt, attempt_time)

        authority = self._lock_authority(
            account_id=account_id,
            user_id=user_id,
            agreement_id=agreement_id,
        )
        locked = self._load_token_for_update(token_id)
        if locked is None:
            return self._record_invalid_auth(attempt, attempt_time)
        values = tuple(locked)
        if (
            int(values[1]) != account_id
            or int(values[2]) != user_id
            or int(values[3]) != agreement_id
            or str(values[4]) != surface_code
            or not self._pepper_ring.verify(
                attempt.token,
                expected_prefix=str(values[5]),
                salt=bytes(values[7]),
                expected_digest=bytes(values[6]),
                digest_version=int(values[8]),
                pepper_version=int(values[9]),
            )
        ):
            return self._record_invalid_auth(attempt, attempt_time)

        now = self._wall_now()
        locked_status = str(values[11])
        if not self._authority_is_current(
            authority, surface_code=surface_code, now=now
        ):
            return self._record_authenticated_denial(
                attempt,
                now=now,
                error_code=CommercialErrorCode.TOKEN_INVALID,
                reason_code="token.authority_invalid",
                token_id=token_id,
                account_id=account_id,
                agreement_id=agreement_id,
                user_id=user_id,
                state=locked_status,
            )
        status = str(values[11])
        expires_at = values[13]
        revoked_at = values[14]
        expired_at = values[15]
        if status == "revoked" or revoked_at is not None:
            return self._record_authenticated_denial(
                attempt,
                now=now,
                error_code=CommercialErrorCode.TOKEN_REVOKED,
                reason_code="token.revoked",
                token_id=token_id,
                account_id=account_id,
                agreement_id=agreement_id,
                user_id=user_id,
                state="revoked",
            )
        if status == "expired" or expired_at is not None or expires_at <= now:
            return self._record_authenticated_denial(
                attempt,
                now=now,
                error_code=CommercialErrorCode.TOKEN_EXPIRED,
                reason_code="token.expired",
                token_id=token_id,
                account_id=account_id,
                agreement_id=agreement_id,
                user_id=user_id,
                state="expired",
            )
        if status != "active":
            return self._record_authenticated_denial(
                attempt,
                now=now,
                error_code=CommercialErrorCode.TOKEN_INVALID,
                reason_code="token.invalid",
            )

        use_audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=use_audit_id,
                commercial_account_id=account_id,
                agreement_id=agreement_id,
                actor_type="service",
                actor_id="mcp-token-verifier",
                action="commercial.mcp_token.use",
                target_type="mcp_token",
                target_id=str(token_id),
                reason_code="token.verified",
                after={
                    "account_id": account_id,
                    "agreement_id": agreement_id,
                    "user_id": user_id,
                    "state": "active",
                    "result_code": "applied",
                },
            ),
        )
        last_used_at = values[16]
        if last_used_at is None or now > last_used_at:
            with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
                cursor.execute(
                    """
                    UPDATE mcp_tokens
                       SET last_used_at = %s, last_used_ip_hash = %s,
                           last_used_audit_event_id = %s,
                           updated_at = GREATEST(
                               clock_timestamp(), updated_at + INTERVAL '1 microsecond'
                           )
                     WHERE id = %s
                    """,
                    (
                        now,
                        attempt.source_ip_hash,
                        str(use_audit_id),
                        str(token_id),
                    ),
                )
        return _VerificationOutcome(
            result=McpTokenVerificationResult(
                token_id=token_id,
                commercial_account_id=account_id,
                user_id=user_id,
                agreement_id=agreement_id,
                surface_code=surface_code,
                requested_scopes=tuple(values[10]),
                entitlement_revision=authority.entitlement_revision,
                verified_at=now,
                use_audit_event_id=use_audit_id,
            )
        )

    def _load_token_by_prefix(self, prefix: str):
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT id, commercial_account_id, user_id, agreement_id,
                       surface_code, token_prefix, secret_digest, token_salt,
                       digest_version, pepper_version, requested_scopes, status,
                       created_at, expires_at, revoked_at, expired_at, last_used_at
                  FROM mcp_tokens WHERE token_prefix = %s
                """,
                (prefix,),
            )
            return cursor.fetchone()

    def _load_token_for_update(self, token_id: UUID):
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT id, commercial_account_id, user_id, agreement_id,
                       surface_code, token_prefix, secret_digest, token_salt,
                       digest_version, pepper_version, requested_scopes, status,
                       created_at, expires_at, revoked_at, expired_at, last_used_at
                  FROM mcp_tokens WHERE id = %s FOR UPDATE
                """,
                (str(token_id),),
            )
            return cursor.fetchone()

    def _lock_authority(
        self,
        *,
        account_id: int,
        user_id: int,
        agreement_id: int,
    ) -> _LockedAuthority:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT status FROM commercial_accounts WHERE id = %s FOR SHARE
                """,
                (account_id,),
            )
            account = cursor.fetchone()
            cursor.execute(
                """
                SELECT status FROM commercial_account_members
                 WHERE commercial_account_id = %s AND user_id = %s FOR SHARE
                """,
                (account_id, user_id),
            )
            member = cursor.fetchone()
            cursor.execute(
                """
                SELECT surface_code, state, service_start_at, service_end_at
                  FROM commercial_agreements
                 WHERE id = %s AND commercial_account_id = %s FOR SHARE
                """,
                (agreement_id, account_id),
            )
            agreement = cursor.fetchone()
            cursor.execute(
                """
                SELECT revision FROM commercial_entitlement_revisions
                 WHERE commercial_account_id = %s FOR SHARE
                """,
                (account_id,),
            )
            revision = cursor.fetchone()
        return _LockedAuthority(
            account_status=str(account[0]) if account is not None else None,
            member_status=str(member[0]) if member is not None else None,
            agreement_surface_code=(
                str(agreement[0]) if agreement is not None else None
            ),
            agreement_state=str(agreement[1]) if agreement is not None else None,
            service_start_at=agreement[2] if agreement is not None else None,
            service_end_at=agreement[3] if agreement is not None else None,
            entitlement_revision=int(revision[0]) if revision is not None else None,
        )

    @staticmethod
    def _authority_is_current(
        authority: _LockedAuthority,
        *,
        surface_code: str,
        now: datetime,
    ) -> bool:
        return bool(
            authority.account_status == "active"
            and authority.member_status == "active"
            and authority.agreement_surface_code == surface_code
            and authority.agreement_state in {"trialing", "active"}
            and authority.service_start_at is not None
            and authority.service_start_at <= now
            and (
                authority.service_end_at is None or authority.service_end_at > now
            )
            and authority.entitlement_revision is not None
        )

    def _insert_failure_audit(
        self,
        *,
        reason_code: str,
        token_id: UUID | None = None,
        account_id: int | None = None,
        agreement_id: int | None = None,
        user_id: int | None = None,
        state: str | None = None,
    ) -> None:
        after = {"result_code": "rejected"}
        if account_id is not None:
            after["account_id"] = account_id
        if agreement_id is not None:
            after["agreement_id"] = agreement_id
        if user_id is not None:
            after["user_id"] = user_id
        if state in {"active", "revoked", "expired"}:
            after["state"] = state
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                commercial_account_id=account_id,
                agreement_id=agreement_id,
                actor_type="service",
                actor_id="mcp-token-verifier",
                action="commercial.mcp_token.validation_failed",
                target_type="mcp_token",
                target_id=str(token_id) if token_id is not None else "unresolved",
                reason_code=reason_code,
                after=after,
            ),
        )

    @staticmethod
    def _invalid() -> _VerificationOutcome:
        return _VerificationOutcome(
            error=CommercialError(CommercialErrorCode.TOKEN_INVALID)
        )

    def _record_invalid_auth(
        self, attempt: McpTokenVerificationAttempt, now: datetime
    ) -> _VerificationOutcome:
        allowed = self._limiter.record_failure(
            attempt_fingerprint=attempt.attempt_fingerprint,
            now=now,
        )
        if not isinstance(allowed, bool):
            raise RuntimeError("MCP token verification limiter returned an invalid decision")
        if not allowed:
            self._insert_failure_audit(reason_code="token.rate_limited")
            return _VerificationOutcome(
                error=CommercialError(CommercialErrorCode.RATE_LIMIT_EXCEEDED)
            )
        self._insert_failure_audit(reason_code="token.invalid")
        return self._invalid()

    def _record_authenticated_denial(
        self,
        attempt: McpTokenVerificationAttempt,
        *,
        now: datetime,
        error_code: CommercialErrorCode,
        reason_code: str,
        token_id: UUID | None = None,
        account_id: int | None = None,
        agreement_id: int | None = None,
        user_id: int | None = None,
        state: str | None = None,
    ) -> _VerificationOutcome:
        allowed = self._limiter.record_failure(
            attempt_fingerprint=attempt.attempt_fingerprint,
            now=now,
        )
        if not isinstance(allowed, bool):
            raise RuntimeError("MCP token verification limiter returned an invalid decision")
        if not allowed:
            self._insert_failure_audit(reason_code="token.rate_limited")
            return _VerificationOutcome(
                error=CommercialError(CommercialErrorCode.RATE_LIMIT_EXCEEDED)
            )
        self._insert_failure_audit(
            reason_code=reason_code,
            token_id=token_id,
            account_id=account_id,
            agreement_id=agreement_id,
            user_id=user_id,
            state=state,
        )
        return _VerificationOutcome(error=CommercialError(error_code))

    def _require_enabled(self, environment: str) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
            and self._flags.commercial_usage_ingest_enabled
            and self._flags.commercial_budget_enforcement_enabled
            and self._flags.mcp_external_auth_enabled
        ):
            raise ValueError("external MCP token verification is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.TOKEN_INVALID)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.TOKEN_INVALID)

    def _server_now(self) -> datetime:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute("SELECT transaction_timestamp()")
            value = cursor.fetchone()[0]
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("database transaction time must be timezone-aware")
        return value

    def _wall_now(self) -> datetime:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute("SELECT clock_timestamp()")
            value = cursor.fetchone()[0]
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("database wall time must be timezone-aware")
        return value

    def _require_clean_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("MCP token verification requires autocommit disabled")
        transaction_status = getattr(self._connection, "get_transaction_status", None)
        if transaction_status is not None and transaction_status() != 0:
            raise ValueError("MCP token verification requires a clean transaction boundary")


__all__ = [
    "McpTokenVerificationAttempt",
    "McpTokenVerificationLimiter",
    "McpTokenVerificationResult",
    "McpTokenVerifier",
]
