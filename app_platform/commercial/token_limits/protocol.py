"""Crash-safe durable acquisition of token request/concurrency authority."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID, uuid5, NAMESPACE_URL

from pydantic import AwareDatetime, Field, StrictInt

from ..flags import CommercialFlags
from ..models import StrictCommercialModel, canonical_sha256
from .models import TokenLimitPolicy
from .redis_store import (
    CommercialTokenLimitRedisError,
    CommercialTokenLimitRedisStore,
    TokenLimitAdmissionCommand,
    TokenLimitLeaseCommand,
)


PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]


class TokenLimitProtocolError(RuntimeError):
    pass


class _PostgresCommitOutcomeUnknown(RuntimeError):
    pass


class TokenLimitAcquireCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    token_id: UUID
    commercial_account_id: PositiveSafeInt
    agreement_terms_id: PositiveSafeInt
    execution_context_id: UUID
    workflow_run_id: UUID
    request_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^\S+$")]
    entitlement_revision: PositiveSafeInt
    lease_id: UUID
    lease_token: UUID
    lease_version: PositiveSafeInt = 1
    redis_generation: PositiveSafeInt = 1
    lease_ttl_seconds: Annotated[StrictInt, Field(ge=30, le=3600)]
    policy: TokenLimitPolicy


class TokenLimitAcquireResult(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9._:-]{0,127}$")
    lease_id: UUID
    state: Literal["active", "blocked", "released", "repair_required"]
    lease_version: PositiveSafeInt
    expires_at: AwareDatetime
    replayed: bool


class TokenLimitHeartbeatCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    token_id: UUID
    lease_id: UUID
    lease_token: UUID
    lease_version: PositiveSafeInt
    redis_generation: PositiveSafeInt
    operation_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^\S+$")]
    lease_ttl_seconds: Annotated[StrictInt, Field(ge=30, le=3600)]


class TokenLimitReleaseCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    token_id: UUID
    lease_id: UUID
    lease_token: UUID
    lease_version: PositiveSafeInt
    redis_generation: PositiveSafeInt
    operation_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^\S+$")]


class TokenLimitReapCommand(TokenLimitReleaseCommand):
    observed_expires_at: AwareDatetime


class TokenLimitLifecycleResult(StrictCommercialModel):
    state: Literal["active", "released", "expired", "repair_required"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9._:-]{0,127}$")
    lease_id: UUID
    lease_version: PositiveSafeInt
    expires_at: AwareDatetime
    replayed: bool


class TokenLimitLifecycleProtocol:
    """Fenced heartbeat/release/reap transitions after durable acquisition."""

    def __init__(self, connection, redis_store, *, flags: CommercialFlags) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise TokenLimitProtocolError("token limit protocol requires transactions")
        if not flags.commercial_token_limit_enforcement_enabled:
            raise TokenLimitProtocolError("token limit enforcement is disabled")
        self._connection, self._redis, self._flags = connection, redis_store, flags

    def heartbeat(self, command: TokenLimitHeartbeatCommand) -> TokenLimitLifecycleResult:
        self._validate_common(command)
        replay = self._durable_replay(command, "heartbeat", "active")
        if replay is not None:
            return replay
        row = self._load_active(command, workflow_terminal=False)
        now, expires_at = row[0], row[1]
        new_expiry = datetime.fromtimestamp(
            int(now.timestamp()) + command.lease_ttl_seconds, tz=timezone.utc
        )
        if new_expiry <= expires_at:
            raise TokenLimitProtocolError("heartbeat must extend the token lease")
        redis = self._call_redis("heartbeat", command, expires_at=new_expiry)
        return self._finalize(command, redis, "active", new_expiry, "heartbeat")

    def release(self, command: TokenLimitReleaseCommand) -> TokenLimitLifecycleResult:
        self._validate_common(command)
        replay = self._durable_replay(command, "release", "released")
        if replay is not None:
            return replay
        row = self._load_active(command, workflow_terminal=True)
        expires_at = row[1]
        redis = self._call_redis("terminal_release", command)
        return self._finalize(command, redis, "released", expires_at, "release")

    def reap(self, command: TokenLimitReapCommand) -> TokenLimitLifecycleResult:
        self._validate_common(command)
        replay = self._durable_replay(command, "expire", "expired")
        if replay is not None:
            return replay
        row = self._load_active(command, workflow_terminal=False)
        now, expires_at = row[0], row[1]
        if expires_at != command.observed_expires_at or now < expires_at:
            raise TokenLimitProtocolError("token lease is not durably eligible for reaping")
        redis = self._call_redis("reap", command, expires_at=expires_at)
        return self._finalize(command, redis, "expired", expires_at, "expire")

    def _validate_common(self, command):
        self._assert_idle()
        if command.environment != self._flags.environment:
            raise TokenLimitProtocolError("token limit environment mismatch")

    def _load_active(self, command, *, workflow_terminal):
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """SELECT transaction_timestamp(), lease.expires_at,
                              workflow.state, lease.state, lease.mcp_token_id,
                              lease.lease_token, lease.lease_version,
                              authority.current_generation, authority.state
                         FROM commercial_token_workflow_leases lease
                         JOIN commercial_workflow_runs workflow
                           ON workflow.id=lease.workflow_run_id
                         JOIN commercial_token_limit_authorities authority
                           ON authority.environment=lease.environment
                          AND authority.mcp_token_id=lease.mcp_token_id
                        WHERE lease.id=%s FOR SHARE OF lease, workflow""",
                    (str(command.lease_id),),
                )
                row = cursor.fetchone()
                expected = (
                    "active", command.token_id, command.lease_token,
                    command.lease_version, command.redis_generation, "stable",
                )
                if row is None or (
                    row[3], UUID(str(row[4])), UUID(str(row[5])), int(row[6]),
                    int(row[7]), row[8],
                ) != expected:
                    raise TokenLimitProtocolError("token lease durable fence mismatch")
                if workflow_terminal and row[2] not in {
                    "succeeded", "failed", "canceled", "abandoned"
                }:
                    raise TokenLimitProtocolError("workflow must be terminal before token lease release")
            self._connection.commit()
            return row
        except Exception:
            self._rollback()
            raise

    def _call_redis(self, method, command, *, expires_at=None):
        redis_command = TokenLimitLeaseCommand(
            token_id=command.token_id, lease_id=command.lease_id,
            lease_token=command.lease_token, lease_version=command.lease_version,
            redis_generation=command.redis_generation,
            operation_id=command.operation_id,
            expires_at_epoch=int(expires_at.timestamp()) if expires_at else None,
        )
        try:
            return getattr(self._redis, method)(redis_command)
        except CommercialTokenLimitRedisError as error:
            raise TokenLimitProtocolError(
                f"token limit {method} failed; work is not authorized"
            ) from error

    def _durable_replay(self, command, event_kind, expected_state):
        command_sha = canonical_sha256(command.model_dump(mode="json"))
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """SELECT lease.state, lease.reason_code, lease.lease_version,
                              lease.expires_at, lease.mcp_token_id, lease.lease_token
                         FROM commercial_token_workflow_leases lease
                         JOIN commercial_token_limit_events event
                           ON event.lease_id=lease.id
                          AND event.event_kind=%s AND event.command_sha256=%s
                          AND event.lease_version=%s
                        WHERE lease.id=%s""",
                    (event_kind, command_sha, command.lease_version,
                     str(command.lease_id)),
                )
                row = cursor.fetchone()
            self._connection.commit()
        except Exception:
            self._rollback()
            raise
        if row is None:
            return None
        expected = (
            expected_state, command.lease_version + 1,
            command.token_id, command.lease_token,
        )
        actual = (row[0], int(row[2]), UUID(str(row[4])), UUID(str(row[5])))
        if actual != expected:
            raise TokenLimitProtocolError("durable lifecycle replay evidence is inconsistent")
        method = {
            "heartbeat": "heartbeat", "release": "terminal_release", "expire": "reap",
        }[event_kind]
        redis = self._call_redis(
            method, command, expires_at=row[3] if event_kind != "release" else None
        )
        expected_outcome = {
            "heartbeat": "heartbeat", "release": "released", "expire": "expired",
        }[event_kind]
        expected_reason = {
            "heartbeat": "limit.heartbeat", "release": "limit.released",
            "expire": "limit.expired",
        }[event_kind]
        if (
            not redis.replayed
            or redis.lease_id != command.lease_id
            or redis.lease_version != int(row[2])
            or redis.outcome != expected_outcome
            or redis.reason_code != expected_reason
            or redis.expires_at_epoch != int(row[3].timestamp())
        ):
            raise TokenLimitProtocolError("durable lifecycle replay lacks Redis evidence")
        return TokenLimitLifecycleResult(
            state=row[0], reason_code=row[1], lease_id=command.lease_id,
            lease_version=int(row[2]), expires_at=row[3], replayed=True,
        )

    def _finalize(self, command, redis, state, expires_at, event_kind):
        command_sha = canonical_sha256(command.model_dump(mode="json"))
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("SELECT transaction_timestamp()")
                now = cursor.fetchone()[0]
                cursor.execute(
                    """UPDATE commercial_token_workflow_leases
                          SET state=%s, lease_version=%s, expires_at=%s,
                              heartbeat_at=CASE WHEN %s='active' THEN %s ELSE heartbeat_at END,
                              released_at=CASE WHEN %s='active' THEN NULL ELSE %s END,
                              reason_code=%s, updated_at=%s
                        WHERE id=%s AND state='active' AND mcp_token_id=%s
                          AND lease_token=%s AND lease_version=%s
                          AND EXISTS (
                              SELECT 1 FROM commercial_token_limit_authorities authority
                               WHERE authority.environment=commercial_token_workflow_leases.environment
                                 AND authority.mcp_token_id=commercial_token_workflow_leases.mcp_token_id
                                 AND authority.current_generation=%s
                                 AND authority.state='stable')""",
                    (state, redis.lease_version, expires_at, state, now, state, now,
                     redis.reason_code, now, str(command.lease_id), str(command.token_id),
                     str(command.lease_token), command.lease_version,
                     command.redis_generation),
                )
                if cursor.rowcount != 1:
                    raise TokenLimitProtocolError("token lease durable finalize lost fence")
                TokenLimitAcquireProtocol._insert_event(
                    cursor, command, command_sha, event_kind, "allow", redis.reason_code,
                )
            try:
                self._connection.commit()
            except Exception as error:
                raise _PostgresCommitOutcomeUnknown("lifecycle commit outcome unknown") from error
        except _PostgresCommitOutcomeUnknown as error:
            self._rollback()
            replay = self._durable_replay(command, event_kind, state)
            if replay is not None:
                return replay
            raise TokenLimitProtocolError(
                "token lease lifecycle commit outcome is unknown; Redis fence is retained"
            ) from error
        except Exception as error:
            self._rollback()
            replay = self._durable_replay(command, event_kind, state)
            if replay is not None:
                return replay
            self._mark_repair(command, redis.lease_version, expires_at)
            raise TokenLimitProtocolError(
                "token lease lifecycle finalization failed and requires repair"
            ) from error
        return TokenLimitLifecycleResult(
            state=state, reason_code=redis.reason_code, lease_id=command.lease_id,
            lease_version=redis.lease_version, expires_at=expires_at,
            replayed=redis.replayed,
        )

    def _mark_repair(self, command, redis_version, expires_at):
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT transaction_timestamp()")
            now = cursor.fetchone()[0]
            cursor.execute(
                """UPDATE commercial_token_workflow_leases
                      SET state='repair_required', lease_version=%s, expires_at=%s,
                          reason_code='limit.lifecycle_repair_required', updated_at=%s
                    WHERE id=%s AND state='active' AND lease_token=%s
                      AND lease_version=%s""",
                (redis_version, expires_at, now, str(command.lease_id),
                 str(command.lease_token), command.lease_version),
            )
            if cursor.rowcount != 1:
                raise TokenLimitProtocolError("token lease repair journal lost fence")
        self._connection.commit()

    def _assert_idle(self):
        if getattr(self._connection, "get_transaction_status", lambda: 0)() != 0:
            raise TokenLimitProtocolError("token limit protocol requires an idle connection")

    def _rollback(self):
        try:
            self._connection.rollback()
        except Exception:
            pass


class TokenLimitAcquireProtocol:
    def __init__(
        self,
        connection: Any,
        redis_store: CommercialTokenLimitRedisStore,
        *,
        flags: CommercialFlags,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise TokenLimitProtocolError("token limit protocol requires transactions")
        if not flags.commercial_token_limit_enforcement_enabled:
            raise TokenLimitProtocolError("token limit enforcement is disabled")
        self._connection = connection
        self._redis = redis_store
        self._flags = flags

    def acquire(self, command: TokenLimitAcquireCommand) -> TokenLimitAcquireResult:
        self._assert_idle()
        if command.environment != self._flags.environment:
            raise TokenLimitProtocolError("token limit environment mismatch")
        command_sha = canonical_sha256(command.model_dump(mode="json"))
        existing, expires_at = self._ensure_pending(command, command_sha)
        if existing is not None:
            return self._verify_replay(command, existing)
        redis_command = self._redis_command(command, expires_at=expires_at)
        try:
            decision = self._redis.admit(redis_command)
        except CommercialTokenLimitRedisError as error:
            raise TokenLimitProtocolError(
                "token limit Redis unavailable; work is not authorized"
            ) from error
        if decision.decision == "block":
            try:
                return self._record_block(command, command_sha, decision)
            except _PostgresCommitOutcomeUnknown as error:
                self._rollback()
                raise TokenLimitProtocolError(
                    "token limit block commit outcome is unknown"
                ) from error
            except Exception as error:
                self._rollback()
                raise TokenLimitProtocolError(
                    "token limit block could not be durably journaled"
                ) from error
        try:
            return self._activate(command, command_sha, decision)
        except _PostgresCommitOutcomeUnknown as outcome_error:
            self._rollback()
            raise TokenLimitProtocolError(
                "token limit activation commit outcome is unknown; Redis authority is retained"
            ) from outcome_error
        except Exception as finalize_error:
            self._rollback()
            try:
                compensated = self._redis.compensate(redis_command)
            except Exception as compensation_error:
                self._mark_repair(command, command_sha, "limit.compensation_required")
                raise TokenLimitProtocolError(
                    "token limit finalization and compensation require repair"
                ) from compensation_error
            if compensated.reason_code != "limit.compensated":
                self._mark_repair(command, command_sha, "limit.compensation_required")
                raise TokenLimitProtocolError("token limit compensation result is invalid")
            self._mark_released(command, command_sha, "limit.compensated")
            raise TokenLimitProtocolError(
                "token limit finalization failed and Redis admission was compensated"
            ) from finalize_error

    def _ensure_pending(self, command, command_sha):
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO commercial_token_limit_authorities (
                           environment,mcp_token_id,current_generation,state)
                         VALUES (%s,%s,1,'stable')
                         ON CONFLICT (environment,mcp_token_id) DO NOTHING""",
                    (command.environment, str(command.token_id)),
                )
                cursor.execute(
                    """SELECT current_generation,state
                         FROM commercial_token_limit_authorities
                        WHERE environment=%s AND mcp_token_id=%s FOR UPDATE""",
                    (command.environment, str(command.token_id)),
                )
                if cursor.fetchone() != (command.redis_generation, "stable"):
                    raise TokenLimitProtocolError("token limit generation is not stable")
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"token-limit:{command.environment}:{command.token_id}:{command.request_id}",),
                )
                cursor.execute(
                    """SELECT command_sha256, state, reason_code, lease_version, expires_at
                         FROM commercial_token_workflow_leases
                        WHERE environment = %s AND mcp_token_id = %s AND request_id = %s
                        FOR UPDATE""",
                    (command.environment, str(command.token_id), command.request_id),
                )
                row = cursor.fetchone()
                if row is not None:
                    if row[0] != command_sha:
                        raise TokenLimitProtocolError("token limit idempotency conflict")
                    self._connection.commit()
                    return row, row[4]
                now = self._load_authority(cursor, command)
                expires_at = datetime.fromtimestamp(
                    int(now.timestamp()) + command.lease_ttl_seconds,
                    tz=timezone.utc,
                )
                cursor.execute(
                    """INSERT INTO commercial_token_workflow_leases (
                           id, environment, mcp_token_id, commercial_account_id,
                           agreement_terms_id, execution_context_id, workflow_run_id,
                           request_id, entitlement_revision, requests_per_minute,
                           requests_per_day, concurrent_workflows, policy_sha256,
                           command_sha256, lease_token, lease_version, redis_generation,
                           state, expires_at, reason_code)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                                 'pending',%s,'limit.pending')""",
                    self._insert_values(command, command_sha, expires_at),
                )
                self._insert_event(cursor, command, command_sha, "pending", "block", "limit.pending")
            self._connection.commit()
            return None, expires_at
        except Exception:
            self._rollback()
            raise

    def _load_authority(self, cursor, command) -> datetime:
        cursor.execute(
            """SELECT transaction_timestamp(), context.status, context.environment,
                      context.mcp_token_id, context.commercial_account_id,
                      context.agreement_terms_id, context.entitlement_revision,
                      workflow.state, token.status, token.expires_at,
                      revision.revision
                 FROM commercial_execution_contexts context
                 JOIN commercial_workflow_runs workflow
                   ON workflow.id = %s AND workflow.execution_context_id = context.id
                 JOIN mcp_tokens token ON token.id = context.mcp_token_id
                 JOIN commercial_entitlement_revisions revision
                   ON revision.commercial_account_id = context.commercial_account_id
                WHERE context.id = %s
                FOR SHARE OF context, workflow, token, revision""",
            (str(command.workflow_run_id), str(command.execution_context_id)),
        )
        row = cursor.fetchone()
        if row is None:
            raise TokenLimitProtocolError("token limit durable authority is missing")
        now = row[0]
        expected = (
            "active", command.environment, command.token_id,
            command.commercial_account_id, command.agreement_terms_id,
            command.entitlement_revision, "started", "active",
        )
        actual = (row[1], row[2], UUID(str(row[3])), int(row[4]), int(row[5]), int(row[6]), row[7], row[8])
        if actual != expected or row[9] <= now or int(row[10]) != command.entitlement_revision:
            raise TokenLimitProtocolError("token limit durable authority is stale")
        cursor.execute(
            """SELECT entitlement_key, value_json #>> '{}'
                 FROM commercial_entitlements
                WHERE commercial_account_id = %s AND agreement_terms_id = %s
                  AND entitlement_revision = %s AND subject_kind = 'mcp_token'
                  AND subject_mcp_token_id = %s AND effect = 'limit' AND status = 'active'
                  AND entitlement_key IN ('limit:requests-per-minute',
                      'limit:requests-per-day','limit:concurrent-workflows')
                  AND effective_from <= %s
                  AND (effective_until IS NULL OR effective_until > %s)
                ORDER BY entitlement_key FOR SHARE""",
            (command.commercial_account_id, command.agreement_terms_id,
             command.entitlement_revision, str(command.token_id), now, now),
        )
        values = {key: int(value) for key, value in cursor.fetchall()}
        expected_limits = {
            "limit:requests-per-minute": command.policy.requests_per_minute,
            "limit:requests-per-day": command.policy.requests_per_day,
            "limit:concurrent-workflows": command.policy.concurrent_workflows,
        }
        if values != expected_limits:
            raise TokenLimitProtocolError("token limit policy is not database authoritative")
        return now

    def _activate(self, command, command_sha, decision):
        with self._connection.cursor() as cursor:
            now = self._load_authority(cursor, command)
            cursor.execute(
                """UPDATE commercial_token_workflow_leases
                      SET state='active', acquired_at=%s, heartbeat_at=%s,
                          reason_code=%s, updated_at=%s
                    WHERE id=%s AND state='pending' AND command_sha256=%s
                    RETURNING expires_at""",
                (now, now, decision.reason_code, now, str(command.lease_id), command_sha),
            )
            if cursor.rowcount != 1:
                raise TokenLimitProtocolError("token limit activation lost durable fence")
            expires_at = cursor.fetchone()[0]
            self._insert_event(cursor, command, command_sha, "acquire", "allow", decision.reason_code, decision)
        try:
            self._connection.commit()
        except Exception as error:
            raise _PostgresCommitOutcomeUnknown(
                "token limit activation commit outcome is unknown"
            ) from error
        return TokenLimitAcquireResult(
            decision="allow", reason_code=decision.reason_code, lease_id=command.lease_id,
            state="active", lease_version=command.lease_version,
            expires_at=expires_at, replayed=False,
        )

    def _record_block(self, command, command_sha, decision):
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT transaction_timestamp()")
            now = cursor.fetchone()[0]
            cursor.execute(
                """UPDATE commercial_token_workflow_leases
                      SET state='blocked', released_at=%s, reason_code=%s, updated_at=%s
                    WHERE id=%s AND state='pending' AND command_sha256=%s
                    RETURNING expires_at""",
                (now, decision.reason_code, now, str(command.lease_id), command_sha),
            )
            if cursor.rowcount != 1:
                raise TokenLimitProtocolError("token limit block lost durable identity")
            expires_at = cursor.fetchone()[0]
            self._insert_event(cursor, command, command_sha, "block", "block", decision.reason_code, decision)
        try:
            self._connection.commit()
        except Exception as error:
            raise _PostgresCommitOutcomeUnknown(
                "token limit block commit outcome is unknown"
            ) from error
        return TokenLimitAcquireResult(
            decision="block", reason_code=decision.reason_code, lease_id=command.lease_id,
            state="blocked", lease_version=command.lease_version,
            expires_at=expires_at, replayed=False,
        )

    def _verify_replay(self, command, row):
        state = row[1]
        if state == "active":
            redis = self._redis.admit(self._redis_command(command, expires_at=row[4]))
            if redis.decision != "allow" or not redis.replayed:
                raise TokenLimitProtocolError("durable token lease lacks Redis authority")
            decision = "allow"
        elif state in {"blocked", "released"}:
            decision = "block"
        else:
            raise TokenLimitProtocolError("token limit lease is pending or requires repair")
        return TokenLimitAcquireResult(
            decision=decision, reason_code=row[2], lease_id=command.lease_id,
            state=state, lease_version=int(row[3]), expires_at=row[4], replayed=True,
        )

    def _mark_released(self, command, command_sha, reason):
        self._terminal_after_compensation(command, command_sha, "released", reason)

    def _mark_repair(self, command, command_sha, reason):
        self._terminal_after_compensation(command, command_sha, "repair_required", reason)

    def _terminal_after_compensation(self, command, command_sha, state, reason):
        self._rollback()
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT transaction_timestamp()")
            now = cursor.fetchone()[0]
            cursor.execute(
                """UPDATE commercial_token_workflow_leases
                      SET state=%s, acquired_at=COALESCE(acquired_at,%s),
                          heartbeat_at=COALESCE(heartbeat_at,%s), released_at=%s,
                          reason_code=%s, updated_at=%s
                    WHERE id=%s AND state='pending' AND command_sha256=%s""",
                (state, now, now, now, reason, now, str(command.lease_id), command_sha),
            )
            if cursor.rowcount != 1:
                raise TokenLimitProtocolError("token limit repair journal lost ownership")
            self._insert_event(cursor, command, command_sha,
                               "repair" if state == "repair_required" else "release",
                               "repair" if state == "repair_required" else "block", reason)
        self._connection.commit()

    @staticmethod
    def _insert_event(cursor, command, command_sha, kind, decision, reason, redis=None):
        event_id = uuid5(NAMESPACE_URL, f"token-limit:{command.lease_id}:{kind}:{command.lease_version}:{command_sha}")
        retry_at = None
        if redis is not None and redis.retry_at_epoch is not None:
            retry_at = datetime.fromtimestamp(redis.retry_at_epoch, tz=timezone.utc)
        cursor.execute(
            """INSERT INTO commercial_token_limit_events (
                   event_id, lease_id, event_kind, command_sha256, lease_version,
                   decision, reason_code, minute_count, day_count, active_workflows,
                   retry_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                 ON CONFLICT (event_id) DO NOTHING""",
            (str(event_id), str(command.lease_id), kind, command_sha,
             command.lease_version, decision, reason,
             redis.minute_count if redis else None, redis.day_count if redis else None,
             redis.active_workflows if redis else None, retry_at),
        )

    @staticmethod
    def _insert_values(command, command_sha, expires_at):
        return (
            str(command.lease_id), command.environment, str(command.token_id),
            command.commercial_account_id, command.agreement_terms_id,
            str(command.execution_context_id), str(command.workflow_run_id),
            command.request_id, command.entitlement_revision,
            command.policy.requests_per_minute, command.policy.requests_per_day,
            command.policy.concurrent_workflows,
            canonical_sha256(command.policy.model_dump(mode="json")), command_sha,
            str(command.lease_token), command.lease_version, command.redis_generation,
            expires_at,
        )

    @staticmethod
    def _redis_command(command, *, expires_at):
        return TokenLimitAdmissionCommand(
            token_id=command.token_id, workflow_run_id=command.workflow_run_id,
            request_id=command.request_id, lease_id=command.lease_id,
            lease_token=command.lease_token, lease_version=command.lease_version,
            entitlement_revision=command.entitlement_revision,
            redis_generation=command.redis_generation,
            lease_expires_at_epoch=int(expires_at.timestamp()), policy=command.policy,
        )


    def _assert_idle(self):
        status = getattr(self._connection, "get_transaction_status", lambda: 0)()
        if status != 0:
            raise TokenLimitProtocolError("token limit protocol requires an idle connection")

    def _rollback(self):
        try:
            self._connection.rollback()
        except Exception:
            pass


__all__ = [
    "TokenLimitAcquireCommand", "TokenLimitAcquireProtocol",
    "TokenLimitAcquireResult", "TokenLimitProtocolError",
    "TokenLimitHeartbeatCommand", "TokenLimitLifecycleProtocol",
    "TokenLimitLifecycleResult", "TokenLimitReleaseCommand", "TokenLimitReapCommand",
]
