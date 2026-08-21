"""PostgreSQL-authoritative token-limit generation rebuild protocol."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, StrictInt

from ..flags import CommercialFlags
from ..models import StrictCommercialModel, canonical_sha256
from .models import TokenLimitPolicy
from .rebuild_store import (
    TokenLimitGenerationBuildCommand,
    TokenLimitRebuildLease,
)
from .redis_store import TokenLimitAdmissionCommand


PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]


class TokenLimitRebuildError(RuntimeError):
    pass


class TokenLimitRebuildCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    token_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=128, pattern=r"^\S+$")
    reason_code: str = Field(default="limit.rebuild", pattern=r"^[a-z][a-z0-9._:-]{0,127}$")


class TokenLimitRebuildResult(StrictCommercialModel):
    token_id: UUID
    expected_generation: PositiveSafeInt
    target_generation: PositiveSafeInt
    snapshot_sha256: str
    minute_count: Annotated[StrictInt, Field(ge=0)]
    day_count: Annotated[StrictInt, Field(ge=0)]
    active_leases: Annotated[StrictInt, Field(ge=0)]
    replayed: bool


class TokenLimitRebuildProtocol:
    def __init__(self, connection, redis_store, *, flags: CommercialFlags) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise TokenLimitRebuildError("token rebuild requires transactions")
        if not flags.commercial_token_limit_enforcement_enabled:
            raise TokenLimitRebuildError("token rebuild requires enforcement")
        self._connection, self._redis, self._flags = connection, redis_store, flags

    def rebuild(self, command: TokenLimitRebuildCommand) -> TokenLimitRebuildResult:
        command = TokenLimitRebuildCommand.model_validate(command.model_dump())
        if command.environment != self._flags.environment:
            raise TokenLimitRebuildError("token rebuild environment mismatch")
        self._require_idle()
        command_sha = canonical_sha256(command.model_dump(mode="json"))
        transition_id = uuid5(NAMESPACE_URL, f"token-limit-rebuild:{command_sha}")
        cas_started = False
        try:
            replay = self._replay(command, command_sha)
            if replay is not None:
                return replay
            self._begin_transition(command, transition_id)
            authority = self._lock_authority(command, transition_id)
            build = self._build_command(command, authority)
            staged = self._redis.build(build)
            if staged.decision != "allow":
                raise TokenLimitRebuildError(f"token generation staging rejected: {staged.reason_code}")
            cas_started = True
            swapped = self._redis.compare_and_set(build)
            if swapped.decision != "allow":
                raise TokenLimitRebuildError(f"token generation CAS rejected: {swapped.reason_code}")
            result = self._record(command, command_sha, build, transition_id,
                                  replayed=staged.replayed or swapped.replayed)
            try:
                self._connection.commit()
            except Exception as error:
                raise TokenLimitRebuildError(
                    "token generation PostgreSQL commit outcome is unknown; reconcile before work"
                ) from error
            return result
        except Exception:
            self._connection.rollback()
            if not cas_started:
                self._restore_stable(command, transition_id)
            raise

    def _replay(self, command, command_sha):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT command_sha256, snapshot_sha256, expected_generation,
                          target_generation, minute_count, day_count, active_leases
                     FROM commercial_token_limit_rebuilds
                    WHERE environment=%s AND mcp_token_id=%s AND idempotency_key=%s""",
                (command.environment, str(command.token_id), command.idempotency_key),
            )
            row = cursor.fetchone()
        self._connection.commit()
        if row is None:
            return None
        if row[0] != command_sha:
            raise TokenLimitRebuildError("token rebuild idempotency conflict")
        return TokenLimitRebuildResult(
            token_id=command.token_id, expected_generation=row[2], target_generation=row[3],
            snapshot_sha256=row[1], minute_count=row[4], day_count=row[5],
            active_leases=row[6], replayed=True,
        )

    def _begin_transition(self, command, transition_id):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT current_generation,state,transition_id
                     FROM commercial_token_limit_authorities
                    WHERE environment=%s AND mcp_token_id=%s FOR UPDATE""",
                (command.environment, str(command.token_id)),
            )
            row = cursor.fetchone()
            if row is None:
                raise TokenLimitRebuildError("token rebuild authority is missing")
            if row[1] == "rebuilding" and row[2] == transition_id:
                self._connection.commit()
                return
            if row[1] != "stable":
                raise TokenLimitRebuildError("token generation transition is unresolved")
            cursor.execute(
                """SELECT COUNT(*) FROM commercial_token_workflow_leases
                    WHERE environment=%s AND mcp_token_id=%s AND state='pending'""",
                (command.environment, str(command.token_id)),
            )
            if cursor.fetchone()[0]:
                raise TokenLimitRebuildError("token rebuild waits for pending admissions")
            cursor.execute(
                """UPDATE commercial_token_limit_authorities
                      SET state='rebuilding',transition_id=%s,updated_at=transaction_timestamp()
                    WHERE environment=%s AND mcp_token_id=%s AND state='stable'""",
                (str(transition_id), command.environment, str(command.token_id)),
            )
        self._connection.commit()

    def _restore_stable(self, command, transition_id):
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE commercial_token_limit_authorities
                          SET state='stable',transition_id=NULL,updated_at=transaction_timestamp()
                        WHERE environment=%s AND mcp_token_id=%s
                          AND state='rebuilding' AND transition_id=%s""",
                    (command.environment, str(command.token_id), str(transition_id)),
                )
            self._connection.commit()
        except Exception:
            self._connection.rollback()

    def _lock_authority(self, command, transition_id):
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                           (f"token-limit-rebuild:{command.environment}:{command.token_id}",))
            cursor.execute(
                """SELECT current_generation,state,transition_id
                     FROM commercial_token_limit_authorities
                    WHERE environment=%s AND mcp_token_id=%s FOR UPDATE""",
                (command.environment, str(command.token_id)),
            )
            token_authority = cursor.fetchone()
            if token_authority is None or (
                token_authority[1] != "rebuilding"
                or UUID(str(token_authority[2])) != transition_id
            ):
                raise TokenLimitRebuildError("token rebuild lost transition authority")
            cursor.execute("SELECT transaction_timestamp()")
            now = cursor.fetchone()[0]
            cursor.execute(
                """SELECT revision.revision, entitlement.entitlement_key,
                          (entitlement.value_json #>> '{}')::BIGINT
                     FROM mcp_tokens token
                     JOIN commercial_entitlement_revisions revision
                       ON revision.commercial_account_id=token.commercial_account_id
                     JOIN commercial_entitlements entitlement
                       ON entitlement.commercial_account_id=token.commercial_account_id
                      AND entitlement.entitlement_revision=revision.revision
                      AND entitlement.subject_kind='mcp_token'
                      AND entitlement.subject_mcp_token_id=token.id
                    WHERE token.id=%s AND token.status='active' AND token.expires_at>%s
                      AND entitlement.effect='limit' AND entitlement.status='active'
                      AND entitlement.effective_from<=%s
                      AND (entitlement.effective_until IS NULL OR entitlement.effective_until>%s)
                      AND entitlement.entitlement_key IN ('limit:requests-per-minute',
                          'limit:requests-per-day','limit:concurrent-workflows')
                    ORDER BY entitlement.entitlement_key FOR SHARE OF token,revision,entitlement""",
                (str(command.token_id), now, now, now),
            )
            policy_rows = cursor.fetchall()
            if len(policy_rows) != 3 or len({int(row[0]) for row in policy_rows}) != 1:
                raise TokenLimitRebuildError("token rebuild current policy authority is invalid")
            values = {row[1]: int(row[2]) for row in policy_rows}
            revision = int(policy_rows[0][0])
            resolved = TokenLimitPolicy(
                requests_per_minute=values["limit:requests-per-minute"],
                requests_per_day=values["limit:requests-per-day"],
                concurrent_workflows=values["limit:concurrent-workflows"],
            )
            policy = (
                revision, resolved.requests_per_minute, resolved.requests_per_day,
                resolved.concurrent_workflows,
                canonical_sha256(resolved.model_dump(mode="json")), int(token_authority[0]),
            )
            cursor.execute(
                """SELECT id, workflow_run_id, request_id, lease_token, lease_version,
                          entitlement_revision, expires_at
                     FROM commercial_token_workflow_leases
                    WHERE environment=%s AND mcp_token_id=%s AND state='active'
                    ORDER BY id FOR UPDATE""",
                (command.environment, str(command.token_id)),
            )
            leases = cursor.fetchall()
            cursor.execute(
                """SELECT DISTINCT redis_generation
                     FROM commercial_token_workflow_leases
                    WHERE environment=%s AND mcp_token_id=%s AND state='active'""",
                (command.environment, str(command.token_id)),
            )
            generations = {int(row[0]) for row in cursor.fetchall()}
            if len(generations) > 1:
                raise TokenLimitRebuildError("active token leases span durable generations")
            minute_start = int(now.timestamp()) // 60 * 60
            day_start = int(now.timestamp()) // 86400 * 86400
            cursor.execute(
                """SELECT
                    COUNT(*) FILTER (WHERE event.occurred_at >= to_timestamp(%s)),
                    COUNT(*) FILTER (WHERE event.occurred_at >= to_timestamp(%s))
                   FROM commercial_token_limit_events event
                   JOIN commercial_token_workflow_leases lease ON lease.id=event.lease_id
                  WHERE lease.environment=%s AND lease.mcp_token_id=%s
                    AND event.event_kind='acquire' AND event.decision='allow'
                    AND lease.reason_code <> 'limit.compensated'""",
                (minute_start, day_start, command.environment, str(command.token_id)),
            )
            minute_count, day_count = map(int, cursor.fetchone())
        pointer, _ = self._redis.current_generation(
            environment=command.environment, mode="enforce", token_id=command.token_id
        )
        expected = pointer or (next(iter(generations)) if generations else int(policy[5]))
        durable_generation = next(iter(generations)) if generations else int(policy[5])
        if durable_generation > expected:
            raise TokenLimitRebuildError("durable token generation is ahead of Redis pointer")
        return {"policy": policy, "leases": leases, "expected": expected,
                "durable_generation": durable_generation,
                "minute_start": minute_start, "day_start": day_start,
                "minute_count": minute_count, "day_count": day_count}

    def _build_command(self, command, authority):
        revision, rpm, rpd, concurrent, policy_sha, _ = authority["policy"]
        policy = TokenLimitPolicy(requests_per_minute=rpm, requests_per_day=rpd,
                                  concurrent_workflows=concurrent)
        target = authority["expected"] + 1
        leases = []
        generation_delta = target - authority["durable_generation"]
        for row in authority["leases"]:
            admission = TokenLimitAdmissionCommand(
                token_id=command.token_id, workflow_run_id=row[1], request_id=row[2],
                lease_id=row[0], lease_token=row[3], lease_version=int(row[4]) + generation_delta,
                entitlement_revision=row[5], redis_generation=target,
                lease_expires_at_epoch=int(row[6].timestamp()), policy=policy,
            )
            digest = canonical_sha256({"environment": command.environment, "mode": "enforce",
                                       **admission.model_dump(mode="json")})
            leases.append(TokenLimitRebuildLease(
                lease_id=row[0], workflow_run_id=row[1], request_id=row[2],
                lease_token=row[3], lease_version=int(row[4]) + generation_delta,
                entitlement_revision=row[5], expires_at_epoch=int(row[6].timestamp()),
                admission_digest=digest,
            ))
        body = dict(environment=command.environment, mode="enforce", token_id=command.token_id,
                    expected_generation=authority["expected"], target_generation=target,
                    entitlement_revision=revision, policy_sha256=policy_sha,
                    requests_per_minute=rpm, requests_per_day=rpd,
                    concurrent_workflows=concurrent,
                    minute_start_epoch=authority["minute_start"],
                    minute_count=authority["minute_count"], day_start_epoch=authority["day_start"],
                    day_count=authority["day_count"], leases=tuple(leases))
        return TokenLimitGenerationBuildCommand(
            snapshot_sha256=canonical_sha256(body), **body
        )

    def _record(self, command, command_sha, build, transition_id, *, replayed):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT COALESCE(MIN(redis_generation), %s),
                          COALESCE(MAX(redis_generation), %s)
                     FROM commercial_token_workflow_leases
                    WHERE environment=%s AND mcp_token_id=%s AND state='active'""",
                (build.expected_generation, build.expected_generation,
                 command.environment, str(command.token_id)),
            )
            minimum, maximum = map(int, cursor.fetchone())
            if minimum != maximum or minimum > build.target_generation:
                raise TokenLimitRebuildError("durable token generations are inconsistent")
            for generation in range(minimum + 1, build.target_generation + 1):
                cursor.execute(
                    """UPDATE commercial_token_workflow_leases
                          SET redis_generation=%s, lease_version=lease_version+1,
                              updated_at=clock_timestamp()
                        WHERE environment=%s AND mcp_token_id=%s AND state='active'
                          AND redis_generation=%s""",
                    (generation, command.environment, str(command.token_id), generation - 1),
                )
                if cursor.rowcount != len(build.leases):
                    raise TokenLimitRebuildError("durable token generation cutover lost fence")
            cursor.execute(
                """INSERT INTO commercial_token_limit_rebuilds (
                    environment,mcp_token_id,idempotency_key,command_sha256,snapshot_sha256,
                    expected_generation,target_generation,minute_count,day_count,active_leases,
                    reason_code) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (command.environment, str(command.token_id), command.idempotency_key,
                 command_sha, build.snapshot_sha256, build.expected_generation,
                 build.target_generation, build.minute_count, build.day_count,
                len(build.leases), command.reason_code),
            )
            cursor.execute(
                """UPDATE commercial_token_limit_authorities
                      SET current_generation=%s,state='stable',transition_id=NULL,
                          updated_at=clock_timestamp()
                    WHERE environment=%s AND mcp_token_id=%s
                      AND state='rebuilding' AND transition_id=%s""",
                (build.target_generation, command.environment, str(command.token_id),
                 str(transition_id)),
            )
            if cursor.rowcount != 1:
                raise TokenLimitRebuildError("token rebuild lost durable transition fence")
        return TokenLimitRebuildResult(
            token_id=command.token_id, expected_generation=build.expected_generation,
            target_generation=build.target_generation, snapshot_sha256=build.snapshot_sha256,
            minute_count=build.minute_count, day_count=build.day_count,
            active_leases=len(build.leases), replayed=replayed,
        )

    def _require_idle(self):
        if getattr(self._connection, "get_transaction_status", lambda: 0)() != 0:
            raise TokenLimitRebuildError("token rebuild requires idle connection")
