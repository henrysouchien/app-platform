"""Dry-run-first comparison of durable token-limit authority and Redis."""

from __future__ import annotations

from importlib import resources
import json
from typing import Literal
from uuid import UUID

from pydantic import Field

from ..flags import CommercialFlags
from ..models import StrictCommercialModel
from ..models import canonical_sha256
from .rebuild_protocol import TokenLimitRebuildCommand, TokenLimitRebuildProtocol
from .models import TokenLimitPolicy
from .redis_store import CommercialTokenLimitRedisError


class TokenLimitReconciliationCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    token_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=128, pattern=r"^\S+$")
    repair: bool = False


class TokenLimitReconciliationResult(StrictCommercialModel):
    token_id: UUID
    clean: bool
    issues: tuple[str, ...]
    repaired: bool
    generation: int | None


class TokenLimitReconciliationProtocol:
    def __init__(self, connection, redis_client, rebuild_store, *, flags: CommercialFlags):
        flags.validate()
        if not flags.commercial_token_limit_enforcement_enabled:
            raise CommercialTokenLimitRedisError("token reconciliation requires enforcement")
        self._connection, self._client, self._rebuild_store = connection, redis_client, rebuild_store
        self._flags = flags
        self._script = resources.files(__package__).joinpath("lua/generation_snapshot.lua").read_text()
        self._sha = None

    def reconcile(self, command: TokenLimitReconciliationCommand):
        command = TokenLimitReconciliationCommand.model_validate(command.model_dump())
        if command.environment != self._flags.environment:
            raise CommercialTokenLimitRedisError("token reconciliation environment mismatch")
        durable = self._durable(command)
        redis = self._redis_snapshot(command)
        issues = self._compare(durable, redis)
        if issues and command.repair:
            if durable["authority_state"] != "stable":
                self._reset_unresolved(command)
            repair_key = canonical_sha256(command.model_dump(mode="json")).split(":", 1)[1]
            TokenLimitRebuildProtocol(
                self._connection, self._rebuild_store, flags=self._flags
            ).rebuild(TokenLimitRebuildCommand(
                environment=command.environment, token_id=command.token_id,
                idempotency_key=f"repair-{repair_key[:64]}",
                reason_code="limit.reconciliation_rebuild",
            ))
            durable = self._durable(command)
            redis = self._redis_snapshot(command)
            remaining = self._compare(durable, redis)
            if remaining:
                raise CommercialTokenLimitRedisError(
                    f"token reconciliation repair did not converge: {','.join(remaining)}"
                )
            return TokenLimitReconciliationResult(
                token_id=command.token_id, clean=True, issues=issues, repaired=True,
                generation=redis.get("generation"),
            )
        return TokenLimitReconciliationResult(
            token_id=command.token_id, clean=not issues, issues=issues, repaired=False,
            generation=redis.get("generation"),
        )

    def _durable(self, command):
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT transaction_timestamp()")
            now = cursor.fetchone()[0]
            cursor.execute(
                """SELECT current_generation,state
                     FROM commercial_token_limit_authorities
                    WHERE environment=%s AND mcp_token_id=%s""",
                (command.environment, str(command.token_id)),
            )
            authority = cursor.fetchone()
            if authority is None:
                raise CommercialTokenLimitRedisError("token reconciliation authority is missing")
            minute_start, day_start = int(now.timestamp()) // 60 * 60, int(now.timestamp()) // 86400 * 86400
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
                    WHERE token.id=%s AND entitlement.effect='limit'
                      AND entitlement.status='active' AND entitlement.effective_from<=%s
                      AND (entitlement.effective_until IS NULL OR entitlement.effective_until>%s)
                      AND entitlement.entitlement_key IN ('limit:requests-per-minute',
                          'limit:requests-per-day','limit:concurrent-workflows')
                    ORDER BY entitlement.entitlement_key""",
                (str(command.token_id), now, now),
            )
            policy_rows = cursor.fetchall()
            if len(policy_rows) != 3:
                raise CommercialTokenLimitRedisError("token reconciliation lacks current policy")
            values = {row[1]: int(row[2]) for row in policy_rows}
            resolved = TokenLimitPolicy(
                requests_per_minute=values["limit:requests-per-minute"],
                requests_per_day=values["limit:requests-per-day"],
                concurrent_workflows=values["limit:concurrent-workflows"],
            )
            policy = (int(policy_rows[0][0]), canonical_sha256(resolved.model_dump(mode="json")))
            cursor.execute(
                """SELECT id, lease_token, lease_version, redis_generation,
                          EXTRACT(EPOCH FROM expires_at)::BIGINT
                     FROM commercial_token_workflow_leases
                    WHERE environment=%s AND mcp_token_id=%s AND state='active' ORDER BY id""",
                (command.environment, str(command.token_id)),
            )
            leases = cursor.fetchall()
            cursor.execute(
                """SELECT COUNT(*) FILTER (WHERE event.occurred_at >= to_timestamp(%s)),
                          COUNT(*) FILTER (WHERE event.occurred_at >= to_timestamp(%s))
                     FROM commercial_token_limit_events event
                     JOIN commercial_token_workflow_leases lease ON lease.id=event.lease_id
                    WHERE lease.environment=%s AND lease.mcp_token_id=%s
                      AND event.event_kind='acquire' AND event.decision='allow'
                      AND lease.reason_code <> 'limit.compensated'""",
                (minute_start, day_start, command.environment, str(command.token_id)),
            )
            minute_count, day_count = map(int, cursor.fetchone())
        self._connection.rollback()
        return {"revision": int(policy[0]), "policy": policy[1], "minute_start": minute_start,
                "day_start": day_start, "minute_count": minute_count, "day_count": day_count,
                "generation": int(authority[0]), "authority_state": authority[1],
                "leases": {(str(row[0]), str(row[1]), int(row[2]), int(row[4])) for row in leases}}

    def _reset_unresolved(self, command):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE commercial_token_limit_authorities
                      SET state='stable',transition_id=NULL,updated_at=transaction_timestamp()
                    WHERE environment=%s AND mcp_token_id=%s AND state<>'stable'""",
                (command.environment, str(command.token_id)),
            )
            if cursor.rowcount != 1:
                raise CommercialTokenLimitRedisError("token unresolved transition changed")
        self._connection.commit()

    def _redis_snapshot(self, command):
        key = self._rebuild_store.pointer_key(command.environment, "enforce", command.token_id)
        try:
            if self._sha is None:
                self._sha = self._client.script_load(self._script)
            try:
                raw = self._client.evalsha(self._sha, 1, key)
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(self._script, 1, key)
            if isinstance(raw, bytes):
                raw = raw.decode()
            return json.loads(raw)
        except Exception as error:
            raise CommercialTokenLimitRedisError("token reconciliation snapshot unavailable") from error

    @staticmethod
    def _compare(durable, redis):
        issues = []
        if not redis.get("present"):
            return ("limit.redis_generation_missing",)
        if durable["authority_state"] != "stable":
            issues.append("limit.generation_transition_unresolved")
        pairs = (("generation", "generation", "limit.generation_mismatch"),
                 ("revision", "entitlement_revision", "limit.entitlement_revision_mismatch"),
                 ("policy", "policy_sha256", "limit.policy_mismatch"),
                 ("minute_start", "minute_start_epoch", "limit.minute_window_mismatch"),
                 ("minute_count", "minute_count", "limit.minute_count_mismatch"),
                 ("day_start", "day_start_epoch", "limit.day_window_mismatch"),
                 ("day_count", "day_count", "limit.day_count_mismatch"))
        for left, right, code in pairs:
            if durable[left] != redis.get(right):
                issues.append(code)
        redis_leases = {(row["lease_id"], row["lease_token"], row["lease_version"], row["expires_at_epoch"])
                        for row in redis.get("leases", [])}
        if durable["leases"] != redis_leases:
            issues.append("limit.active_leases_mismatch")
        return tuple(issues)
