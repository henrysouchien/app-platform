"""Atomic Redis admission for per-token request and workflow limits."""

from __future__ import annotations

from importlib import resources
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictInt

from ..flags import CommercialFlags
from ..models import StrictCommercialModel, canonical_sha256
from .models import TokenLimitPolicy


PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]


class CommercialTokenLimitRedisError(RuntimeError):
    """Token-limit Redis authority is unavailable or malformed."""


class TokenLimitAdmissionCommand(StrictCommercialModel):
    token_id: UUID
    workflow_run_id: UUID
    request_id: Annotated[str, Field(min_length=1, max_length=128)]
    lease_id: UUID
    lease_token: UUID
    lease_version: PositiveSafeInt
    entitlement_revision: PositiveSafeInt
    redis_generation: PositiveSafeInt
    lease_expires_at_epoch: PositiveSafeInt
    policy: TokenLimitPolicy


class TokenLimitAdmissionDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: Literal[
        "limit.allowed",
        "limit.requests_per_minute",
        "limit.requests_per_day",
        "limit.concurrent_workflows",
        "limit.idempotency_conflict",
        "limit.lease_identity_conflict",
        "limit.authority_conflict",
        "limit.compensated",
    ]
    lease_id: UUID
    lease_version: PositiveSafeInt
    replayed: bool
    minute_count: Annotated[StrictInt, Field(ge=0, le=2**52 - 1)]
    day_count: Annotated[StrictInt, Field(ge=0, le=2**52 - 1)]
    active_workflows: Annotated[StrictInt, Field(ge=0, le=2**52 - 1)]
    retry_at_epoch: Annotated[StrictInt, Field(ge=0, le=2**52 - 1)] | None


class TokenLimitLeaseCommand(StrictCommercialModel):
    token_id: UUID
    lease_id: UUID
    lease_token: UUID
    lease_version: PositiveSafeInt
    redis_generation: PositiveSafeInt
    operation_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^\S+$")]
    expires_at_epoch: PositiveSafeInt | None = None


class TokenLimitLeaseDecision(StrictCommercialModel):
    outcome: Literal["heartbeat", "released", "expired"]
    reason_code: Literal[
        "limit.heartbeat", "limit.released", "limit.expired",
    ]
    lease_id: UUID
    lease_version: PositiveSafeInt
    expires_at_epoch: PositiveSafeInt
    active_workflows: Annotated[StrictInt, Field(ge=0, le=2**52 - 1)]
    replayed: bool


class CommercialTokenLimitRedisStore:
    def __init__(self, client, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not (
            flags.commercial_control_enabled
            and (
                flags.commercial_token_limit_shadow_mode
                or flags.commercial_token_limit_enforcement_enabled
            )
        ):
            raise CommercialTokenLimitRedisError("commercial token limits are disabled")
        self._client = client
        self._environment = flags.environment
        self._mode = (
            "enforce" if flags.commercial_token_limit_enforcement_enabled else "shadow"
        )
        self._script = (
            resources.files(__package__).joinpath("lua/admit.lua").read_text(encoding="utf-8")
        )
        self._release_script = (
            resources.files(__package__).joinpath("lua/release.lua").read_text(encoding="utf-8")
        )
        lua = resources.files(__package__).joinpath("lua")
        self._heartbeat_script = lua.joinpath("heartbeat.lua").read_text(encoding="utf-8")
        self._terminal_release_script = lua.joinpath("terminal_release.lua").read_text(encoding="utf-8")
        self._reap_script = lua.joinpath("reap.lua").read_text(encoding="utf-8")
        self._sha: str | None = None
        self._release_sha: str | None = None
        self._lifecycle_shas: dict[str, str] = {}

    def admit(self, command: TokenLimitAdmissionCommand) -> TokenLimitAdmissionDecision:
        command = TokenLimitAdmissionCommand.model_validate(command.model_dump())
        keys = build_token_limit_keys(
            environment=self._environment,
            mode=self._mode,
            token_id=command.token_id,
            lease_id=command.lease_id,
            request_id=command.request_id,
            generation=command.redis_generation,
        )
        argv = (
            str(command.workflow_run_id), command.request_id, str(command.lease_id),
            str(command.lease_token), str(command.lease_version),
            str(command.entitlement_revision), _admission_digest(
                command, environment=self._environment, mode=self._mode
            ), canonical_sha256(command.policy.model_dump(mode="json")),
            str(command.lease_expires_at_epoch), str(command.policy.requests_per_minute),
            str(command.policy.requests_per_day), str(command.policy.concurrent_workflows),
            str(command.redis_generation),
        )
        try:
            if self._sha is None:
                self._sha = self._client.script_load(self._script)
            try:
                raw = self._client.evalsha(self._sha, len(keys), *keys, *argv)
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(self._script, len(keys), *keys, *argv)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            document = json.loads(raw)
            return TokenLimitAdmissionDecision.model_validate(document)
        except Exception as error:
            if isinstance(error, CommercialTokenLimitRedisError):
                raise
            raise CommercialTokenLimitRedisError(
                f"commercial token-limit Redis unavailable or invalid: {error}"
            ) from error

    def compensate(self, command: TokenLimitAdmissionCommand) -> TokenLimitAdmissionDecision:
        command = TokenLimitAdmissionCommand.model_validate(command.model_dump())
        keys = build_token_limit_keys(
            environment=self._environment, mode=self._mode, token_id=command.token_id,
            lease_id=command.lease_id, request_id=command.request_id,
            generation=command.redis_generation,
        )
        digest = _admission_digest(
            command, environment=self._environment, mode=self._mode
        )
        argv = (
            str(command.lease_id), str(command.lease_token),
            str(command.lease_version), digest, str(command.redis_generation),
        )
        try:
            if self._release_sha is None:
                self._release_sha = self._client.script_load(self._release_script)
            try:
                raw = self._client.evalsha(
                    self._release_sha, len(keys), *keys, *argv
                )
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(
                    self._release_script, len(keys), *keys, *argv
                )
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return TokenLimitAdmissionDecision.model_validate(json.loads(raw))
        except Exception as error:
            raise CommercialTokenLimitRedisError(
                f"commercial token-limit compensation unavailable or invalid: {error}"
            ) from error

    def heartbeat(self, command: TokenLimitLeaseCommand) -> TokenLimitLeaseDecision:
        if command.expires_at_epoch is None:
            raise CommercialTokenLimitRedisError("heartbeat requires an expiry")
        return self._lifecycle("heartbeat", command, self._heartbeat_script)

    def terminal_release(self, command: TokenLimitLeaseCommand) -> TokenLimitLeaseDecision:
        if command.expires_at_epoch is not None:
            raise CommercialTokenLimitRedisError("terminal release must not change expiry")
        return self._lifecycle("release", command, self._terminal_release_script)

    def reap(self, command: TokenLimitLeaseCommand) -> TokenLimitLeaseDecision:
        if command.expires_at_epoch is None:
            raise CommercialTokenLimitRedisError("reaping requires the observed expiry")
        return self._lifecycle("reap", command, self._reap_script)

    def _lifecycle(self, operation, command, script):
        command = TokenLimitLeaseCommand.model_validate(command.model_dump())
        keys = build_token_limit_lifecycle_keys(
            environment=self._environment, mode=self._mode, token_id=command.token_id,
            lease_id=command.lease_id, operation=operation,
            operation_id=command.operation_id, generation=command.redis_generation,
        )
        digest = canonical_sha256({
            "environment": self._environment, "mode": self._mode,
            "operation": operation, **command.model_dump(mode="json"),
        })
        argv = (
            str(command.lease_id), str(command.lease_token), str(command.lease_version),
            digest, str(command.expires_at_epoch or 0), str(command.redis_generation),
        )
        try:
            sha = self._lifecycle_shas.get(operation)
            if sha is None:
                sha = self._client.script_load(script)
                self._lifecycle_shas[operation] = sha
            try:
                raw = self._client.evalsha(sha, len(keys), *keys, *argv)
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(script, len(keys), *keys, *argv)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return TokenLimitLeaseDecision.model_validate(json.loads(raw))
        except Exception as error:
            raise CommercialTokenLimitRedisError(
                f"commercial token-limit {operation} unavailable or invalid: {error}"
            ) from error


def build_token_limit_keys(
    *, environment: str, mode: str, token_id: UUID, lease_id: UUID, request_id: str,
    generation: int = 1,
) -> tuple[str, str, str, str, str]:
    if environment not in {"dev", "staging", "prod"} or mode not in {"shadow", "enforce"}:
        raise ValueError("token-limit key namespace is invalid")
    if not request_id or len(request_id) > 128 or any(ord(char) < 33 for char in request_id):
        raise ValueError("token-limit request identity is invalid")
    if not 0 < generation <= 2**52 - 1:
        raise ValueError("token-limit generation is invalid")
    tag = f"{{{environment}:{token_id}}}"
    base = f"commercial:limit:v1:{mode}:{tag}"
    prefix = f"{base}:g{generation}"
    return (
        f"{prefix}:counters",
        f"{prefix}:leases",
        f"{prefix}:lease:{lease_id}",
        f"{prefix}:idem:{request_id}",
        f"{base}:generation",
    )


def build_token_limit_lifecycle_keys(
    *, environment: str, mode: str, token_id: UUID, lease_id: UUID,
    operation: str, operation_id: str,
    generation: int = 1,
) -> tuple[str, str, str, str]:
    if operation not in {"heartbeat", "release", "reap"}:
        raise ValueError("token-limit lifecycle operation is invalid")
    if not operation_id or len(operation_id) > 128 or any(char.isspace() for char in operation_id):
        raise ValueError("token-limit lifecycle operation identity is invalid")
    base = build_token_limit_keys(
        environment=environment, mode=mode, token_id=token_id,
        lease_id=lease_id, request_id=operation_id,
        generation=generation,
    )
    prefix = base[1].rsplit(":leases", 1)[0]
    return base[1], base[2], f"{prefix}:lifecycle:{operation}:{operation_id}", base[4]


def _admission_digest(command, *, environment: str, mode: str) -> str:
    return canonical_sha256({
        "environment": environment,
        "mode": mode,
        **command.model_dump(mode="json"),
    })


__all__ = [
    "CommercialTokenLimitRedisError", "CommercialTokenLimitRedisStore",
    "TokenLimitAdmissionCommand", "TokenLimitAdmissionDecision",
    "TokenLimitLeaseCommand", "TokenLimitLeaseDecision",
    "build_token_limit_keys", "build_token_limit_lifecycle_keys",
]
