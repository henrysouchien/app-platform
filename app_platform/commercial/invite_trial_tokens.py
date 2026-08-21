"""One-time MCP token issuance for an activated invite-only trial."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictBool

from .agreement_lifecycle import IdempotencyKey
from .flags import CommercialFlags
from .invite_trials import Environment, InviteTrialError
from .mcp_token_codec import McpTokenPepperRing
from .mcp_token_lifecycle import (
    McpTokenLifecycleService,
    McpTokenRevokeCommand,
)
from .mcp_tokens import (
    McpTokenLifetimePolicy,
    McpTokenMintCommand,
    McpTokenMintResult,
    McpTokenService,
)
from .models import StableCode, StrictCommercialModel, canonical_sha256


TRIAL_TOKEN_SCOPES = ("scope:read", "scope:trade-preview")
TRIAL_REQUESTS_PER_MINUTE = 60
TRIAL_REQUESTS_PER_DAY = 1000
TRIAL_CONCURRENT_WORKFLOWS = 2
TRIAL_MODEL_CAP_MICROUSD = 2_000_000
TRIAL_TECHNICAL_CAP_MICROUSD = 19_800_000
TRIAL_MAX_SINGLE_RESERVATION_MICROUSD = 2_000_000
TRIAL_TOP_UP_QUANTUM_MICROUSD = 50_000
TRIAL_MAX_UNRESERVED_DELTA_MICROUSD = 10_000
TRIAL_LATE_CHILD_ALLOWANCE_MICROUSD = 100_000
TRIAL_MAX_PERIOD_OVERDRAFT_MICROUSD = 120_000


class TrialTokenIssueCommand(StrictCommercialModel):
    activation_id: UUID
    idempotency_key: IdempotencyKey


class TrialTokenRecoverCommand(StrictCommercialModel):
    activation_id: UUID
    idempotency_key: IdempotencyKey


class TrialTokenIssueResult(StrictCommercialModel):
    activation_id: UUID
    token_id: UUID
    token: str | None = Field(default=None, repr=False)
    secret_available: StrictBool
    expires_at: AwareDatetime
    requested_scopes: tuple[StableCode, ...]
    requests_per_minute: Annotated[int, Field(gt=0)]
    requests_per_day: Annotated[int, Field(gt=0)]
    concurrent_workflows: Annotated[int, Field(gt=0)]
    model_cap_microusd: Annotated[int, Field(gt=0)]
    technical_cap_microusd: Annotated[int, Field(gt=0)]
    generation: Annotated[int, Field(ge=1, le=2)]
    recovered: StrictBool = False
    replayed: StrictBool = False


class InviteTrialTokenService:
    """Mint the sole token whose lineage owns all trial provider work and cost."""

    def __init__(
        self,
        connection: Any,
        *,
        flags: CommercialFlags,
        pepper_ring: McpTokenPepperRing,
        lifetime_policy: McpTokenLifetimePolicy,
    ) -> None:
        flags.validate()
        if not flags.invite_trial_enabled:
            raise InviteTrialError("Invite trials are disabled")
        self._connection = connection
        self._flags = flags
        self._pepper_ring = pepper_ring
        self._lifetime_policy = lifetime_policy

    def issue_as_user(
        self,
        *,
        authenticated_user_id: int,
        runtime_environment: Environment,
        command: TrialTokenIssueCommand,
    ) -> TrialTokenIssueResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Trial token issuance requires a transaction")
        try:
            authority = self._load_authority(
                authenticated_user_id=authenticated_user_id,
                environment=runtime_environment,
                activation_id=command.activation_id,
            )
            payload_sha256 = canonical_sha256(
                {
                    "command_kind": "issue_invite_trial_token",
                    "authenticated_user_id": authenticated_user_id,
                    "environment": runtime_environment,
                    **command.model_dump(mode="python"),
                }
            )
            existing = self._load_generation(command.activation_id, 1)
            if existing is not None and (
                existing[1] != command.idempotency_key
                or existing[2] != payload_sha256
            ):
                raise InviteTrialError("The trial token has already been issued")
            budget_period_id = self._ensure_budget_period(authority)
            mint_command = McpTokenMintCommand(
                idempotency_key=command.idempotency_key,
                commercial_account_id=authority["commercial_account_id"],
                agreement_id=authority["agreement_id"],
                surface_code="hp1",
                expected_entitlement_revision=(
                    int(existing[3])
                    if existing is not None
                    else authority["entitlement_revision"]
                ),
                label="Hank Standard Trial",
                requested_scopes=TRIAL_TOKEN_SCOPES,
                expires_at=authority["trial_expires_at"],
                reason_code="invite_trial.token_issued",
            )
            minted = McpTokenService(
                self._connection,
                flags=self._flags,
                pepper_ring=self._pepper_ring,
                lifetime_policy=self._lifetime_policy,
            ).prepare_mint_in_transaction(
                actor_user_id=authenticated_user_id,
                runtime_environment=runtime_environment,
                command=mint_command,
            )
            if existing is None:
                self._insert_issuance(
                    command=command,
                    environment=runtime_environment,
                    user_id=authenticated_user_id,
                    authority=authority,
                    minted=minted,
                    payload_sha256=payload_sha256,
                    budget_period_id=budget_period_id,
                    generation=1,
                    replaced_token_id=None,
                    token_command_idempotency_key=command.idempotency_key,
                )
            elif UUID(str(existing[0])) != minted.token_metadata.id:
                raise InviteTrialError("Trial token replay authority is invalid")
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self._result(command.activation_id, minted, generation=1)

    def recover_as_user(
        self,
        *,
        authenticated_user_id: int,
        runtime_environment: Environment,
        command: TrialTokenRecoverCommand,
    ) -> TrialTokenIssueResult:
        """Replace a potentially lost first secret once, with no dual-active window."""

        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Trial token recovery requires a transaction")
        try:
            authority = self._load_authority(
                authenticated_user_id=authenticated_user_id,
                environment=runtime_environment,
                activation_id=command.activation_id,
            )
            payload_sha256 = canonical_sha256(
                {
                    "command_kind": "recover_invite_trial_token",
                    "authenticated_user_id": authenticated_user_id,
                    "environment": runtime_environment,
                    **command.model_dump(mode="python"),
                }
            )
            original = self._load_generation(command.activation_id, 1)
            if original is None:
                raise InviteTrialError("The trial token has not been issued")
            existing = self._load_generation(command.activation_id, 2)
            if existing is not None and (
                existing[1] != command.idempotency_key
                or existing[2] != payload_sha256
            ):
                raise InviteTrialError("The trial token recovery has already been used")

            identity = uuid5(
                NAMESPACE_URL,
                f"hank:invite-trial-token-recovery:{runtime_environment}:"
                f"{authenticated_user_id}:{command.activation_id}:"
                f"{command.idempotency_key}",
            )
            mint_key = f"trial-recovery-mint-{uuid5(identity, 'mint')}"
            if existing is None:
                original_token_id = UUID(str(original[0]))
                token_version, token_status = self._load_token_lifecycle(original_token_id)
                if token_status != "active":
                    raise InviteTrialError("The trial token recovery is unavailable")
                lifecycle = McpTokenLifecycleService(
                    self._connection,
                    flags=self._flags,
                    pepper_ring=self._pepper_ring,
                )
                prepared_revoke = lifecycle.prepare_revoke_as_customer_for_replacement(
                    actor_user_id=authenticated_user_id,
                    runtime_environment=runtime_environment,
                    command=McpTokenRevokeCommand(
                        idempotency_key=(
                            f"trial-recovery-revoke-{uuid5(identity, 'revoke')}"
                        ),
                        commercial_account_id=authority["commercial_account_id"],
                        agreement_id=authority["agreement_id"],
                        surface_code="hp1",
                        token_id=original_token_id,
                        expected_lifecycle_version=token_version,
                        expected_entitlement_revision=authority["entitlement_revision"],
                        reason_code="invite_trial.token_delivery_recovery",
                    ),
                )
                mint_expected_revision = authority["entitlement_revision"]
            else:
                original_token_id = UUID(str(existing[5]))
                mint_expected_revision = int(existing[3])

            mint_command = McpTokenMintCommand(
                idempotency_key=mint_key,
                commercial_account_id=authority["commercial_account_id"],
                agreement_id=authority["agreement_id"],
                surface_code="hp1",
                expected_entitlement_revision=mint_expected_revision,
                label="Hank Standard Trial (recovered)",
                requested_scopes=TRIAL_TOKEN_SCOPES,
                expires_at=authority["trial_expires_at"],
                reason_code="invite_trial.token_recovered",
            )
            minted = McpTokenService(
                self._connection,
                flags=self._flags,
                pepper_ring=self._pepper_ring,
                lifetime_policy=self._lifetime_policy,
            ).prepare_mint_in_transaction(
                actor_user_id=authenticated_user_id,
                runtime_environment=runtime_environment,
                command=mint_command,
            )
            if existing is None:
                lifecycle.finalize_revoke_replacement(
                    prepared_revoke,
                    entitlement_revision=minted.entitlement_revision,
                    projection_changed=minted.projection_changed,
                    runtime_environment=runtime_environment,
                )
                self._insert_issuance(
                    command=command,
                    environment=runtime_environment,
                    user_id=authenticated_user_id,
                    authority=authority,
                    minted=minted,
                    payload_sha256=payload_sha256,
                    budget_period_id=int(original[4]),
                    generation=2,
                    replaced_token_id=original_token_id,
                    token_command_idempotency_key=mint_key,
                )
            elif UUID(str(existing[0])) != minted.token_metadata.id:
                raise InviteTrialError("Trial token recovery replay authority is invalid")
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self._result(
            command.activation_id,
            minted,
            generation=2,
            recovered=True,
        )

    def _load_authority(
        self, *, authenticated_user_id: int, environment: str, activation_id: UUID
    ) -> dict[str, Any]:
        if environment != self._flags.environment:
            raise InviteTrialError("Trial runtime environment mismatch")
        now = datetime.now(timezone.utc)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT activation.commercial_account_id, activation.agreement_id,
                          activation.trial_expires_at, agreement.state,
                          account.public_id, agreement.public_id, revision.revision,
                          activation.agreement_terms_id, terms.budget_policy_id,
                          activation.trial_started_at
                     FROM commercial_trial_activations activation
                     JOIN commercial_agreements agreement
                       ON agreement.id = activation.agreement_id
                     JOIN commercial_accounts account
                       ON account.id = activation.commercial_account_id
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                      AND member.user_id = activation.activated_by_user_id
                     JOIN commercial_entitlement_revisions revision
                       ON revision.commercial_account_id = account.id
                     JOIN commercial_agreement_terms terms
                       ON terms.id = activation.agreement_terms_id
                    WHERE activation.activation_id = %s
                      AND activation.environment = %s
                      AND activation.activated_by_user_id = %s
                      AND agreement.channel = 'invite_trial'
                      AND agreement.surface_code = 'hp1'
                      AND account.kind = 'individual' AND account.status = 'active'
                      AND member.role = 'owner' AND member.status = 'active'
                    FOR UPDATE OF activation, agreement, account, member, revision""",
                (str(activation_id), environment, authenticated_user_id),
            )
            row = cursor.fetchone()
        if row is None or row[3] != "trialing" or row[2] <= now:
            raise InviteTrialError("Trial token authority is unavailable")
        return {
            "commercial_account_id": int(row[0]),
            "agreement_id": int(row[1]),
            "trial_expires_at": row[2],
            "account_public_id": row[4],
            "agreement_public_id": row[5],
            "entitlement_revision": int(row[6]),
            "agreement_terms_id": int(row[7]),
            "budget_policy_id": int(row[8]),
            "trial_started_at": row[9],
        }

    def _load_generation(self, activation_id: UUID, generation: int):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT token_id, idempotency_key, payload_sha256,
                          expected_entitlement_revision, budget_period_id,
                          replaced_token_id
                     FROM commercial_trial_token_issuances
                    WHERE activation_id = %s AND generation = %s FOR UPDATE""",
                (str(activation_id), generation),
            )
            return cursor.fetchone()

    def _load_token_lifecycle(self, token_id: UUID) -> tuple[int, str]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT version, status FROM mcp_tokens WHERE id = %s FOR UPDATE",
                (str(token_id),),
            )
            row = cursor.fetchone()
        if row is None:
            raise InviteTrialError("The trial token recovery is unavailable")
        return int(row[0]), str(row[1])

    def _insert_issuance(
        self,
        *,
        command: TrialTokenIssueCommand | TrialTokenRecoverCommand,
        environment: str,
        user_id: int,
        authority: dict[str, Any],
        minted: McpTokenMintResult,
        payload_sha256: str,
        budget_period_id: int,
        generation: int,
        replaced_token_id: UUID | None,
        token_command_idempotency_key: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO commercial_trial_token_issuances (
                       activation_id, generation, token_id, replaced_token_id,
                       environment, activated_by_user_id,
                       commercial_account_id, agreement_id, idempotency_key,
                       token_command_idempotency_key, payload_sha256, expires_at,
                       requests_per_minute,
                       requests_per_day, concurrent_workflows,
                       model_cap_microusd, technical_cap_microusd,
                       expected_entitlement_revision, budget_period_id
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    str(command.activation_id),
                    generation,
                    str(minted.token_metadata.id),
                    str(replaced_token_id) if replaced_token_id else None,
                    environment,
                    user_id,
                    authority["commercial_account_id"],
                    authority["agreement_id"],
                    command.idempotency_key,
                    token_command_idempotency_key,
                    payload_sha256,
                    authority["trial_expires_at"],
                    TRIAL_REQUESTS_PER_MINUTE,
                    TRIAL_REQUESTS_PER_DAY,
                    TRIAL_CONCURRENT_WORKFLOWS,
                    TRIAL_MODEL_CAP_MICROUSD,
                    TRIAL_TECHNICAL_CAP_MICROUSD,
                    authority["entitlement_revision"],
                    budget_period_id,
                ),
            )

    def _ensure_budget_period(self, authority: dict[str, Any]) -> int:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT id FROM commercial_budget_periods
                    WHERE agreement_terms_id = %s
                      AND period_start_at = %s AND period_end_at = %s
                    FOR UPDATE""",
                (
                    authority["agreement_terms_id"],
                    authority["trial_started_at"],
                    authority["trial_expires_at"],
                ),
            )
            row = cursor.fetchone()
            if row is not None:
                return int(row[0])
            cursor.execute(
                """INSERT INTO commercial_budget_periods (
                       agreement_terms_id, budget_policy_id,
                       period_start_at, period_end_at,
                       model_limit_microusd, technical_limit_microusd,
                       non_model_reserve_microusd,
                       max_single_reservation_microusd,
                       top_up_quantum_microusd, max_unreserved_delta_microusd,
                       late_child_allowance_microusd, max_concurrent_reservations,
                       max_period_overdraft_microusd, state
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'open')
                   RETURNING id""",
                (
                    authority["agreement_terms_id"],
                    authority["budget_policy_id"],
                    authority["trial_started_at"],
                    authority["trial_expires_at"],
                    TRIAL_MODEL_CAP_MICROUSD,
                    TRIAL_TECHNICAL_CAP_MICROUSD,
                    TRIAL_TECHNICAL_CAP_MICROUSD - TRIAL_MODEL_CAP_MICROUSD,
                    TRIAL_MAX_SINGLE_RESERVATION_MICROUSD,
                    TRIAL_TOP_UP_QUANTUM_MICROUSD,
                    TRIAL_MAX_UNRESERVED_DELTA_MICROUSD,
                    TRIAL_LATE_CHILD_ALLOWANCE_MICROUSD,
                    TRIAL_CONCURRENT_WORKFLOWS,
                    TRIAL_MAX_PERIOD_OVERDRAFT_MICROUSD,
                ),
            )
            return int(cursor.fetchone()[0])

    @staticmethod
    def _result(
        activation_id: UUID,
        minted: McpTokenMintResult,
        *,
        generation: int,
        recovered: bool = False,
    ) -> TrialTokenIssueResult:
        return TrialTokenIssueResult(
            activation_id=activation_id,
            token_id=minted.token_metadata.id,
            token=minted.token,
            secret_available=minted.secret_available,
            expires_at=minted.token_metadata.expires_at,
            requested_scopes=TRIAL_TOKEN_SCOPES,
            requests_per_minute=TRIAL_REQUESTS_PER_MINUTE,
            requests_per_day=TRIAL_REQUESTS_PER_DAY,
            concurrent_workflows=TRIAL_CONCURRENT_WORKFLOWS,
            model_cap_microusd=TRIAL_MODEL_CAP_MICROUSD,
            technical_cap_microusd=TRIAL_TECHNICAL_CAP_MICROUSD,
            generation=generation,
            recovered=recovered,
            replayed=minted.replayed,
        )


__all__ = [
    "InviteTrialTokenService",
    "TrialTokenIssueCommand",
    "TrialTokenIssueResult",
    "TrialTokenRecoverCommand",
]
