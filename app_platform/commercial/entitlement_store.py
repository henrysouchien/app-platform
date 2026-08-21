"""Authoritative account-wide persistence for commercial entitlements."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .agreements import AgreementState
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority_invalidation import (
    CommercialAuthorityInvalidationCommand,
    publish_authority_invalidation,
)
from .entitlements import (
    CanonicalEntitlementFact,
    EntitlementProjectionInput,
    EntitlementTokenSubject,
    ExplicitEntitlementFact,
    project_entitlements,
    resolve_effective_entitlements,
)
from .flags import CommercialFlags
from .models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .policies import EntitlementPolicyBody


ENTITLEMENT_INVALIDATION_CHANNEL = "commercial_entitlement_invalidation"
TRIAL_ENTITLEMENT_POLICY_CODES = {"hp1": "hp1_standard"}
_ENTITLEMENT_BEARING_STATES = frozenset(
    {
        AgreementState.TRIALING,
        AgreementState.ACTIVE,
        AgreementState.PAST_DUE,
        AgreementState.GRACE,
        AgreementState.CANCELED,
    }
)


class AgreementProjectionControls(StrictCommercialModel):
    agreement_id: int = Field(gt=0)
    trial_entitlement_policy_id: int | None = Field(default=None, gt=0)


class AccountProjectionRequest(StrictCommercialModel):
    commercial_account_id: int = Field(gt=0)
    projected_at: AwareDatetime
    agreements: tuple[AgreementProjectionControls, ...] = ()

    @model_validator(mode="after")
    def _unique_agreements(self) -> "AccountProjectionRequest":
        identities = [item.agreement_id for item in self.agreements]
        if len(set(identities)) != len(identities):
            raise ValueError("agreement projection controls must be unique")
        return self


class MaterializedEntitlementFact(StrictCommercialModel):
    agreement_id: int = Field(gt=0)
    agreement_terms_id: int = Field(gt=0)
    surface_code: StableCode
    terms_policy_id: int = Field(gt=0)
    source_policy_id: int = Field(gt=0)
    fact: CanonicalEntitlementFact


class AccountEntitlementProjection(StrictCommercialModel):
    facts: tuple[MaterializedEntitlementFact, ...]
    content_sha256: Sha256Digest
    source_watermark: dict[str, Any]


class EntitlementProjectionResult(StrictCommercialModel):
    commercial_account_id: int = Field(gt=0)
    revision: int = Field(gt=0)
    content_sha256: Sha256Digest
    fact_count: int = Field(ge=0)
    audit_event_id: UUID | None = None
    changed: bool


class EntitlementExpiryFence(StrictCommercialModel):
    observed_revision: int = Field(gt=0)
    observed_boundary_at: AwareDatetime


class EntitlementProjectionFenceSuperseded(RuntimeError):
    """The scheduled expiry no longer matches the locked entitlement authority."""


class McpTokenEntitlementPreviewRequest(StrictCommercialModel):
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    user_id: int = Field(gt=0)
    candidate_token_id: UUID
    projected_at: AwareDatetime


class McpTokenEntitlementPreviewResult(StrictCommercialModel):
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    user_id: int = Field(gt=0)
    candidate_token_id: UUID
    effective_facts: tuple[CanonicalEntitlementFact, ...]
    content_sha256: Sha256Digest


class AccountEntitlementProjectionHook:
    """Agreement lifecycle hook that always rebuilds the complete account set."""

    def __init__(
        self,
        *,
        flags: CommercialFlags,
        controls_provider: Callable[
            [int], tuple[AgreementProjectionControls, ...]
        ] = lambda _account_id: (),
    ) -> None:
        self._flags = flags
        self._controls_provider = controls_provider

    def agreement_changed(
        self,
        connection: Any,
        *,
        before: Any,
        after: Any,
        effective_at: datetime,
    ) -> None:
        projected_at = effective_at
        if before.state == after.state:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT transaction_timestamp()")
                transaction_time = cursor.fetchone()[0]
            finally:
                cursor.close()
            projected_at = min(effective_at, transaction_time)
        projection = persist_account_entitlements(
            connection,
            flags=self._flags,
            request=AccountProjectionRequest(
                commercial_account_id=after.commercial_account_id,
                projected_at=projected_at,
                agreements=self._controls_provider(after.commercial_account_id),
            ),
        )
        publish_authority_invalidation(
            connection,
            CommercialAuthorityInvalidationCommand(
                environment=self._flags.environment,
                kind="agreement",
                commercial_account_id=after.commercial_account_id,
                entitlement_revision=projection.revision,
            ),
        )


def _json_object(value: Any, *, label: str) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _effective_access_until(
    state: AgreementState,
    row: tuple[Any, ...],
    policy: EntitlementPolicyBody,
    state_effective_at: datetime,
) -> datetime | None:
    grace_end_at, current_period_end_at, service_end_at = row[5:8]
    rule = policy.retention_for(state.value)
    if rule is None:
        return None
    candidates = [state_effective_at + timedelta(seconds=rule.access_seconds)]
    if service_end_at is not None:
        candidates.append(service_end_at)
    if state == AgreementState.GRACE and grace_end_at is not None:
        candidates.append(grace_end_at)
    if state == AgreementState.CANCELED and current_period_end_at is not None:
        candidates.append(current_period_end_at)
    return min(candidates)


def _earliest_optional(*values: datetime | None) -> datetime | None:
    present = [value for value in values if value is not None]
    return min(present) if present else None


def _load_account_projection(
    connection: Any,
    request: AccountProjectionRequest,
    *,
    preview_token_subject: tuple[int, EntitlementTokenSubject] | None = None,
) -> tuple[UUID, AccountEntitlementProjection]:
    controls_by_agreement = {item.agreement_id: item for item in request.agreements}
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT public_id FROM commercial_accounts WHERE id = %s FOR UPDATE",
            (request.commercial_account_id,),
        )
        account = cursor.fetchone()
        if account is None:
            raise ValueError("commercial account does not exist")
        account_public_id = UUID(str(account[0]))

        cursor.execute(
            """
            SELECT id, surface_code, state, state_effective_at,
                   service_start_at, grace_end_at, current_period_end_at,
                   service_end_at
              FROM commercial_agreements
             WHERE commercial_account_id = %s
             ORDER BY id
             FOR UPDATE
            """,
            (request.commercial_account_id,),
        )
        agreements = cursor.fetchall()
        known_ids = {int(row[0]) for row in agreements}
        unknown_controls = set(controls_by_agreement) - known_ids
        if unknown_controls:
            raise ValueError(
                "agreement controls do not belong to the commercial account"
            )

        cursor.execute(
            """
            SELECT terms.id, terms.agreement_id, terms.entitlement_policy_id,
                   terms.effective_from, terms.effective_until
              FROM commercial_agreement_terms AS terms
             WHERE terms.commercial_account_id = %s
               AND terms.effective_from <= %s
               AND (terms.effective_until IS NULL OR terms.effective_until > %s)
               AND (to_jsonb(terms)->>'voided_at') IS NULL
             ORDER BY terms.agreement_id, terms.revision
             FOR UPDATE
            """,
            (
                request.commercial_account_id,
                request.projected_at,
                request.projected_at,
            ),
        )
        term_rows = cursor.fetchall()
        terms_by_agreement: dict[int, tuple[Any, ...]] = {}
        for row in term_rows:
            agreement_id = int(row[1])
            if agreement_id in terms_by_agreement:
                raise ValueError(
                    "multiple agreement terms are effective at projection time"
                )
            terms_by_agreement[agreement_id] = row

        policy_ids = {int(row[2]) for row in term_rows}
        policy_ids.update(
            item.trial_entitlement_policy_id
            for item in request.agreements
            if item.trial_entitlement_policy_id is not None
        )
        policies: dict[
            int,
            tuple[str, EntitlementPolicyBody, datetime, datetime | None],
        ] = {}
        if policy_ids:
            cursor.execute(
                """
                SELECT id, policy_code, body_json, activated_at, retired_at
                  FROM commercial_policy_versions
                 WHERE id = ANY(%s) AND policy_kind = 'entitlement'
                 FOR SHARE
                """,
                (sorted(policy_ids),),
            )
            policies = {
                int(row[0]): (
                    str(row[1]),
                    EntitlementPolicyBody.model_validate(
                        _json_object(row[2], label="entitlement policy body")
                    ),
                    row[3],
                    row[4],
                )
                for row in cursor.fetchall()
            }
        if set(policy_ids) != set(policies):
            raise ValueError("an authoritative entitlement policy is missing")

        approved_trial_ids: dict[str, int] = {}
        trial_surfaces = {
            str(row[1])
            for row in agreements
            if AgreementState(row[2]) == AgreementState.TRIALING
        }
        for surface_code in sorted(trial_surfaces):
            expected_code = TRIAL_ENTITLEMENT_POLICY_CODES.get(surface_code)
            if expected_code is None:
                raise ValueError("trial surface has no approved Standard policy")
            cursor.execute(
                """
                SELECT id, policy_code, body_json, activated_at, retired_at
                  FROM commercial_policy_versions
                 WHERE policy_kind = 'entitlement' AND policy_code = %s
                   AND state IN ('active', 'retired')
                   AND activated_at <= %s
                   AND (retired_at IS NULL OR retired_at > %s)
                 FOR SHARE
                """,
                (expected_code, request.projected_at, request.projected_at),
            )
            trial_rows = cursor.fetchall()
            if len(trial_rows) != 1:
                raise ValueError("approved Standard trial policy is not unambiguous")
            trial_row = trial_rows[0]
            trial_id = int(trial_row[0])
            policies[trial_id] = (
                str(trial_row[1]),
                EntitlementPolicyBody.model_validate(
                    _json_object(trial_row[2], label="trial entitlement policy body")
                ),
                trial_row[3],
                trial_row[4],
            )
            approved_trial_ids[surface_code] = trial_id

        cursor.execute(
            """
            SELECT user_id FROM commercial_account_members
             WHERE commercial_account_id = %s AND status = 'active'
             ORDER BY user_id FOR SHARE
            """,
            (request.commercial_account_id,),
        )
        active_user_ids = tuple(int(row[0]) for row in cursor.fetchall())

        if preview_token_subject is not None:
            preview_agreement_id, preview_subject = preview_token_subject
            if preview_agreement_id not in known_ids:
                raise ValueError(
                    "preview MCP token agreement does not belong to the commercial account"
                )
            if preview_subject.user_id not in set(active_user_ids):
                raise ValueError(
                    "preview MCP token user is not an active account member"
                )

        token_subjects_by_agreement: dict[int, list[EntitlementTokenSubject]] = {}
        existing_token_ids: set[UUID] = set()
        cursor.execute("SELECT to_regclass('mcp_tokens')")
        if cursor.fetchone()[0] is not None:
            cursor.execute(
                """
                SELECT token.id, token.user_id, token.agreement_id
                  FROM mcp_tokens AS token
                  JOIN commercial_account_members AS member
                    ON member.commercial_account_id = token.commercial_account_id
                   AND member.user_id = token.user_id
                   AND member.status = 'active'
                  JOIN commercial_agreements AS agreement
                    ON agreement.id = token.agreement_id
                   AND agreement.commercial_account_id = token.commercial_account_id
                   AND agreement.surface_code = token.surface_code
                 WHERE token.commercial_account_id = %s
                   AND token.status = 'active'
                   AND token.revoked_at IS NULL
                   AND token.created_at <= %s
                   AND token.expires_at > %s
                 ORDER BY token.agreement_id, token.id
                 FOR SHARE OF token
                """,
                (
                    request.commercial_account_id,
                    request.projected_at,
                    request.projected_at,
                ),
            )
            for row in cursor.fetchall():
                existing_token_ids.add(UUID(str(row[0])))
                token_subjects_by_agreement.setdefault(int(row[2]), []).append(
                    EntitlementTokenSubject(
                        token_id=UUID(str(row[0])),
                        user_id=int(row[1]),
                    )
                )
        if preview_token_subject is not None:
            preview_agreement_id, preview_subject = preview_token_subject
            if preview_subject.token_id in existing_token_ids:
                raise ValueError("preview MCP token identity already exists")
            token_subjects_by_agreement.setdefault(preview_agreement_id, []).append(
                preview_subject
            )
        cursor.execute(
            """
            SELECT agreement_id, subject_kind, subject_user_id, source_kind,
                   entitlement_key, effect, value_json, priority,
                   effective_from, effective_until, reason_code
              FROM commercial_entitlement_overrides
             WHERE commercial_account_id = %s AND revoked_at IS NULL
               AND effective_from <= %s
               AND (effective_until IS NULL OR effective_until > %s)
             ORDER BY agreement_id, id
             FOR SHARE
            """,
            (
                request.commercial_account_id,
                request.projected_at,
                request.projected_at,
            ),
        )
        active_users = set(active_user_ids)
        explicit_by_agreement: dict[int, list[ExplicitEntitlementFact]] = {}
        for row in cursor.fetchall():
            if row[1] == "user" and int(row[2]) not in active_users:
                continue
            value = row[6]
            if isinstance(value, str):
                value = json.loads(value)
            explicit_by_agreement.setdefault(int(row[0]), []).append(
                ExplicitEntitlementFact(
                    subject_kind=row[1],
                    subject_user_id=int(row[2]) if row[2] is not None else None,
                    source_kind=row[3],
                    entitlement_key=row[4],
                    effect=row[5],
                    value=value,
                    priority=int(row[7]),
                    effective_from=row[8],
                    effective_until=row[9],
                    reason_code=row[10],
                )
            )
    finally:
        cursor.close()

    desired: list[MaterializedEntitlementFact] = []
    for agreement in agreements:
        agreement_id = int(agreement[0])
        surface_code = agreement[1]
        state = AgreementState(agreement[2])
        state_effective_at = agreement[3]
        controls = controls_by_agreement.get(
            agreement_id, AgreementProjectionControls(agreement_id=agreement_id)
        )
        terms = terms_by_agreement.get(agreement_id)
        if terms is None:
            if state in _ENTITLEMENT_BEARING_STATES and (
                agreement[4] is None or agreement[4] <= request.projected_at
            ):
                if state not in {AgreementState.CANCELED, AgreementState.EXPIRED}:
                    raise ValueError(
                        "entitlement-bearing agreement has no current terms"
                    )
            continue
        policy_id = int(terms[2])
        _policy_code, policy, _policy_activated_at, _policy_retired_at = policies[
            policy_id
        ]
        if policy.surface_code != surface_code:
            raise ValueError("authoritative entitlement policy surface mismatch")
        trial_policy = None
        effective_policy_id = policy_id
        projection_effective_from = terms[3]
        projection_effective_until = _earliest_optional(terms[4], agreement[7])
        if state == AgreementState.TRIALING:
            approved_trial_id = approved_trial_ids[surface_code]
            trial_id = controls.trial_entitlement_policy_id or approved_trial_id
            if trial_id != approved_trial_id:
                raise ValueError(
                    "trial policy override is not the approved Standard policy"
                )
            (
                trial_code,
                trial_policy,
                trial_policy_activated_at,
                trial_policy_retired_at,
            ) = policies[trial_id]
            expected_trial_code = TRIAL_ENTITLEMENT_POLICY_CODES.get(surface_code)
            if expected_trial_code is None or trial_code != expected_trial_code:
                raise ValueError("trial policy is not the approved Standard policy")
            effective_policy_id = trial_id
            projection_effective_from = max(terms[3], trial_policy_activated_at)
            projection_effective_until = _earliest_optional(
                terms[4], agreement[7], trial_policy_retired_at
            )
        projection = project_entitlements(
            # Retention is immutable policy content, never caller-selected.
            EntitlementProjectionInput(
                commercial_account_id=request.commercial_account_id,
                agreement_id=agreement_id,
                agreement_terms_id=int(terms[0]),
                policy_id=effective_policy_id,
                surface_code=surface_code,
                agreement_state=state,
                policy=policy,
                trial_policy=trial_policy,
                state_retained_keys=(
                    policy.retention_for(state.value).keys
                    if policy.retention_for(state.value) is not None
                    else ()
                ),
                active_user_ids=active_user_ids,
                token_subjects=tuple(token_subjects_by_agreement.get(agreement_id, ())),
                explicit_facts=tuple(explicit_by_agreement.get(agreement_id, ())),
                effective_from=projection_effective_from,
                effective_until=projection_effective_until,
                state_effective_from=max(projection_effective_from, state_effective_at),
                entitlement_access_until=_effective_access_until(
                    state, agreement, policy, state_effective_at
                ),
                projected_at=request.projected_at,
            )
        )
        desired.extend(
            MaterializedEntitlementFact(
                agreement_id=agreement_id,
                agreement_terms_id=int(terms[0]),
                surface_code=surface_code,
                terms_policy_id=policy_id,
                source_policy_id=effective_policy_id,
                fact=fact,
            )
            for fact in projection.facts
        )
    facts = tuple(
        sorted(
            desired,
            key=lambda item: canonical_sha256(item.model_dump(mode="python")),
        )
    )
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT commercial_entitlement_agreement_source_watermark(%s, %s)
            """,
            (request.commercial_account_id, request.projected_at),
        )
        source_watermark = _json_object(
            cursor.fetchone()[0], label="entitlement agreement source watermark"
        )
    finally:
        cursor.close()
    return account_public_id, AccountEntitlementProjection(
        facts=facts,
        content_sha256=canonical_sha256(
            [item.model_dump(mode="python") for item in facts]
        ),
        source_watermark=source_watermark,
    )


def preview_mcp_token_entitlements(
    connection: Any,
    *,
    flags: CommercialFlags,
    request: McpTokenEntitlementPreviewRequest,
) -> McpTokenEntitlementPreviewResult:
    """Project a non-persisted candidate token through the authoritative policy path."""

    if not flags.commercial_entitlement_projection_enabled:
        raise RuntimeError("commercial entitlement projection is disabled")
    if getattr(connection, "autocommit", False):
        raise ValueError("MCP token entitlement preview requires autocommit disabled")
    _account_public_id, projection = _load_account_projection(
        connection,
        AccountProjectionRequest(
            commercial_account_id=request.commercial_account_id,
            projected_at=request.projected_at,
        ),
        preview_token_subject=(
            request.agreement_id,
            EntitlementTokenSubject(
                token_id=request.candidate_token_id,
                user_id=request.user_id,
            ),
        ),
    )
    agreement_facts = tuple(
        item.fact
        for item in projection.facts
        if item.agreement_id == request.agreement_id
    )
    effective = resolve_effective_entitlements(
        agreement_facts,
        user_id=request.user_id,
        token_id=request.candidate_token_id,
    )
    return McpTokenEntitlementPreviewResult(
        commercial_account_id=request.commercial_account_id,
        agreement_id=request.agreement_id,
        user_id=request.user_id,
        candidate_token_id=request.candidate_token_id,
        effective_facts=effective,
        content_sha256=canonical_sha256(
            [fact.model_dump(mode="python") for fact in effective]
        ),
    )


def persist_account_entitlements(
    connection: Any,
    *,
    flags: CommercialFlags,
    request: AccountProjectionRequest,
    expiry_fence: EntitlementExpiryFence | None = None,
) -> EntitlementProjectionResult:
    """Project and materialize the complete account set in one caller transaction."""

    if not flags.commercial_entitlement_projection_enabled:
        raise RuntimeError("commercial entitlement projection is disabled")
    if getattr(connection, "autocommit", False):
        raise ValueError("entitlement projection requires autocommit disabled")
    account_public_id, projection = _load_account_projection(connection, request)
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT revision, content_sha256, fact_count, audit_event_id,
                   source_watermark
              FROM commercial_entitlement_revisions
             WHERE commercial_account_id = %s FOR UPDATE
            """,
            (request.commercial_account_id,),
        )
        current = cursor.fetchone()
        if expiry_fence is not None:
            if current is None or int(current[0]) != expiry_fence.observed_revision:
                raise EntitlementProjectionFenceSuperseded()
            cursor.execute(
                """
                SELECT MIN(effective_until)
                  FROM commercial_entitlements
                 WHERE commercial_account_id = %s
                   AND entitlement_revision = %s
                   AND status = 'active'
                   AND effective_until IS NOT NULL
                   AND effective_until <= %s
                """,
                (
                    request.commercial_account_id,
                    expiry_fence.observed_revision,
                    request.projected_at,
                ),
            )
            boundary = cursor.fetchone()[0]
            if boundary is None or boundary != expiry_fence.observed_boundary_at:
                raise EntitlementProjectionFenceSuperseded()
        if (
            current is not None
            and current[1] == projection.content_sha256
            and _json_object(
                current[4], label="stored entitlement agreement source watermark"
            )
            == projection.source_watermark
        ):
            return EntitlementProjectionResult(
                commercial_account_id=request.commercial_account_id,
                revision=current[0],
                content_sha256=current[1],
                fact_count=current[2],
                audit_event_id=UUID(str(current[3])),
                changed=False,
            )
        revision = 1 if current is None else int(current[0]) + 1
        audit = CommercialAuditEvent(
            commercial_account_id=request.commercial_account_id,
            actor_type="service",
            actor_id="entitlement-projector",
            action="commercial.entitlement.project",
            target_type="commercial_account",
            target_id=str(account_public_id),
            after={
                "account_id": request.commercial_account_id,
                "version": revision,
                "content_sha256": projection.content_sha256,
                "result_code": "applied",
            },
        )
        insert_commercial_audit_event(connection, audit)
        if current is None:
            cursor.execute(
                """
                INSERT INTO commercial_entitlement_revisions (
                    commercial_account_id, revision, content_sha256, fact_count,
                    audit_event_id, projection_txid, source_watermark,
                    source_evaluated_at
                ) VALUES (
                    %s, 1, %s, %s, %s, txid_current(), %s::jsonb, %s
                )
                """,
                (
                    request.commercial_account_id,
                    projection.content_sha256,
                    len(projection.facts),
                    str(audit.event_id),
                    json.dumps(projection.source_watermark, separators=(",", ":")),
                    request.projected_at,
                ),
            )
        else:
            cursor.execute(
                """
                UPDATE commercial_entitlement_revisions
                   SET revision = %s, content_sha256 = %s, fact_count = %s,
                       audit_event_id = %s, projection_txid = txid_current(),
                       source_watermark = %s::jsonb, source_evaluated_at = %s,
                       updated_at = clock_timestamp()
                 WHERE commercial_account_id = %s
                """,
                (
                    revision,
                    projection.content_sha256,
                    len(projection.facts),
                    str(audit.event_id),
                    json.dumps(projection.source_watermark, separators=(",", ":")),
                    request.projected_at,
                    request.commercial_account_id,
                ),
            )
            cursor.execute(
                """
                UPDATE commercial_entitlements
                   SET status = 'superseded',
                       effective_until = LEAST(
                           COALESCE(effective_until,
                               GREATEST(clock_timestamp(), effective_from + interval '1 microsecond')),
                           GREATEST(clock_timestamp(), effective_from + interval '1 microsecond')
                       )
                 WHERE commercial_account_id = %s AND status = 'active'
                """,
                (request.commercial_account_id,),
            )
        for stored in projection.facts:
            fact = stored.fact
            cursor.execute(
                """
                INSERT INTO commercial_entitlements (
                    commercial_account_id, entitlement_revision, projection_txid,
                    agreement_id, agreement_terms_id, surface_code, subject_kind,
                    subject_user_id, subject_mcp_token_id, source_kind,
                    entitlement_key, effect, value_json, priority, policy_id,
                    source_policy_id,
                    effective_from, effective_until, status, reason_code
                ) VALUES (
                    %s, %s, txid_current(), %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s::jsonb, %s, %s, %s, %s, %s, 'active', %s
                )
                """,
                (
                    request.commercial_account_id,
                    revision,
                    stored.agreement_id,
                    stored.agreement_terms_id,
                    stored.surface_code,
                    fact.subject_kind,
                    fact.subject_user_id,
                    str(fact.subject_mcp_token_id)
                    if fact.subject_mcp_token_id
                    else None,
                    fact.source_kind,
                    fact.entitlement_key,
                    fact.effect,
                    json.dumps(fact.value, separators=(",", ":")),
                    fact.priority,
                    stored.terms_policy_id,
                    stored.source_policy_id,
                    fact.effective_from,
                    fact.effective_until,
                    fact.reason_code,
                ),
            )
        cursor.execute(
            "SELECT pg_notify(%s, %s)",
            (
                ENTITLEMENT_INVALIDATION_CHANNEL,
                json.dumps(
                    {
                        "commercial_account_id": request.commercial_account_id,
                        "revision": revision,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        )
        publish_authority_invalidation(
            connection,
            CommercialAuthorityInvalidationCommand(
                environment=flags.environment,
                kind="entitlement",
                commercial_account_id=request.commercial_account_id,
                entitlement_revision=revision,
            ),
        )
        return EntitlementProjectionResult(
            commercial_account_id=request.commercial_account_id,
            revision=revision,
            content_sha256=projection.content_sha256,
            fact_count=len(projection.facts),
            audit_event_id=audit.event_id,
            changed=True,
        )
    finally:
        cursor.close()


__all__ = [
    "AccountEntitlementProjection",
    "AccountEntitlementProjectionHook",
    "AccountProjectionRequest",
    "AgreementProjectionControls",
    "ENTITLEMENT_INVALIDATION_CHANNEL",
    "EntitlementProjectionResult",
    "EntitlementExpiryFence",
    "EntitlementProjectionFenceSuperseded",
    "MaterializedEntitlementFact",
    "McpTokenEntitlementPreviewRequest",
    "McpTokenEntitlementPreviewResult",
    "TRIAL_ENTITLEMENT_POLICY_CODES",
    "persist_account_entitlements",
    "preview_mcp_token_entitlements",
]
