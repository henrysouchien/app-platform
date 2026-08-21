"""Pure deterministic projection for subject-scoped commercial entitlements."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, JsonValue, StrictInt, model_validator

from .agreements import AgreementState
from .models import StableCode, StrictCommercialModel, canonical_sha256
from .policies import EntitlementPolicyBody


SubjectKind = Literal["account", "user", "mcp_token"]
EntitlementEffect = Literal["allow", "deny", "limit"]
SourceKind = Literal["agreement", "safety_opt_in", "admin_override", "payment_grace"]


class EntitlementTokenSubject(StrictCommercialModel):
    token_id: UUID
    user_id: Annotated[StrictInt, Field(gt=0)]


class ExplicitEntitlementFact(StrictCommercialModel):
    subject_kind: SubjectKind
    subject_user_id: Annotated[StrictInt, Field(gt=0)] | None = None
    subject_mcp_token_id: UUID | None = None
    source_kind: Literal["safety_opt_in", "admin_override"]
    entitlement_key: StableCode
    effect: EntitlementEffect
    value: JsonValue
    priority: StrictInt = 0
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None
    reason_code: StableCode

    @model_validator(mode="after")
    def _shape(self) -> "ExplicitEntitlementFact":
        if self.subject_kind == "account":
            valid_subject = (
                self.subject_user_id is None and self.subject_mcp_token_id is None
            )
        elif self.subject_kind == "user":
            valid_subject = (
                self.subject_user_id is not None
                and self.subject_mcp_token_id is None
            )
        else:
            valid_subject = (
                self.subject_user_id is None
                and self.subject_mcp_token_id is not None
            )
        if not valid_subject:
            raise ValueError("explicit entitlement subject identity is invalid")
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("explicit entitlement end must follow its start")
        _validate_effect_value(self.effect, self.value)
        if (
            self.entitlement_key == "scope:trade-execute"
            and self.effect == "allow"
            and self.subject_kind == "account"
        ):
            raise ValueError("trade execution allows cannot be account scoped")
        return self


class EntitlementProjectionInput(StrictCommercialModel):
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    policy_id: Annotated[StrictInt, Field(gt=0)]
    surface_code: StableCode
    agreement_state: AgreementState
    policy: EntitlementPolicyBody
    trial_policy: EntitlementPolicyBody | None = None
    state_retained_keys: tuple[StableCode, ...] = ()
    active_user_ids: tuple[Annotated[StrictInt, Field(gt=0)], ...] = ()
    token_subjects: tuple[EntitlementTokenSubject, ...] = ()
    explicit_facts: tuple[ExplicitEntitlementFact, ...] = ()
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None
    state_effective_from: AwareDatetime
    entitlement_access_until: AwareDatetime | None = None
    projected_at: AwareDatetime

    @model_validator(mode="after")
    def _consistent(self) -> "EntitlementProjectionInput":
        if self.policy.surface_code != self.surface_code:
            raise ValueError("entitlement policy surface must match projection surface")
        if self.agreement_state == AgreementState.TRIALING:
            if self.trial_policy is None or self.trial_policy.surface_code != self.surface_code:
                raise ValueError("trial projection requires a same-surface trial policy")
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("projection effective end must follow its start")
        if self.state_effective_from < self.effective_from:
            raise ValueError("state boundary cannot precede agreement terms")
        if self.state_effective_from > self.projected_at:
            raise ValueError("state boundary cannot follow projection time")
        if (
            self.effective_until is not None
            and self.state_effective_from >= self.effective_until
        ):
            raise ValueError("state boundary must be inside agreement terms")
        if self.agreement_state in {AgreementState.PAST_DUE, AgreementState.GRACE}:
            if not self.state_retained_keys:
                if self.entitlement_access_until is not None:
                    raise ValueError("empty payment retention cannot have an access boundary")
                return self
            if self.entitlement_access_until is None:
                raise ValueError("payment grace projection requires an access boundary")
            if self.entitlement_access_until <= self.state_effective_from:
                raise ValueError("payment grace end must follow its state boundary")
        if (
            self.agreement_state == AgreementState.CANCELED
            and self.entitlement_access_until is not None
            and self.entitlement_access_until > self.projected_at
            and not self.state_retained_keys
        ):
            raise ValueError("canceled access requires configured safe retained keys")
        if (
            self.agreement_state == AgreementState.CANCELED
            and self.entitlement_access_until is not None
            and self.entitlement_access_until <= self.state_effective_from
        ):
            raise ValueError("canceled access end must follow its state boundary")
        if len(set(self.state_retained_keys)) != len(self.state_retained_keys):
            raise ValueError("state retained keys must be unique")
        if len(set(self.active_user_ids)) != len(self.active_user_ids):
            raise ValueError("active user identities must be unique")
        token_ids = [subject.token_id for subject in self.token_subjects]
        if len(set(token_ids)) != len(token_ids):
            raise ValueError("token subjects must be unique")
        if any(subject.user_id not in self.active_user_ids for subject in self.token_subjects):
            raise ValueError("token subjects require active member users")
        active_users = set(self.active_user_ids)
        active_tokens = set(token_ids)
        for fact in self.explicit_facts:
            if fact.subject_kind == "user" and fact.subject_user_id not in active_users:
                raise ValueError("explicit user facts require an active member")
            if (
                fact.subject_kind == "mcp_token"
                and fact.subject_mcp_token_id not in active_tokens
            ):
                raise ValueError("explicit token facts require an active token subject")
        return self


class CanonicalEntitlementFact(StrictCommercialModel):
    subject_kind: SubjectKind
    subject_user_id: int | None = None
    subject_mcp_token_id: UUID | None = None
    source_kind: SourceKind
    entitlement_key: StableCode
    effect: EntitlementEffect
    value: JsonValue
    priority: int
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None
    reason_code: StableCode

    @model_validator(mode="after")
    def _valid_fact(self) -> "CanonicalEntitlementFact":
        _validate_effect_value(self.effect, self.value)
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("canonical entitlement end must follow its start")
        return self


class EntitlementProjection(StrictCommercialModel):
    facts: tuple[CanonicalEntitlementFact, ...]
    content_sha256: str


def _validate_effect_value(effect: EntitlementEffect, value: JsonValue) -> None:
    if effect in {"allow", "deny"} and value is not True:
        raise ValueError("allow and deny entitlement values must be true")
    if effect == "limit" and (
        isinstance(value, bool) or not isinstance(value, int) or value < 0
    ):
        raise ValueError("limit entitlement values must be non-negative integers")


def _subject_key(fact: CanonicalEntitlementFact) -> tuple:
    return (
        fact.subject_kind,
        fact.subject_user_id or 0,
        str(fact.subject_mcp_token_id or ""),
        fact.entitlement_key,
    )


def _sort_key(fact: CanonicalEntitlementFact) -> tuple:
    return (
        *_subject_key(fact),
        fact.effect,
        -fact.priority,
        fact.source_kind,
        fact.reason_code,
        fact.effective_from.isoformat(),
        fact.effective_until.isoformat() if fact.effective_until else "",
    )


def _state_keys(state: AgreementState) -> frozenset[str] | None:
    if state in {
        AgreementState.DRAFT,
        AgreementState.PENDING_PAYMENT,
        AgreementState.PAUSED,
        AgreementState.EXPIRED,
    }:
        return frozenset()
    return None


def _policy_facts(value: EntitlementProjectionInput) -> list[CanonicalEntitlementFact]:
    if (
        value.projected_at < value.effective_from
        or (
        value.effective_until is not None
        and value.effective_until <= value.projected_at
        )
    ):
        return []
    allowed_keys = _state_keys(value.agreement_state)
    policy = value.policy
    if value.agreement_state == AgreementState.TRIALING:
        policy = value.trial_policy
        if policy is None:  # model validation is the public boundary
            return []
    if value.agreement_state in {AgreementState.PAST_DUE, AgreementState.GRACE}:
        allowed_keys = frozenset(value.state_retained_keys)
    if value.agreement_state == AgreementState.CANCELED:
        if (
            value.entitlement_access_until is None
            or value.entitlement_access_until <= value.projected_at
        ):
            return []
        allowed_keys = frozenset(value.state_retained_keys)
    if allowed_keys == frozenset():
        return []
    end = value.effective_until
    if value.entitlement_access_until is not None:
        end = min(
            (candidate for candidate in (end, value.entitlement_access_until) if candidate),
            default=None,
        )
        if value.entitlement_access_until <= value.projected_at:
            return []
    if end is not None and end <= value.effective_from:
        return []
    source: SourceKind = (
        "payment_grace"
        if value.agreement_state in {AgreementState.PAST_DUE, AgreementState.GRACE}
        else "agreement"
    )
    facts: list[CanonicalEntitlementFact] = []
    for grant in policy.grants:
        if allowed_keys is not None and grant.key not in allowed_keys:
            continue
        _validate_effect_value(grant.effect, grant.value)
        subjects: list[tuple[SubjectKind, int | None, UUID | None]]
        if grant.subject_kind == "account":
            subjects = [("account", None, None)]
        elif grant.subject_kind == "user":
            subjects = [("user", user_id, None) for user_id in value.active_user_ids]
        else:
            subjects = [
                ("mcp_token", None, subject.token_id)
                for subject in value.token_subjects
            ]
        for subject_kind, user_id, token_id in subjects:
            facts.append(
                CanonicalEntitlementFact(
                    subject_kind=subject_kind,
                    subject_user_id=user_id,
                    subject_mcp_token_id=token_id,
                    source_kind=source,
                    entitlement_key=grant.key,
                    effect=grant.effect,
                    value=grant.value,
                    priority=0,
                    effective_from=max(
                        value.effective_from, value.state_effective_from
                    ),
                    effective_until=end,
                    reason_code="policy.projection",
                )
            )
    return facts


def _explicit_facts(value: EntitlementProjectionInput) -> list[CanonicalEntitlementFact]:
    def bounded(fact: ExplicitEntitlementFact) -> CanonicalEntitlementFact | None:
        start = max(fact.effective_from, value.effective_from)
        end = min(
            (
                candidate
                for candidate in (fact.effective_until, value.effective_until)
                if candidate is not None
            ),
            default=None,
        )
        if end is not None and end <= start:
            return None
        if end is not None and end <= value.projected_at:
            return None
        return CanonicalEntitlementFact(
            **fact.model_dump(
                mode="python", exclude={"effective_from", "effective_until"}
            ),
            effective_from=start,
            effective_until=end,
        )

    if value.agreement_state != AgreementState.ACTIVE:
        result = [
            bounded(fact)
            for fact in value.explicit_facts
            if fact.effect == "deny"
            and fact.effective_from <= value.projected_at
            and (fact.effective_until is None or fact.effective_until > value.projected_at)
        ]
        return [fact for fact in result if fact is not None]
    active_users = set(value.active_user_ids)
    active_tokens = {subject.token_id for subject in value.token_subjects}
    result = [
        bounded(fact)
        for fact in value.explicit_facts
        if fact.effective_from <= value.projected_at
        and (fact.effective_until is None or fact.effective_until > value.projected_at)
        and (fact.subject_kind != "user" or fact.subject_user_id in active_users)
        and (
            fact.subject_kind != "mcp_token"
            or fact.subject_mcp_token_id in active_tokens
        )
    ]
    return [fact for fact in result if fact is not None]


def _resolve_conflicts(
    facts: list[CanonicalEntitlementFact],
) -> list[CanonicalEntitlementFact]:
    groups: dict[tuple, list[CanonicalEntitlementFact]] = {}
    for fact in facts:
        groups.setdefault(_subject_key(fact), []).append(fact)
    resolved: list[CanonicalEntitlementFact] = []
    for identity in sorted(groups):
        candidates = groups[identity]
        denies = [fact for fact in candidates if fact.effect == "deny"]
        if denies:
            resolved.append(sorted(denies, key=_sort_key)[0])
            continue
        limits = [fact for fact in candidates if fact.effect == "limit"]
        if limits:
            resolved.append(
                min(limits, key=lambda fact: (int(fact.value), _sort_key(fact)))
            )
            continue
        allows = [fact for fact in candidates if fact.effect == "allow"]
        if allows:
            resolved.append(sorted(allows, key=_sort_key)[0])
    return resolved


def project_entitlements(value: EntitlementProjectionInput) -> EntitlementProjection:
    """Return the canonical effective fact set and content digest without I/O."""

    if value.projected_at < value.effective_from or (
        value.effective_until is not None
        and value.projected_at >= value.effective_until
    ):
        return EntitlementProjection(facts=(), content_sha256=canonical_sha256([]))
    resolved = _resolve_conflicts(_policy_facts(value) + _explicit_facts(value))
    eligibility_subjects = {
        _subject_key(fact)[:3]
        for fact in resolved
        if fact.entitlement_key == "eligibility:trade-execute-opt-in"
        and fact.effect == "allow"
    }
    account_eligible = ("account", 0, "") in eligibility_subjects
    resolved = [
        fact
        for fact in resolved
        if fact.entitlement_key != "scope:trade-execute"
        or fact.effect == "deny"
        or account_eligible
    ]
    canonical = tuple(sorted(resolved, key=_sort_key))
    digest = canonical_sha256(
        [fact.model_dump(mode="python") for fact in canonical]
    )
    return EntitlementProjection(facts=canonical, content_sha256=digest)


def resolve_effective_entitlements(
    facts: tuple[CanonicalEntitlementFact, ...],
    *,
    user_id: int | None = None,
    token_id: UUID | None = None,
) -> tuple[CanonicalEntitlementFact, ...]:
    """Resolve account plus matching subject facts with deny/min-limit precedence."""

    applicable = [
        fact
        for fact in facts
        if fact.subject_kind == "account"
        or (fact.subject_kind == "user" and fact.subject_user_id == user_id)
        or (
            fact.subject_kind == "mcp_token"
            and fact.subject_mcp_token_id == token_id
        )
    ]
    groups: dict[str, list[CanonicalEntitlementFact]] = {}
    for fact in applicable:
        groups.setdefault(fact.entitlement_key, []).append(fact)
    result: list[CanonicalEntitlementFact] = []
    for key in sorted(groups):
        candidates = groups[key]
        denies = [fact for fact in candidates if fact.effect == "deny"]
        if denies:
            result.append(sorted(denies, key=_sort_key)[0])
            continue
        limits = [fact for fact in candidates if fact.effect == "limit"]
        if limits:
            result.append(
                min(limits, key=lambda fact: (int(fact.value), _sort_key(fact)))
            )
            continue
        allows = [fact for fact in candidates if fact.effect == "allow"]
        if allows:
            result.append(sorted(allows, key=_sort_key)[0])
    return tuple(sorted(result, key=lambda fact: fact.entitlement_key))


__all__ = [
    "CanonicalEntitlementFact",
    "EntitlementProjection",
    "EntitlementProjectionInput",
    "EntitlementTokenSubject",
    "ExplicitEntitlementFact",
    "project_entitlements",
    "resolve_effective_entitlements",
]
