"""Server-side payer classification from immutable terms and observed routes."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
import json
from typing import Annotated, Any, Literal

from pydantic import Field, JsonValue, StrictInt, model_validator

from .models import (
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)
from .policies import PayerPolicyBody, PayerRule


class PayerClass(StrEnum):
    CUSTOMER_PAID = "customer_paid"
    HANK_PAID = "hank_paid"
    HANK_SHADOW_PRICED = "hank_shadow_priced"


class PayerDecisionState(StrEnum):
    CLASSIFIED = "classified"
    QUARANTINED = "quarantined"


class ObservedCredentialRoute(StrictCommercialModel):
    provider: StableCode
    cost_class: StableCode
    credential_route: StableCode
    credential_owner: Literal["customer", "hank", "flat_subscription"]
    credential_reference_sha256: Sha256Digest


class PayerPolicyIdentity(StrictCommercialModel):
    policy_id: Annotated[StrictInt, Field(gt=0)]
    policy_code: StableCode
    version: NonEmptyStr
    content_sha256: Sha256Digest


class VerifiedPayerPolicy(StrictCommercialModel):
    identity: PayerPolicyIdentity
    source_body: dict[str, JsonValue]
    policy: PayerPolicyBody

    @model_validator(mode="after")
    def _verified_snapshot(self) -> "VerifiedPayerPolicy":
        if canonical_sha256(self.source_body) != self.identity.content_sha256:
            raise ValueError("payer policy content hash mismatch")
        if PayerPolicyBody.model_validate(self.source_body) != self.policy:
            raise ValueError("payer policy typed body differs from its source snapshot")
        return self

    @classmethod
    def from_raw(
        cls, *, identity: PayerPolicyIdentity, source_body: dict[str, JsonValue]
    ) -> "VerifiedPayerPolicy":
        return cls(
            identity=identity,
            source_body=source_body,
            policy=PayerPolicyBody.model_validate(source_body),
        )


class PayerClassificationDecision(StrictCommercialModel):
    state: PayerDecisionState
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    payer_policy: PayerPolicyIdentity
    observed_route: ObservedCredentialRoute
    payer_class: PayerClass | None = None
    matched_cost_class: StableCode | None = None
    reason_code: StableCode

    @model_validator(mode="after")
    def _coherent(self) -> "PayerClassificationDecision":
        if self.state is PayerDecisionState.CLASSIFIED:
            if self.payer_class is None or self.matched_cost_class is None:
                raise ValueError("classified payer decision is incomplete")
        elif self.payer_class is not None or self.matched_cost_class is not None:
            raise ValueError("quarantined payer decision cannot assert a payer")
        return self


def classify_payer(
    *,
    commercial_account_id: int,
    agreement_id: int,
    agreement_terms_id: int,
    payer_policy: VerifiedPayerPolicy,
    observed_route: ObservedCredentialRoute,
) -> PayerClassificationDecision:
    matches = [
        rule
        for rule in payer_policy.policy.rules
        if rule.cost_class == observed_route.cost_class
        and rule.credential_owner == observed_route.credential_owner
        and observed_route.provider in rule.providers
        and _selector_matches(rule.credential_route, observed_route.credential_route)
    ]
    if matches:
        maximum = max(_specificity(rule) for rule in matches)
        matches = [rule for rule in matches if _specificity(rule) == maximum]
    if len(matches) != 1:
        return PayerClassificationDecision(
            state=PayerDecisionState.QUARANTINED,
            commercial_account_id=commercial_account_id,
            agreement_id=agreement_id,
            agreement_terms_id=agreement_terms_id,
            payer_policy=payer_policy.identity,
            observed_route=observed_route,
            reason_code=(
                "payer.route_unmatched" if not matches else "payer.route_ambiguous"
            ),
        )
    rule = matches[0]
    return PayerClassificationDecision(
        state=PayerDecisionState.CLASSIFIED,
        commercial_account_id=commercial_account_id,
        agreement_id=agreement_id,
        agreement_terms_id=agreement_terms_id,
        payer_policy=payer_policy.identity,
        observed_route=observed_route,
        payer_class=PayerClass(rule.payer_class),
        matched_cost_class=rule.cost_class,
        reason_code="payer.policy_match",
    )


class PostgresPayerClassifier:
    """Resolve payer policy only through the durable agreement-terms identity."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def classify(
        self,
        *,
        agreement_terms_id: int,
        observed_route: ObservedCredentialRoute,
        evaluated_at: datetime,
    ) -> PayerClassificationDecision:
        if not isinstance(evaluated_at, datetime) or evaluated_at.tzinfo is None:
            raise ValueError("payer evaluation time must be timezone-aware")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT terms.commercial_account_id, terms.agreement_id, terms.id,
                       policy.id, policy.policy_code, policy.version,
                       policy.content_sha256, policy.body_json,
                       terms.effective_from, terms.effective_until
                  FROM commercial_agreement_terms terms
                  JOIN commercial_policy_versions policy
                    ON policy.id = terms.payer_policy_id
                   AND policy.policy_kind = 'payer'
                   AND policy.state IN ('active', 'retired')
                 WHERE terms.id = %s AND terms.sealed_at IS NOT NULL
                """,
                (agreement_terms_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise ValueError("agreement terms payer policy is unavailable")
        effective_from, effective_until = row[8], row[9]
        if evaluated_at < effective_from or (
            effective_until is not None and evaluated_at >= effective_until
        ):
            raise ValueError("agreement terms are not effective at payer evaluation time")
        body = json.loads(row[7]) if isinstance(row[7], str) else row[7]
        if not isinstance(body, dict) or canonical_sha256(body) != row[6]:
            raise ValueError("durable payer policy content hash mismatch")
        identity = PayerPolicyIdentity(
            policy_id=int(row[3]),
            policy_code=str(row[4]),
            version=str(row[5]),
            content_sha256=str(row[6]),
        )
        verified_policy = VerifiedPayerPolicy.from_raw(
            identity=identity,
            source_body=body,
        )
        return classify_payer(
            commercial_account_id=int(row[0]),
            agreement_id=int(row[1]),
            agreement_terms_id=int(row[2]),
            payer_policy=verified_policy,
            observed_route=observed_route,
        )


def _selector_matches(selector: str, observed: str) -> bool:
    return selector == "*" or selector == observed


def _specificity(rule: PayerRule) -> int:
    return int(rule.credential_route != "*")


__all__ = [
    "ObservedCredentialRoute",
    "PayerClass",
    "PayerClassificationDecision",
    "PayerDecisionState",
    "PayerPolicyIdentity",
    "PostgresPayerClassifier",
    "VerifiedPayerPolicy",
    "classify_payer",
]
