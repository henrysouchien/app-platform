"""Fail-closed dynamic scope authority for one verified external MCP token."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictInt, field_validator, model_validator

from .entitlements import CanonicalEntitlementFact, resolve_effective_entitlements
from .errors import CommercialErrorCode
from .mcp_exposure import McpExposureManifest
from .models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256


ToolKey = Annotated[
    str,
    Field(pattern=r"^[a-z][a-z0-9-]*:[a-z][a-z0-9_]*$"),
]


class McpDynamicScopeRequest(StrictCommercialModel):
    tool_key: ToolKey
    user_id: Annotated[StrictInt, Field(gt=0)]
    token_id: UUID
    authorized_at: AwareDatetime
    token_requested_scopes: tuple[StableCode, ...] = Field(min_length=1, max_length=64)
    applicable_entitlements: tuple[CanonicalEntitlementFact, ...]
    emergency_denied_scopes: tuple[StableCode, ...] = ()

    @field_validator("token_requested_scopes", "emergency_denied_scopes")
    @classmethod
    def _canonical_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("MCP dynamic scopes must be sorted and unique")
        if any(not scope.startswith("scope:") for scope in value):
            raise ValueError("MCP dynamic scopes must use the scope namespace")
        return value


class McpDynamicScopeDecision(StrictCommercialModel):
    allowed: bool
    denial_code: CommercialErrorCode | None = None
    effective_scopes: tuple[StableCode, ...] = ()
    required_scopes: tuple[StableCode, ...] = ()
    manifest_version: StableCode
    manifest_sha256: Sha256Digest

    @model_validator(mode="after")
    def _coherent(self) -> "McpDynamicScopeDecision":
        if self.allowed == (self.denial_code is not None):
            raise ValueError("dynamic scope decisions require exactly one outcome")
        if self.allowed and not self.effective_scopes:
            raise ValueError("allowed dynamic scope decisions require effective scopes")
        if not set(self.required_scopes).issubset(self.effective_scopes):
            if self.allowed:
                raise ValueError("allowed tool scopes exceed effective token scopes")
        return self


def resolve_mcp_dynamic_scopes(
    manifest: McpExposureManifest,
    request: McpDynamicScopeRequest,
) -> McpDynamicScopeDecision:
    """Intersect current policy facts with token, manifest, and emergency authority."""

    if canonical_sha256(manifest.content_body()) != manifest.content_sha256:
        raise ValueError("MCP exposure manifest integrity check failed")
    exposure = manifest.tools.get(request.tool_key)
    if (
        exposure is None
        or exposure.exposure != "hosted-public"
        or exposure.availability != "v1"
    ):
        return McpDynamicScopeDecision(
            allowed=False,
            denial_code=CommercialErrorCode.TOOL_NOT_EXPOSED,
            manifest_version=manifest.manifest_version,
            manifest_sha256=manifest.content_sha256,
        )

    current_facts = tuple(
        fact
        for fact in request.applicable_entitlements
        if fact.effective_from <= request.authorized_at
        and (
            fact.effective_until is None
            or request.authorized_at < fact.effective_until
        )
    )
    effective_facts = resolve_effective_entitlements(
        current_facts,
        user_id=request.user_id,
        token_id=request.token_id,
    )
    allowed_entitlement_scopes = {
        fact.entitlement_key
        for fact in effective_facts
        if fact.entitlement_key.startswith("scope:")
        and fact.effect == "allow"
        and fact.value is True
    }
    public_v1_scopes = {
        scope
        for tool in manifest.tools.values()
        if tool.exposure == "hosted-public" and tool.availability == "v1"
        for scope in tool.required_scopes
    }
    effective_scopes = tuple(
        sorted(
            set(request.token_requested_scopes)
            & allowed_entitlement_scopes
            & public_v1_scopes
            - set(request.emergency_denied_scopes)
        )
    )
    required_scopes = tuple(exposure.required_scopes)
    if not set(required_scopes).issubset(effective_scopes):
        return McpDynamicScopeDecision(
            allowed=False,
            denial_code=CommercialErrorCode.TOKEN_SCOPE_DENIED,
            effective_scopes=effective_scopes,
            required_scopes=required_scopes,
            manifest_version=manifest.manifest_version,
            manifest_sha256=manifest.content_sha256,
        )
    return McpDynamicScopeDecision(
        allowed=True,
        effective_scopes=effective_scopes,
        required_scopes=required_scopes,
        manifest_version=manifest.manifest_version,
        manifest_sha256=manifest.content_sha256,
    )


__all__ = [
    "McpDynamicScopeDecision",
    "McpDynamicScopeRequest",
    "ToolKey",
    "resolve_mcp_dynamic_scopes",
]
