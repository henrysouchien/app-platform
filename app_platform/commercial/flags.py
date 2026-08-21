"""Typed, default-off feature flags for the commercial control plane."""

from __future__ import annotations

from dataclasses import dataclass, fields
import os
import threading
from typing import Mapping


_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_ENVIRONMENT_ALIASES = {
    "dev": "dev",
    "development": "dev",
    "local": "dev",
    "test": "dev",
    "testing": "dev",
    "staging": "staging",
    "stage": "staging",
    "prod": "prod",
    "production": "prod",
}


def _read_flag(env: Mapping[str, str], name: str) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return False
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be one of true/false, 1/0, yes/no, or on/off; got {raw!r}"
    )


def _read_environment(env: Mapping[str, str]) -> str:
    raw = (env.get("ENVIRONMENT") or "development").strip().lower()
    normalized = _ENVIRONMENT_ALIASES.get(raw)
    if normalized is None:
        raise ValueError(f"ENVIRONMENT is not supported by commercial controls: {raw!r}")
    return normalized


@dataclass(frozen=True, slots=True)
class CommercialFlags:
    """Validated commercial rollout state.

    These flags control behavior, not policy contents.  Every flag is false when
    absent so deploying the code cannot activate commercial behavior implicitly.
    """

    environment: str
    commercial_control_enabled: bool = False
    commercial_entitlement_projection_enabled: bool = False
    commercial_tier_compatibility_shadow_enabled: bool = False
    commercial_usage_ingest_enabled: bool = False
    commercial_work_authorization_enabled: bool = False
    commercial_usage_shadow_mode: bool = False
    commercial_budget_shadow_mode: bool = False
    commercial_budget_enforcement_enabled: bool = False
    commercial_budget_rollout_guard_enabled: bool = False
    commercial_budget_reconciliation_enabled: bool = False
    commercial_budget_reconciliation_auto_repair_enabled: bool = False
    commercial_reconciliation_enabled: bool = False
    commercial_retry_lineage_shadow_mode: bool = False
    commercial_retry_lineage_enforcement_enabled: bool = False
    commercial_token_limit_shadow_mode: bool = False
    commercial_token_limit_enforcement_enabled: bool = False
    mcp_external_auth_enabled: bool = False
    stripe_billing_enabled: bool = False
    stripe_live_mode_enabled: bool = False
    invite_trial_enabled: bool = False
    self_serve_checkout_enabled: bool = False
    customer_billing_portal_enabled: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "CommercialFlags":
        flags = cls(
            environment=_read_environment(env),
            commercial_control_enabled=_read_flag(env, "COMMERCIAL_CONTROL_ENABLED"),
            commercial_entitlement_projection_enabled=_read_flag(
                env, "COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED"
            ),
            commercial_tier_compatibility_shadow_enabled=_read_flag(
                env, "COMMERCIAL_TIER_COMPATIBILITY_SHADOW_ENABLED"
            ),
            commercial_usage_ingest_enabled=_read_flag(
                env, "COMMERCIAL_USAGE_INGEST_ENABLED"
            ),
            commercial_work_authorization_enabled=_read_flag(
                env, "COMMERCIAL_WORK_AUTHORIZATION_ENABLED"
            ),
            commercial_usage_shadow_mode=_read_flag(
                env, "COMMERCIAL_USAGE_SHADOW_MODE"
            ),
            commercial_budget_shadow_mode=_read_flag(
                env, "COMMERCIAL_BUDGET_SHADOW_MODE"
            ),
            commercial_budget_enforcement_enabled=_read_flag(
                env, "COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED"
            ),
            commercial_budget_rollout_guard_enabled=_read_flag(
                env, "COMMERCIAL_BUDGET_ROLLOUT_GUARD_ENABLED"
            ),
            commercial_budget_reconciliation_enabled=_read_flag(
                env, "COMMERCIAL_BUDGET_RECONCILIATION_ENABLED"
            ),
            commercial_budget_reconciliation_auto_repair_enabled=_read_flag(
                env, "COMMERCIAL_BUDGET_RECONCILIATION_AUTO_REPAIR_ENABLED"
            ),
            commercial_reconciliation_enabled=_read_flag(
                env, "COMMERCIAL_RECONCILIATION_ENABLED"
            ),
            commercial_retry_lineage_shadow_mode=_read_flag(
                env, "COMMERCIAL_RETRY_LINEAGE_SHADOW_MODE"
            ),
            commercial_retry_lineage_enforcement_enabled=_read_flag(
                env, "COMMERCIAL_RETRY_LINEAGE_ENFORCEMENT_ENABLED"
            ),
            commercial_token_limit_shadow_mode=_read_flag(
                env, "COMMERCIAL_TOKEN_LIMIT_SHADOW_MODE"
            ),
            commercial_token_limit_enforcement_enabled=_read_flag(
                env, "COMMERCIAL_TOKEN_LIMIT_ENFORCEMENT_ENABLED"
            ),
            mcp_external_auth_enabled=_read_flag(env, "MCP_EXTERNAL_AUTH_ENABLED"),
            stripe_billing_enabled=_read_flag(env, "STRIPE_BILLING_ENABLED"),
            stripe_live_mode_enabled=_read_flag(env, "STRIPE_LIVE_MODE_ENABLED"),
            invite_trial_enabled=_read_flag(env, "INVITE_TRIAL_ENABLED"),
            self_serve_checkout_enabled=_read_flag(
                env, "SELF_SERVE_CHECKOUT_ENABLED"
            ),
            customer_billing_portal_enabled=_read_flag(
                env, "CUSTOMER_BILLING_PORTAL_ENABLED"
            ),
        )
        flags.validate()
        if flags.customer_billing_portal_enabled:
            missing_runtime = [
                name
                for name in (
                    "CELERY_ENABLED",
                    "COMMERCIAL_STRIPE_WEBHOOK_PROJECTOR_ENABLED",
                )
                if not _read_flag(env, name)
            ]
            if missing_runtime:
                raise ValueError(
                    "CUSTOMER_BILLING_PORTAL_ENABLED requires "
                    + ", ".join(missing_runtime)
                )
        return flags

    def validate(self) -> None:
        """Reject combinations that can bypass required lower layers."""

        if self.environment not in {"dev", "staging", "prod"}:
            raise ValueError(f"Unsupported commercial environment: {self.environment!r}")

        enabled_children = [
            field.name
            for field in fields(self)
            if field.name not in {"environment", "commercial_control_enabled"}
            and bool(getattr(self, field.name))
        ]
        if enabled_children and not self.commercial_control_enabled:
            raise ValueError(
                "COMMERCIAL_CONTROL_ENABLED is required when any commercial child flag is enabled: "
                + ", ".join(sorted(enabled_children))
            )

        self._require(
            self.commercial_tier_compatibility_shadow_enabled,
            self.commercial_entitlement_projection_enabled,
            "COMMERCIAL_TIER_COMPATIBILITY_SHADOW_ENABLED requires "
            "COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED",
        )
        self._require(
            self.commercial_usage_shadow_mode,
            self.commercial_usage_ingest_enabled,
            "COMMERCIAL_USAGE_SHADOW_MODE requires COMMERCIAL_USAGE_INGEST_ENABLED",
        )
        self._require(
            self.commercial_work_authorization_enabled,
            self.commercial_usage_ingest_enabled,
            "COMMERCIAL_WORK_AUTHORIZATION_ENABLED requires "
            "COMMERCIAL_USAGE_INGEST_ENABLED",
        )
        self._require(
            self.commercial_budget_shadow_mode,
            self.commercial_usage_ingest_enabled,
            "COMMERCIAL_BUDGET_SHADOW_MODE requires COMMERCIAL_USAGE_INGEST_ENABLED",
        )
        if self.commercial_budget_enforcement_enabled:
            missing = []
            if not self.commercial_entitlement_projection_enabled:
                missing.append("COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED")
            if not self.commercial_usage_ingest_enabled:
                missing.append("COMMERCIAL_USAGE_INGEST_ENABLED")
            if missing:
                raise ValueError(
                    "COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED requires " + ", ".join(missing)
                )

        self._require(
            self.commercial_budget_rollout_guard_enabled,
            self.commercial_budget_enforcement_enabled,
            "COMMERCIAL_BUDGET_ROLLOUT_GUARD_ENABLED requires "
            "COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED",
        )
        if (
            self.environment in {"staging", "prod"}
            and self.commercial_budget_enforcement_enabled
            and not self.commercial_budget_rollout_guard_enabled
        ):
            raise ValueError(
                "COMMERCIAL_BUDGET_ROLLOUT_GUARD_ENABLED is required for "
                "staging/production budget enforcement"
            )

        self._require(
            self.commercial_budget_reconciliation_enabled,
            self.commercial_budget_enforcement_enabled,
            "COMMERCIAL_BUDGET_RECONCILIATION_ENABLED requires "
            "COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED",
        )
        self._require(
            self.commercial_budget_reconciliation_auto_repair_enabled,
            self.commercial_budget_reconciliation_enabled,
            "COMMERCIAL_BUDGET_RECONCILIATION_AUTO_REPAIR_ENABLED requires "
            "COMMERCIAL_BUDGET_RECONCILIATION_ENABLED",
        )

        if self.commercial_retry_lineage_shadow_mode:
            missing = []
            requirements = {
                "COMMERCIAL_USAGE_INGEST_ENABLED": self.commercial_usage_ingest_enabled,
                "COMMERCIAL_WORK_AUTHORIZATION_ENABLED": self.commercial_work_authorization_enabled,
                "COMMERCIAL_RECONCILIATION_ENABLED": self.commercial_reconciliation_enabled,
            }
            missing.extend(name for name, enabled in requirements.items() if not enabled)
            if missing:
                raise ValueError(
                    "COMMERCIAL_RETRY_LINEAGE_SHADOW_MODE requires "
                    + ", ".join(missing)
                )

        self._require(
            self.commercial_retry_lineage_enforcement_enabled,
            self.commercial_retry_lineage_shadow_mode,
            "COMMERCIAL_RETRY_LINEAGE_ENFORCEMENT_ENABLED requires "
            "COMMERCIAL_RETRY_LINEAGE_SHADOW_MODE",
        )

        if self.commercial_token_limit_enforcement_enabled:
            missing = []
            requirements = {
                "COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED": self.commercial_entitlement_projection_enabled,
                "COMMERCIAL_USAGE_INGEST_ENABLED": self.commercial_usage_ingest_enabled,
                "MCP_EXTERNAL_AUTH_ENABLED": self.mcp_external_auth_enabled,
            }
            missing.extend(name for name, enabled in requirements.items() if not enabled)
            if missing:
                raise ValueError(
                    "COMMERCIAL_TOKEN_LIMIT_ENFORCEMENT_ENABLED requires "
                    + ", ".join(missing)
                )
            if not self.commercial_token_limit_shadow_mode:
                raise ValueError(
                    "COMMERCIAL_TOKEN_LIMIT_ENFORCEMENT_ENABLED requires "
                    "COMMERCIAL_TOKEN_LIMIT_SHADOW_MODE"
                )
        self._require(
            self.commercial_token_limit_shadow_mode,
            self.commercial_entitlement_projection_enabled,
            "COMMERCIAL_TOKEN_LIMIT_SHADOW_MODE requires "
            "COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED",
        )

        if self.mcp_external_auth_enabled:
            missing = []
            if not self.commercial_entitlement_projection_enabled:
                missing.append("COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED")
            if not self.commercial_budget_enforcement_enabled:
                missing.append("COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED")
            if missing:
                raise ValueError("MCP_EXTERNAL_AUTH_ENABLED requires " + ", ".join(missing))

        self._require(
            self.stripe_billing_enabled,
            self.commercial_entitlement_projection_enabled,
            "STRIPE_BILLING_ENABLED requires COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED",
        )
        self._require(
            self.stripe_live_mode_enabled,
            self.stripe_billing_enabled,
            "STRIPE_LIVE_MODE_ENABLED requires STRIPE_BILLING_ENABLED",
        )
        if self.stripe_live_mode_enabled and self.environment != "prod":
            raise ValueError("STRIPE_LIVE_MODE_ENABLED is allowed only in ENVIRONMENT=production")

        if self.invite_trial_enabled:
            missing = []
            if not self.mcp_external_auth_enabled:
                missing.append("MCP_EXTERNAL_AUTH_ENABLED")
            if not self.commercial_usage_ingest_enabled:
                missing.append("COMMERCIAL_USAGE_INGEST_ENABLED")
            if not self.commercial_budget_enforcement_enabled:
                missing.append("COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED")
            if not self.commercial_token_limit_shadow_mode:
                missing.append("COMMERCIAL_TOKEN_LIMIT_SHADOW_MODE")
            if not self.commercial_token_limit_enforcement_enabled:
                missing.append("COMMERCIAL_TOKEN_LIMIT_ENFORCEMENT_ENABLED")
            if missing:
                raise ValueError("INVITE_TRIAL_ENABLED requires " + ", ".join(missing))

        if self.self_serve_checkout_enabled:
            missing = []
            requirements = {
                "COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED": self.commercial_entitlement_projection_enabled,
                "COMMERCIAL_USAGE_INGEST_ENABLED": self.commercial_usage_ingest_enabled,
                "COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED": self.commercial_budget_enforcement_enabled,
                "MCP_EXTERNAL_AUTH_ENABLED": self.mcp_external_auth_enabled,
                "STRIPE_BILLING_ENABLED": self.stripe_billing_enabled,
            }
            missing.extend(name for name, enabled in requirements.items() if not enabled)
            if missing:
                raise ValueError("SELF_SERVE_CHECKOUT_ENABLED requires " + ", ".join(missing))
            if self.environment == "prod" and not self.stripe_live_mode_enabled:
                raise ValueError(
                    "SELF_SERVE_CHECKOUT_ENABLED in production requires STRIPE_LIVE_MODE_ENABLED"
                )

        self._require(
            self.customer_billing_portal_enabled,
            self.stripe_billing_enabled,
            "CUSTOMER_BILLING_PORTAL_ENABLED requires STRIPE_BILLING_ENABLED",
        )

    @staticmethod
    def _require(condition: bool, requirement: bool, message: str) -> None:
        if condition and not requirement:
            raise ValueError(message)


_FLAGS_LOCK = threading.Lock()
_FLAGS_CACHE: CommercialFlags | None = None


def get_commercial_flags(*, refresh: bool = False) -> CommercialFlags:
    """Return the process-level validated flag snapshot."""

    global _FLAGS_CACHE
    with _FLAGS_LOCK:
        if refresh or _FLAGS_CACHE is None:
            _FLAGS_CACHE = CommercialFlags.from_env()
        return _FLAGS_CACHE


def reset_commercial_flags_cache() -> None:
    """Clear cached flags for tests or an explicit configuration reload."""

    global _FLAGS_CACHE
    with _FLAGS_LOCK:
        _FLAGS_CACHE = None


__all__ = ["CommercialFlags", "get_commercial_flags", "reset_commercial_flags_cache"]
