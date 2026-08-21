"""Typed named-operator CLI for controlled commercial pilot operations."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
from decimal import Decimal
import json
import logging
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, ContextManager, Literal, Mapping
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from database.session import get_db_session

from .authority import CommercialRole
from .authority_store import PostgresChangeRequestStore, load_named_operator
from .admin_snapshot import CommercialAdminSnapshotService
from .account_commands import AccountCommandService, AccountCreateCommand
from .agreement_lifecycle import (
    AgreementTermsChangeCommand,
    AgreementTransitionCommand,
    CommercialAgreementLifecycleService,
)
from .agreements import AgreementState, CommercialAgreementItemCreate
from .errors import CommercialError
from .change_request_commands import ChangeRequestCommandService
from .flags import CommercialFlags, get_commercial_flags
from .manual_agreements import (
    ManualAgreementActivationCommand,
    ManualAgreementActivationIntent,
    ManualAgreementDraftCommand,
    ManualBudgetEnvelope,
    ManualAgreementPreview,
    ManualAgreementPreviewRequest,
    ManualAgreementPreviewService,
    ManualAgreementService,
)
from .models import canonical_sha256
from .manual_billing import (
    ManualBillingService,
    ManualInvoiceCommand,
    ManualMovementCommand,
)
from .manual_catalog import ManualCatalogDiscoveryService
from .operator_identity import (
    load_operator_assertion_public_key,
    verify_operator_assertion,
)
from .entitlement_store import AccountEntitlementProjectionHook
from .entitlement_overrides import (
    EntitlementOverrideCommand,
    EntitlementOverrideService,
)
from .legacy_cutover import LegacyCutoverService, LegacyUserClassification
from .invite_trials import InviteTrialService, TrialInviteCommand
from .mcp_token_lifecycle import McpTokenLifecycleService, McpTokenRevokeCommand
from .pilot_report import PilotWeeklyReportService
from .reconciliation import (
    BillingReconciliationCommand,
    CommercialReconciliationService,
    ProviderCostReconciliationCommand,
    ProviderCostResolutionCommand,
    ReconciliationResolutionCommand,
)
from .billing.stripe_repair_workflow import (
    ObserverConnectionFactory,
    execute_stripe_repair_workflow,
    get_stripe_repair_observer_connection,
)

Environment = Literal["dev", "staging", "prod"]
ConnectionFactory = Callable[[], ContextManager[Any]]
logger = logging.getLogger(__name__)


class _ControlledPilotProjection:
    """Phase-C1 boundary: agreement state changes do not grant entitlements yet."""

    def __init__(self, flags: CommercialFlags) -> None:
        self._flags = flags

    def agreement_changed(self, connection: object, **_change: Any) -> None:
        if self._flags.commercial_entitlement_projection_enabled:
            raise RuntimeError(
                "an entitlement projection hook is required when projection is enabled"
            )


def _projection_hook(flags: CommercialFlags) -> object:
    if flags.commercial_entitlement_projection_enabled:
        return AccountEntitlementProjectionHook(flags=flags)
    return _ControlledPilotProjection(flags)


def _json_input(path: str) -> dict[str, Any]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def _protected_file_value(path: str, *, label: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} file cannot be opened safely") from exc
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or facts.st_nlink != 1
            or facts.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ValueError(
                f"{label} file must be an owner-only, singly linked regular file"
            )
        if facts.st_size <= 0 or facts.st_size > 16_384:
            raise ValueError(f"{label} file size is invalid")
        payload = bytearray()
        while len(payload) <= 16_384:
            chunk = os.read(descriptor, min(4096, 16_385 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > 16_384:
            raise ValueError(f"{label} file size is invalid")
        try:
            value = payload.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ValueError(f"{label} file is not valid UTF-8") from exc
        if not value:
            raise ValueError(f"{label} file is empty")
        return value
    finally:
        os.close(descriptor)


def _step_up_event_id(path: str) -> UUID:
    try:
        return UUID(_protected_file_value(path, label="step-up event"))
    except ValueError as exc:
        raise ValueError("step-up event file must contain one UUID") from exc


def _json_output(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, default=str, indent=2, sort_keys=True)


def _public_change_request(request: Any) -> dict[str, Any]:
    return request.model_dump(
        mode="json",
        exclude={
            "requester_step_up_at",
            "requester_step_up_event_id",
            "approver_step_up_at",
            "approver_step_up_event_id",
            "executor_step_up_at",
            "executor_step_up_event_id",
        },
    )


def _manual_billing_contract(kind: Literal["invoice", "movement"]) -> dict[str, Any]:
    if kind == "invoice":
        model = ManualInvoiceCommand
        example = {
            "idempotency_key": "invoice-acme-2026-07",
            "commercial_account_id": 123,
            "agreement_id": 456,
            "external_document_id": "invoice-acme-2026-07",
            "document_kind": "manual_invoice",
            "status_source_event_id": "invoice-acme-2026-07.open",
            "status": "open",
            "currency": "USD",
            "issued_at": "2026-07-01T00:00:00Z",
            "status_effective_at": "2026-07-01T00:00:00Z",
            "lines": [
                {
                    "external_line_id": "invoice-acme-2026-07.line-1",
                    "agreement_terms_id": 789,
                    "price_code": None,
                    "net_consideration_ex_tax_cents": 10000,
                    "tax_cents": 0,
                    "service_period_start_at": "2026-07-01T00:00:00Z",
                    "service_period_end_at": "2026-08-01T00:00:00Z",
                    "allocations": [
                        {
                            "period_start_at": "2026-07-01T00:00:00Z",
                            "period_end_at": "2026-08-01T00:00:00Z",
                            "recognized_revenue_cents": 10000,
                        }
                    ],
                }
            ],
            "reason_code": "billing.manual_invoice",
        }
    else:
        model = ManualMovementCommand
        example = {
            "idempotency_key": "refund-acme-2026-07",
            "commercial_account_id": 123,
            "agreement_id": 456,
            "document_id": 1001,
            "external_object_type": "refund_note",
            "external_object_id": "refund-acme-2026-07",
            "movement_kind": "refund",
            "signed_amount_cents": -500,
            "currency": "USD",
            "occurred_at": "2026-07-15T00:00:00Z",
            "reason_code": "billing.customer_refund",
        }
    model.model_validate(example)
    return {
        "kind": kind,
        "schema": model.model_json_schema(),
        "example": example,
        "usage": (
            "Save example as JSON, replace durable IDs/timestamps/amounts, then pass it "
            f"to record-manual-{kind} --input FILE with a signed operator assertion."
        ),
    }


def _manual_pilot_contract() -> dict[str, Any]:
    service_start = datetime(2026, 8, 1, tzinfo=timezone.utc)
    service_end = datetime(2026, 9, 12, tzinfo=timezone.utc)
    account = {
        "idempotency_key": "pilot-acme-account-v1",
        "owner_user_id": 42,
        "kind": "firm",
        "display_name": "Acme Capital",
        "reason_code": "pilot.account_create",
    }
    preview_request = {
        "commercial_account_id": 123,
        "catalog_policy_id": 10,
        "offer_code": "founding_design_partner_pilot",
        "price_codes": ["founding_pilot_fixed_usd_v1"],
        "channel": "pilot",
        "service_start_at": "2026-08-01T00:00:00Z",
        "service_end_at": "2026-09-12T00:00:00Z",
        "contract_reference": "acme-pilot-2026",
        "source_event_id": "acme-pilot-2026.preview",
        "negotiated_amount_cents_by_price_code": {},
    }
    preview_facts: dict[str, Any] = {
        "commercial_account_id": 123,
        "catalog_policy_id": 10,
        "entitlement_policy_id": 11,
        "payer_policy_id": 12,
        "budget_policy_id": 13,
        "offer_code": "founding_design_partner_pilot",
        "primary_price_code": "founding_pilot_fixed_usd_v1",
        "surface_code": "hp1",
        "channel": "pilot",
        "currency": "USD",
        "service_start_at": service_start,
        "service_end_at": service_end,
        "current_period_start_at": service_start,
        "current_period_end_at": service_end,
        "contract_reference": "acme-pilot-2026",
        "source_event_id": "acme-pilot-2026.preview",
        "contracted_service_period_cents": 300_000,
        "total_contract_value_cents": 300_000,
        "items": (
            CommercialAgreementItemCreate(
                item_code="founding_pilot_fixed_usd_v1",
                item_kind="recurring",
                price_code="founding_pilot_fixed_usd_v1",
                quantity=Decimal("1"),
                unit_amount_cents=300_000,
                billing_interval="fixed_term",
                service_start_at=service_start,
                service_end_at=service_end,
                metadata={"catalog_price_code": "founding_pilot_fixed_usd_v1"},
            ),
        ),
        "budget": ManualBudgetEnvelope(
            model_budget_microusd=50_000_000,
            technical_ceiling_microusd_by_price_code={
                "founding_pilot_fixed_usd_v1": 60_000_000
            },
            non_model_ceiling_microusd_by_price_code={
                "founding_pilot_fixed_usd_v1": 10_000_000
            },
            max_period_overdraft_microusd=1_000_000,
        ),
    }
    preview_model = ManualAgreementPreview(
        preview_sha256=canonical_sha256(preview_facts),
        **preview_facts,
    )
    preview = preview_model.model_dump(mode="json")
    draft = {
        "idempotency_key": "acme-pilot-draft-v1",
        "reason_code": "pilot.agreement_draft",
        "preview": preview,
    }
    activation = {
        "agreement_id": 456,
        "expected_version": 1,
        "idempotency_key": "acme-pilot-activate-v1",
        "reason_code": "pilot.agreement_activate",
        "preview": preview,
    }
    AccountCreateCommand.model_validate(account)
    ManualAgreementPreviewRequest.model_validate(preview_request)
    ManualAgreementPreview.model_validate(preview)
    ManualAgreementDraftCommand.model_validate(draft)
    ManualAgreementActivationIntent.model_validate(activation)
    return {
        "schema_version": "commercial.manual-pilot-contract.v1",
        "schemas": {
            "create_account": AccountCreateCommand.model_json_schema(),
            "preview_manual": ManualAgreementPreviewRequest.model_json_schema(),
            "create_manual_draft": ManualAgreementDraftCommand.model_json_schema(),
            "activation_intent": ManualAgreementActivationIntent.model_json_schema(),
        },
        "examples": {
            "create_account": account,
            "preview_manual": preview_request,
            "preview_result_shape": preview,
            "create_manual_draft": draft,
            "activation_intent": activation,
        },
        "prerequisite": {
            "command": "manual-catalog",
            "argv": [
                "manual-catalog",
                "--operator-assertion-file",
                "/secure/requester.assertion",
                "--environment",
                "dev",
            ],
            "selector": (
                "catalog_policy_id_by_offer_price."
                "founding_design_partner_pilot:founding_pilot_fixed_usd_v1"
            ),
            "substitute_into": "examples.preview_manual.catalog_policy_id",
            "selection_policy": (
                "the service chooses the newest active catalog containing the exact "
                "offer and price"
            ),
        },
        "workflow": [
            {
                "step": 1,
                "command": "create-account",
                "argv": [
                    "create-account",
                    "--operator-assertion-file",
                    "/secure/requester.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "account.json",
                ],
                "input_example": "create_account",
                "capture": "commercial_account_id",
                "substitute_into": "examples.preview_manual.commercial_account_id",
            },
            {
                "step": 2,
                "command": "preview-manual",
                "argv": [
                    "preview-manual",
                    "--operator-assertion-file",
                    "/secure/requester.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "preview.json",
                ],
                "input_example": "preview_manual",
                "capture": "$",
                "substitute_into": "examples.create_manual_draft.preview and examples.activation_intent.preview",
            },
            {
                "step": 3,
                "command": "create-manual-draft",
                "argv": [
                    "create-manual-draft",
                    "--operator-assertion-file",
                    "/secure/requester.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "draft.json",
                ],
                "input_example": "create_manual_draft",
                "capture": ["agreement_id", "version"],
                "substitute_into": [
                    "examples.activation_intent.agreement_id",
                    "examples.activation_intent.expected_version",
                ],
            },
            {
                "step": 4,
                "command": "request-manual-activation",
                "argv": [
                    "request-manual-activation",
                    "--operator-assertion-file",
                    "/secure/requester.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "activation.json",
                    "--step-up-event-file",
                    "/secure/requester-step-up.uuid",
                    "--expires-in-seconds",
                    "3600",
                    "--idempotency-key",
                    "acme-activation-request-v1",
                ],
                "input_example": "activation_intent",
                "capture": "request.request_id",
                "substitute_into": "steps[5].argv.--request-id and steps[6].argv.--request-id",
                "evidence": "requester assertion and requester step-up event are distinct protected files",
            },
            {
                "step": 5,
                "command": "approve-manual-activation",
                "argv": [
                    "approve-manual-activation",
                    "--operator-assertion-file",
                    "/secure/approver.assertion",
                    "--environment",
                    "dev",
                    "--request-id",
                    "00000000-0000-0000-0000-000000000001",
                    "--step-up-event-file",
                    "/secure/approver-step-up.uuid",
                    "--idempotency-key",
                    "acme-activation-approve-v1",
                ],
                "input_example": None,
                "capture": "request.state",
                "required_operator": (
                    "a different named commercial_admin than the requester in prod"
                ),
                "evidence": "approver assertion and approver step-up event",
            },
            {
                "step": 6,
                "command": "activate-manual",
                "argv": [
                    "activate-manual",
                    "--operator-assertion-file",
                    "/secure/requester.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "activation.json",
                    "--request-id",
                    "00000000-0000-0000-0000-000000000001",
                    "--step-up-event-file",
                    "/secure/executor-step-up.uuid",
                ],
                "input_example": "activation_intent",
                "capture": ["agreement_id", "result_terms_id", "state"],
                "evidence": "unchanged approved activation JSON and a new executor step-up event",
            },
        ],
        "usage": (
            "Run the prerequisite to discover the active catalog_policy_id, then follow each argv "
            "template and capture/substitution path. Write each selected example object "
            "to its named JSON file. Never edit a preview after step 2; copy the exact "
            "object into draft and activation inputs. Each mutation idempotency key and "
            "each step-up evidence file is intentionally separate."
        ),
    }


def _reconciliation_contract() -> dict[str, Any]:
    finding_id = "00000000-0000-0000-0000-000000000001"
    examples = {
        "reconcile_billing": {
            "idempotency_key": "reconcile-acme-2026-07-12",
            "commercial_account_id": 123,
            "reason_code": "reconciliation.operator_run",
        },
        "reconcile_provider_costs": {
            "idempotency_key": "reconcile-provider-costs-2026-07-12",
            "reason_code": "reconciliation.operator_run",
        },
        "resolve_billing_finding": {
            "idempotency_key": "resolve-acme-finding-v1",
            "commercial_account_id": 123,
            "source_finding_id": finding_id,
            "resolution_kind": "resolved",
            "reason_code": "reconciliation.operator_verified",
            "note_redacted": "Verified against corrected durable source facts; no customer content included.",
        },
        "resolve_provider_cost_finding": {
            "idempotency_key": "resolve-provider-finding-v1",
            "source_finding_id": finding_id,
            "resolution_kind": "accepted_risk",
            "reason_code": "reconciliation.temporary_variance",
            "note_redacted": "Temporary immaterial variance accepted; no customer content included.",
        },
    }
    models = {
        "reconcile_billing": BillingReconciliationCommand,
        "reconcile_provider_costs": ProviderCostReconciliationCommand,
        "resolve_billing_finding": ReconciliationResolutionCommand,
        "resolve_provider_cost_finding": ProviderCostResolutionCommand,
    }
    for name, model in models.items():
        model.model_validate(examples[name])
    return {
        "schema_version": "commercial.reconciliation-cli-contract.v1",
        "schemas": {name: model.model_json_schema() for name, model in models.items()},
        "examples": examples,
        "commands": {
            "reconcile_billing": "reconcile-billing",
            "reconcile_provider_costs": "reconcile-provider-costs",
            "resolve_billing_finding": "resolve-billing-finding",
            "resolve_provider_cost_finding": "resolve-provider-cost-finding",
        },
        "scope": {
            "reconcile": "records append-only reconciliation run and finding evidence",
            "resolve": "appends a named disposition to one latest open finding",
        },
        "limitations": [
            "does not execute suggested_repair or repair_kind",
            "does not mutate source billing, usage, cost, or budget facts",
            "does not rebuild or modify Redis enforcement state",
            "repair remains a separate audited operator workflow",
        ],
        "usage": (
            "Run reconciliation first and capture findings[].finding_id. Resolve only the "
            "latest open finding with a new idempotency key, stable reason code, and an "
            "optional already-redacted note. Never include customer data, credentials, "
            "prompts, responses, or secrets in note_redacted."
        ),
    }


def _entitlement_override_contract() -> dict[str, Any]:
    base = {
        "commercial_account_id": 123,
        "agreement_id": 456,
        "expected_entitlement_revision": 1,
        "surface_code": "hp1",
        "entitlement_key": "scope:trade-execute",
        "value": True,
        "priority": 100,
        "effective_from": "2026-08-01T00:00:00Z",
        "effective_until": "2026-08-08T00:00:00Z",
        "reason_code": "entitlement.pilot_override",
    }
    examples = {
        "safe_deny": {
            "idempotency_key": "deny-account-execution-v1",
            "operation": "create",
            **base,
            "subject_kind": "account",
            "subject_user_id": None,
            "effect": "deny",
        },
        "approved_allow": {
            "idempotency_key": "allow-user-execution-v1",
            "operation": "create",
            **base,
            "subject_kind": "user",
            "subject_user_id": 42,
            "effect": "allow",
        },
        "revoke": {
            "idempotency_key": "revoke-override-v1",
            "operation": "revoke",
            "commercial_account_id": 123,
            "agreement_id": 456,
            "expected_entitlement_revision": 1,
            "override_id": "00000000-0000-0000-0000-000000000001",
            "reason_code": "entitlement.pilot_override_revoke",
        },
    }
    for example in examples.values():
        EntitlementOverrideCommand.model_validate(example)
    return {
        "schema_version": "commercial.entitlement-override-cli-contract.v1",
        "schema": EntitlementOverrideCommand.model_json_schema(),
        "examples": examples,
        "authority": {
            "safe": "bounded deny/limit creation or allow revocation; entitlement_operator",
            "high_risk": (
                "allow creation or deny/limit revocation; commercial_admin step-up, "
                "approval, and distinct maker-checker in prod"
            ),
        },
        "safe_command": "apply-safe-entitlement-override",
        "high_risk_workflow": [
            "request-entitlement-override",
            "approve-entitlement-override",
            "execute-entitlement-override",
        ],
        "safe_workflow": {
            "command": "apply-safe-entitlement-override",
            "argv": [
                "apply-safe-entitlement-override",
                "--operator-assertion-file",
                "/secure/entitlement-operator.assertion",
                "--environment",
                "dev",
                "--input",
                "safe-deny.json",
            ],
            "input_example": "safe_deny",
            "required_operator": "named entitlement_operator",
        },
        "approval_workflow": [
            {
                "step": 1,
                "command": "request-entitlement-override",
                "argv": [
                    "request-entitlement-override",
                    "--operator-assertion-file",
                    "/secure/requester.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "approved-allow.json",
                    "--step-up-event-file",
                    "/secure/requester-step-up.uuid",
                    "--idempotency-key",
                    "request-approved-allow-v1",
                ],
                "input_example": "approved_allow",
                "capture": "request.request_id",
                "required_operator": "named commercial_admin with recent step-up",
            },
            {
                "step": 2,
                "command": "approve-entitlement-override",
                "argv": [
                    "approve-entitlement-override",
                    "--operator-assertion-file",
                    "/secure/approver.assertion",
                    "--environment",
                    "dev",
                    "--request-id",
                    "00000000-0000-0000-0000-000000000001",
                    "--step-up-event-file",
                    "/secure/approver-step-up.uuid",
                    "--idempotency-key",
                    "approve-approved-allow-v1",
                ],
                "input_example": None,
                "substitute": "request.request_id into argv.--request-id",
                "required_operator": (
                    "a different named commercial_admin than the requester in prod, "
                    "with recent step-up"
                ),
            },
            {
                "step": 3,
                "command": "execute-entitlement-override",
                "argv": [
                    "execute-entitlement-override",
                    "--operator-assertion-file",
                    "/secure/executor.assertion",
                    "--environment",
                    "dev",
                    "--input",
                    "approved-allow.json",
                    "--request-id",
                    "00000000-0000-0000-0000-000000000001",
                    "--step-up-event-file",
                    "/secure/executor-step-up.uuid",
                ],
                "input_example": "approved_allow",
                "substitute": "request.request_id into argv.--request-id",
                "required_operator": "named commercial_admin with recent step-up",
            },
        ],
        "usage": (
            "The JSON idempotency_key identifies the business mutation; keep it unchanged "
            "between request and execute. The request and approval --idempotency-key values "
            "identify those workflow commands and must be separate. Use the exact same approved "
            "input JSON for request and execute. Step-up UUIDs belong only in separate owner-only "
            "files. Capture request.request_id and substitute it into approval and execution."
        ),
    }


def _common(subparser: argparse.ArgumentParser, *, input_file: bool = False) -> None:
    subparser.add_argument(
        "--operator-assertion-file",
        required=True,
        help="Owner-only file containing a short-lived signed operator assertion.",
    )
    subparser.add_argument(
        "--environment", choices=("dev", "staging", "prod"), required=True
    )
    if input_file:
        subparser.add_argument(
            "--input",
            required=True,
            help="Typed JSON input file, or '-' for stdin.",
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app_platform.commercial",
        description=(
            "Named-operator commercial pilot controls. Authorization is resolved "
            "from durable role and step-up records."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    billing_contract = commands.add_parser(
        "describe-manual-billing",
        help="Print the JSON Schema and an editable manual billing example",
    )
    billing_contract.add_argument(
        "--kind", choices=("invoice", "movement"), required=True
    )

    commands.add_parser(
        "describe-manual-pilot",
        help="Print schemas, validated examples, and the manual pilot activation workflow",
    )

    commands.add_parser(
        "describe-reconciliation",
        help="Print schemas and validated examples for reconciliation and disposition commands",
    )

    commands.add_parser(
        "describe-entitlement-override",
        help="Print the typed override schema, examples, and authority workflow",
    )

    manual_catalog = commands.add_parser(
        "manual-catalog",
        help="List active manual offers and the durable catalog policy IDs they require",
    )
    _common(manual_catalog)

    for command, help_text in (
        (
            "reconcile-billing",
            "Run an account billing/revenue/economics reconciliation",
        ),
        ("reconcile-provider-costs", "Run environment provider-cost reconciliation"),
        (
            "resolve-billing-finding",
            "Append a disposition for a current billing finding",
        ),
        (
            "resolve-provider-cost-finding",
            "Append a disposition for a provider-cost finding",
        ),
    ):
        reconciliation = commands.add_parser(command, help=help_text)
        _common(reconciliation, input_file=True)

    request_stripe_repair = commands.add_parser(
        "request-stripe-repair",
        help="Request maker-checker approval for one current Stripe repair finding",
    )
    _common(request_stripe_repair)
    request_stripe_repair.add_argument("--finding-id", type=UUID, required=True)
    request_stripe_repair.add_argument("--reason-code", required=True)
    request_stripe_repair.add_argument("--step-up-event-file", required=True)
    request_stripe_repair.add_argument("--expires-in-seconds", type=int, default=3600)
    request_stripe_repair.add_argument("--idempotency-key", required=True)

    approve_stripe_repair = commands.add_parser(
        "approve-stripe-repair",
        help="Approve a pending Stripe repair request as a separate operator",
    )
    _common(approve_stripe_repair)
    approve_stripe_repair.add_argument("--request-id", type=UUID, required=True)
    approve_stripe_repair.add_argument("--step-up-event-file", required=True)
    approve_stripe_repair.add_argument("--idempotency-key", required=True)

    execute_stripe_repair = commands.add_parser(
        "execute-stripe-repair",
        help="Execute an approved Stripe repair and record fresh convergence evidence",
    )
    _common(execute_stripe_repair)
    execute_stripe_repair.add_argument("--request-id", type=UUID, required=True)
    execute_stripe_repair.add_argument("--step-up-event-file", required=True)

    issue_trial_invite = commands.add_parser(
        "issue-trial-invite",
        help="Issue one identity-bound invite for the hard-capped Standard trial",
    )
    _common(issue_trial_invite, input_file=True)

    incident_revoke = commands.add_parser(
        "revoke-compromised-mcp-token",
        help="Immediately revoke one MCP token as a named entitlement operator",
    )
    _common(incident_revoke, input_file=True)

    safe_override = commands.add_parser(
        "apply-safe-entitlement-override",
        help="Create a bounded deny/limit or revoke an allow",
    )
    _common(safe_override, input_file=True)

    request_override = commands.add_parser(
        "request-entitlement-override",
        help="Request approval for an access-expanding override mutation",
    )
    _common(request_override, input_file=True)
    request_override.add_argument("--step-up-event-file", required=True)
    request_override.add_argument("--expires-in-seconds", type=int, default=3600)
    request_override.add_argument("--idempotency-key", required=True)

    approve_override = commands.add_parser(
        "approve-entitlement-override",
        help="Approve an access-expanding override mutation",
    )
    _common(approve_override)
    approve_override.add_argument("--request-id", type=UUID, required=True)
    approve_override.add_argument("--step-up-event-file", required=True)
    approve_override.add_argument("--idempotency-key", required=True)

    execute_override = commands.add_parser(
        "execute-entitlement-override",
        help="Execute the exact approved override mutation",
    )
    _common(execute_override, input_file=True)
    execute_override.add_argument("--request-id", type=UUID, required=True)
    execute_override.add_argument("--step-up-event-file", required=True)

    preview = commands.add_parser(
        "preview-manual", help="Preview durable catalog terms"
    )
    _common(preview, input_file=True)

    draft = commands.add_parser("create-manual-draft", help="Create an audited draft")
    _common(draft, input_file=True)

    request = commands.add_parser(
        "request-manual-activation", help="Request approval for an activation intent"
    )
    _common(request, input_file=True)
    request.add_argument("--step-up-event-file", required=True)
    request.add_argument("--expires-in-seconds", type=int, default=3600)
    request.add_argument("--idempotency-key", required=True)

    approve = commands.add_parser(
        "approve-manual-activation", help="Approve a pending activation request"
    )
    _common(approve)
    approve.add_argument("--request-id", type=UUID, required=True)
    approve.add_argument("--step-up-event-file", required=True)
    approve.add_argument("--idempotency-key", required=True)

    show = commands.add_parser("show-change-request", help="Inspect approval state")
    _common(show)
    show.add_argument("--request-id", type=UUID, required=True)

    activate = commands.add_parser(
        "activate-manual", help="Execute an approved activation intent"
    )
    _common(activate, input_file=True)
    activate.add_argument("--request-id", type=UUID, required=True)
    activate.add_argument("--step-up-event-file", required=True)

    account = commands.add_parser(
        "create-account", help="Create an audited commercial account and owner"
    )
    _common(account, input_file=True)

    invoice = commands.add_parser(
        "record-manual-invoice",
        help="Record an audited manual invoice and revenue schedule",
        epilog=(
            "Run `python -m app_platform.commercial describe-manual-billing "
            "--kind invoice` for JSON Schema and a valid editable example."
        ),
    )
    _common(invoice, input_file=True)

    movement = commands.add_parser(
        "record-manual-movement",
        help="Record an audited receipt, refund, credit, or processor fee",
        epilog=(
            "Run `python -m app_platform.commercial describe-manual-billing "
            "--kind movement` for JSON Schema and a valid editable example."
        ),
    )
    _common(movement, input_file=True)

    transition = commands.add_parser(
        "transition-agreement", help="Pause, cancel, or expire an agreement"
    )
    _common(transition, input_file=True)

    terms = commands.add_parser(
        "schedule-terms", help="Schedule a future agreement terms revision"
    )
    _common(terms, input_file=True)
    terms.add_argument("--step-up-event-file")
    terms.add_argument("--change-request-id", type=UUID, action="append", default=[])

    audit = commands.add_parser(
        "audit-history", help="Retrieve commercial audit history"
    )
    _common(audit)
    audit.add_argument("--commercial-account-id", type=int, required=True)
    audit.add_argument("--agreement-id", type=int)
    audit.add_argument("--before-audit-id", type=int)
    audit.add_argument("--limit", type=int, default=100)

    admin_snapshot = commands.add_parser(
        "admin-account-snapshot",
        help="Render a bounded, secret-safe commercial account snapshot",
    )
    _common(admin_snapshot)
    admin_snapshot.add_argument("--commercial-account-id", type=int, required=True)

    inventory = commands.add_parser(
        "legacy-user-inventory",
        help="List paid/business users requiring cutover review",
    )
    _common(inventory)

    review = commands.add_parser(
        "review-legacy-user", help="Append an explicit legacy-user classification"
    )
    _common(review)
    review.add_argument("--user-id", type=int, required=True)
    review.add_argument("--observed-tier", choices=("paid", "business"), required=True)
    review.add_argument(
        "--classification",
        choices=tuple(value.value for value in LegacyUserClassification),
        required=True,
    )
    review.add_argument("--reason-code", required=True)
    review.add_argument("--agreement-id", type=int)

    pilot_report = commands.add_parser(
        "pilot-weekly-report",
        help="Render the immutable initial-pilot UTC-week economics report",
    )
    _common(pilot_report)
    pilot_report.add_argument(
        "--week-start",
        type=date.fromisoformat,
        required=True,
        help="UTC Monday in YYYY-MM-DD format.",
    )
    return parser


def _require_runtime_environment(
    args_environment: Environment, flags: CommercialFlags
) -> None:
    if flags.environment != args_environment:
        raise ValueError(
            "CLI environment must exactly match the configured deployment environment"
        )
    if not flags.commercial_control_enabled:
        raise ValueError("commercial control is disabled")


def _execute(
    args: argparse.Namespace,
    *,
    connection: Any,
    flags: CommercialFlags,
    now: datetime,
    operator_user_id: int,
) -> Any:
    environment: Environment = args.environment
    _require_runtime_environment(environment, flags)
    if args.command == "admin-account-snapshot":
        return CommercialAdminSnapshotService(
            connection, flags=flags
        ).render_account_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            commercial_account_id=args.commercial_account_id,
        )

    if args.command == "revoke-compromised-mcp-token":
        command = McpTokenRevokeCommand.model_validate(_json_input(args.input))
        if command.reason_code != "token.suspected_compromise":
            raise ValueError(
                "incident token revocation requires reason_code "
                "token.suspected_compromise"
            )
        return McpTokenLifecycleService(connection, flags=flags).revoke_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    deployment_cursor = connection.cursor()
    try:
        deployment_cursor.execute(
            "SELECT environment FROM commercial_deployment_context WHERE singleton"
        )
        deployment = deployment_cursor.fetchone()
    finally:
        deployment_cursor.close()
    if deployment is None or deployment[0] != environment:
        raise CommercialError("commercial_role_required")

    if args.command == "create-account":
        command = AccountCreateCommand.model_validate(_json_input(args.input))
        return AccountCommandService(connection).create_account(
            operator_user_id=operator_user_id,
            environment=environment,
            command=command,
        )

    if args.command == "manual-catalog":
        return ManualCatalogDiscoveryService(
            connection, flags=flags
        ).discover_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
        )

    if args.command == "reconcile-billing":
        command = BillingReconciliationCommand.model_validate(_json_input(args.input))
        return CommercialReconciliationService(
            connection, flags=flags
        ).reconcile_billing_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "reconcile-provider-costs":
        command = ProviderCostReconciliationCommand.model_validate(
            _json_input(args.input)
        )
        return CommercialReconciliationService(
            connection, flags=flags
        ).reconcile_provider_costs_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "resolve-billing-finding":
        command = ReconciliationResolutionCommand.model_validate(
            _json_input(args.input)
        )
        return CommercialReconciliationService(
            connection, flags=flags
        ).resolve_finding_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "resolve-provider-cost-finding":
        command = ProviderCostResolutionCommand.model_validate(_json_input(args.input))
        return CommercialReconciliationService(
            connection, flags=flags
        ).resolve_provider_cost_finding_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "request-stripe-repair":
        if args.expires_in_seconds < 60 or args.expires_in_seconds > 86400:
            raise ValueError("expires-in-seconds must be between 60 and 86400")
        result = ChangeRequestCommandService(connection).request_live_stripe_repair(
            operator_user_id=operator_user_id,
            environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            idempotency_key=args.idempotency_key,
            finding_id=args.finding_id,
            reason_code=args.reason_code,
            expires_in_seconds=args.expires_in_seconds,
            now=now,
        )
        return {
            "command_id": str(result.command_id),
            "replayed": result.replayed,
            "request": _public_change_request(result.request),
        }

    if args.command == "issue-trial-invite":
        command = TrialInviteCommand.model_validate(_json_input(args.input))
        return InviteTrialService(
            connection,
            flags=flags,
            projection_hook=_projection_hook(flags),
            clock=lambda: now,
        ).issue_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "approve-stripe-repair":
        result = ChangeRequestCommandService(connection).approve_live_stripe_repair(
            operator_user_id=operator_user_id,
            environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            idempotency_key=args.idempotency_key,
            request_id=args.request_id,
            now=now,
        )
        return {
            "command_id": str(result.command_id),
            "replayed": result.replayed,
            "request": _public_change_request(result.request),
        }

    if args.command == "apply-safe-entitlement-override":
        command = EntitlementOverrideCommand.model_validate(_json_input(args.input))
        return EntitlementOverrideService(
            connection, flags=flags, clock=lambda: now
        ).execute_safe_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "request-entitlement-override":
        if args.expires_in_seconds < 60 or args.expires_in_seconds > 86400:
            raise ValueError("expires-in-seconds must be between 60 and 86400")
        command = EntitlementOverrideCommand.model_validate(_json_input(args.input))
        result = EntitlementOverrideService(
            connection, flags=flags, clock=lambda: now
        ).request_high_risk_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            request_idempotency_key=args.idempotency_key,
            command=command,
            expires_in_seconds=args.expires_in_seconds,
        )
        return {
            "command_id": str(result.command_id),
            "replayed": result.replayed,
            "request": _public_change_request(result.request),
        }

    if args.command == "approve-entitlement-override":
        result = EntitlementOverrideService(
            connection, flags=flags, clock=lambda: now
        ).approve_high_risk_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            approval_idempotency_key=args.idempotency_key,
            request_id=args.request_id,
        )
        return {
            "command_id": str(result.command_id),
            "replayed": result.replayed,
            "request": _public_change_request(result.request),
        }

    if args.command == "execute-entitlement-override":
        command = EntitlementOverrideCommand.model_validate(_json_input(args.input))
        return EntitlementOverrideService(
            connection, flags=flags, clock=lambda: now
        ).execute_approved_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            request_id=args.request_id,
            command=command,
        )

    if args.command == "record-manual-invoice":
        command = ManualInvoiceCommand.model_validate(_json_input(args.input))
        return ManualBillingService(connection, flags=flags).record_invoice_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "record-manual-movement":
        command = ManualMovementCommand.model_validate(_json_input(args.input))
        return ManualBillingService(
            connection, flags=flags
        ).record_movement_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "transition-agreement":
        command = AgreementTransitionCommand.model_validate(_json_input(args.input))
        if command.target_state not in {
            AgreementState.PAUSED,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }:
            raise ValueError(
                "operator lifecycle command allows only paused, canceled, or expired"
            )
        return CommercialAgreementLifecycleService(
            connection,
            projection_hook=_projection_hook(flags),
            clock=lambda: now,
        ).transition_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "schedule-terms":
        command = AgreementTermsChangeCommand.model_validate(_json_input(args.input))
        if command.change_timing != "period_end":
            raise ValueError("schedule-terms requires change_timing period_end")
        if command.change_request_ids or command.step_up_event_id is not None:
            raise ValueError(
                "approval and step-up evidence must be supplied through protected CLI options"
            )
        command = command.model_copy(
            update={
                "change_request_ids": tuple(args.change_request_id),
                "step_up_event_id": _step_up_event_id(args.step_up_event_file)
                if args.step_up_event_file
                else None,
            }
        )
        return CommercialAgreementLifecycleService(
            connection,
            projection_hook=_projection_hook(flags),
            clock=lambda: now,
        ).change_terms_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    if args.command == "legacy-user-inventory":
        return [
            item.model_dump(mode="json")
            for item in LegacyCutoverService(connection).inventory_as_operator(
                operator_user_id=operator_user_id,
                environment=environment,
            )
        ]

    if args.command == "review-legacy-user":
        if args.user_id <= 0 or (
            args.agreement_id is not None and args.agreement_id <= 0
        ):
            raise ValueError("legacy review identifiers must be positive")
        return LegacyCutoverService(connection).record_review_as_operator(
            operator_user_id=operator_user_id,
            environment=environment,
            user_id=args.user_id,
            observed_tier=args.observed_tier,
            classification=LegacyUserClassification(args.classification),
            reason_code=args.reason_code,
            agreement_id=args.agreement_id,
        )

    if args.command == "audit-history":
        if args.commercial_account_id <= 0 or not 1 <= args.limit <= 200:
            raise ValueError("audit account and limit are outside allowed bounds")
        operator = load_named_operator(
            connection, user_id=operator_user_id, environment=environment
        )
        if not operator.roles.intersection(
            {CommercialRole.COMMERCIAL_VIEWER, CommercialRole.COMMERCIAL_ADMIN}
        ):
            raise CommercialError("commercial_role_required")
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT id, event_id, commercial_account_id, agreement_id,
                       actor_type, actor_id, action, target_type, target_id,
                       reason_code, before_json, after_json, request_id, occurred_at
                  FROM commercial_audit_log
                 WHERE commercial_account_id = %s
                   AND (%s IS NULL OR agreement_id = %s)
                   AND (%s IS NULL OR id < %s)
                 ORDER BY id DESC LIMIT %s
                """,
                (
                    args.commercial_account_id,
                    args.agreement_id,
                    args.agreement_id,
                    args.before_audit_id,
                    args.before_audit_id,
                    args.limit,
                ),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        names = (
            "id",
            "event_id",
            "commercial_account_id",
            "agreement_id",
            "actor_type",
            "actor_id",
            "action",
            "target_type",
            "target_id",
            "reason_code",
            "before",
            "after",
            "request_id",
            "occurred_at",
        )
        return [
            {
                key: (
                    {k: v for k, v in value.items() if k != "step_up_event_id"}
                    if key in {"before", "after"} and isinstance(value, dict)
                    else value
                )
                for key, value in zip(names, row, strict=True)
            }
            for row in rows
        ]

    if args.command == "pilot-weekly-report":
        return PilotWeeklyReportService(connection, flags=flags).render_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            week_start=args.week_start,
        )

    if args.command == "preview-manual":
        request = ManualAgreementPreviewRequest.model_validate(_json_input(args.input))
        return ManualAgreementPreviewService(
            connection, flags=flags, clock=lambda: now
        ).preview_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            request=request,
        )

    if args.command == "create-manual-draft":
        command = ManualAgreementDraftCommand.model_validate(_json_input(args.input))
        return ManualAgreementService(
            connection,
            projection_hook=_projection_hook(flags),
            flags=flags,
            clock=lambda: now,
        ).create_draft_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    store = PostgresChangeRequestStore(connection)
    if args.command == "show-change-request":
        request = store.get(args.request_id)
        if request is None or request.environment != environment:
            raise CommercialError("commercial_approval_required")
        operator = load_named_operator(
            connection, user_id=operator_user_id, environment=environment
        )
        if (
            CommercialRole.COMMERCIAL_ADMIN not in operator.roles
            and request.requester_user_id != operator.user_id
        ):
            raise CommercialError("commercial_role_required")
        return _public_change_request(request)

    if args.command == "request-manual-activation":
        if args.expires_in_seconds < 60 or args.expires_in_seconds > 86400:
            raise ValueError("expires-in-seconds must be between 60 and 86400")
        intent = ManualAgreementActivationIntent.model_validate(_json_input(args.input))
        manual_service = ManualAgreementService(
            connection,
            projection_hook=_projection_hook(flags),
            flags=flags,
            clock=lambda: now,
        )
        result = ChangeRequestCommandService(
            connection, manual_agreement_service=manual_service
        ).request_manual_activation(
            operator_user_id=operator_user_id,
            environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            idempotency_key=args.idempotency_key,
            intent=intent,
            expires_in_seconds=args.expires_in_seconds,
            now=now,
        )
        return {
            "activation_intent": intent.model_dump(mode="json"),
            "command_id": str(result.command_id),
            "replayed": result.replayed,
            "request": _public_change_request(result.request),
        }

    if args.command == "approve-manual-activation":
        result = ChangeRequestCommandService(
            connection,
            manual_agreement_service=ManualAgreementService(
                connection,
                projection_hook=_projection_hook(flags),
                flags=flags,
                clock=lambda: now,
            ),
        ).approve_manual_activation(
            operator_user_id=operator_user_id,
            environment=environment,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
            idempotency_key=args.idempotency_key,
            request_id=args.request_id,
            now=now,
        )
        return {
            "command_id": str(result.command_id),
            "replayed": result.replayed,
            "request": _public_change_request(result.request),
        }

    if args.command == "activate-manual":
        intent = ManualAgreementActivationIntent.model_validate(_json_input(args.input))
        command = ManualAgreementActivationCommand(
            **intent.model_dump(mode="python"),
            change_request_id=args.request_id,
            step_up_event_id=_step_up_event_id(args.step_up_event_file),
        )
        return ManualAgreementService(
            connection,
            projection_hook=_projection_hook(flags),
            flags=flags,
            clock=lambda: now,
        ).activate_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=command,
        )

    raise ValueError(f"unsupported command: {args.command}")


def main(
    argv: list[str] | None = None,
    *,
    connection_factory: ConnectionFactory = get_db_session,
    flags: CommercialFlags | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    assertion_public_key: Ed25519PublicKey | None = None,
    observer_connection_factory: ObserverConnectionFactory = (
        get_stripe_repair_observer_connection
    ),
    runtime_env: Mapping[str, str] = os.environ,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command in {
        "describe-manual-billing",
        "describe-manual-pilot",
        "describe-reconciliation",
        "describe-entitlement-override",
    }:
        if args.command == "describe-manual-billing":
            contract = _manual_billing_contract(args.kind)
        elif args.command == "describe-manual-pilot":
            contract = _manual_pilot_contract()
        elif args.command == "describe-reconciliation":
            contract = _reconciliation_contract()
        else:
            contract = _entitlement_override_contract()
        print(_json_output(contract))
        return 0
    try:
        runtime_flags = flags or get_commercial_flags()
        now = clock()
        identity = verify_operator_assertion(
            _protected_file_value(
                args.operator_assertion_file, label="operator assertion"
            ),
            public_key=assertion_public_key or load_operator_assertion_public_key(),
            environment=args.environment,
            now=now,
        )
        with connection_factory() as connection:
            if args.command == "execute-stripe-repair":
                _require_runtime_environment(args.environment, runtime_flags)
                with observer_connection_factory() as observer_connection:
                    result = execute_stripe_repair_workflow(
                        writer=connection,
                        observer=observer_connection,
                        flags=runtime_flags,
                        operator_user_id=identity.subject_user_id,
                        runtime_environment=args.environment,
                        step_up_event_id=_step_up_event_id(args.step_up_event_file),
                        request_id=args.request_id,
                        clock=clock,
                        env=runtime_env,
                    )
            else:
                result = _execute(
                    args,
                    connection=connection,
                    flags=runtime_flags,
                    now=now,
                    operator_user_id=identity.subject_user_id,
                )
                connection.commit()
    except CommercialError as exc:
        print(_json_output({"error": exc.to_public_payload()}), file=sys.stderr)
        return 1
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        print(
            _json_output(
                {"error": {"code": "invalid_operator_command", "message": str(exc)}}
            ),
            file=sys.stderr,
        )
        return 2
    except Exception:
        logger.exception("Commercial operator command failed")
        print(
            _json_output(
                {
                    "error": {
                        "code": "commercial_operator_command_failed",
                        "message": "The commercial operator command failed safely.",
                    }
                }
            ),
            file=sys.stderr,
        )
        return 1
    print(_json_output(result))
    if (
        args.command == "execute-stripe-repair"
        and result.get("workflow_status") == "requires_attention"
    ):
        return 3
    return 0


__all__ = ["main"]
