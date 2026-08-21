"""Fail-closed MCP exposure manifest loading and static tool discovery."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Literal

from pydantic import Field, StrictStr, field_validator, model_validator

from .models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256


MCP_EXPOSURE_SCHEMA_VERSION = 1
CURRENT_MCP_EXPOSURE_MANIFEST_VERSION = "mcp-exposure-2026-07-12-v1"
DEFAULT_MCP_EXPOSURE_MANIFEST_PATH = (
    Path(__file__).resolve().parents[2] / "config/mcp_exposure_manifest.json"
)
KNOWN_MCP_SCOPE_KEYS = frozenset(
    {
        "scope:premium",
        "scope:read",
        "scope:trade-execute",
        "scope:trade-preview",
    }
)
_MAX_MANIFEST_BYTES = 2_000_000
_TOOL_KEY = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9_]*$")
_IGNORED_MCP_SERVER_PARTS = frozenset(
    {
        ".git",
        ".claude",
        ".codex",
        ".context",
        ".gemini",
        ".venv",
        "venv",
        "node_modules",
        "site-packages",
        "tests",
        "evals",
        "build",
        "dist",
    }
)


@dataclass(frozen=True, slots=True)
class McpServerInventoryEntry:
    server_name: str
    entrypoint: str
    server_variable: str


APPROVED_MCP_SERVER_INVENTORY = (
    McpServerInventoryEntry("fmp-mcp", "fmp/server.py", "mcp"),
    McpServerInventoryEntry("hank-mcp", "mcp_server_connector.py", "mcp_connector"),
    McpServerInventoryEntry("ibkr-mcp", "ibkr/server.py", "mcp"),
    McpServerInventoryEntry(
        "portfolio-trades-mcp", "mcp_server_trades.py", "mcp_trades"
    ),
    McpServerInventoryEntry(
        "portfolio-config-mcp", "mcp_server_config.py", "mcp_config"
    ),
    McpServerInventoryEntry(
        "portfolio-producers-mcp", "mcp_server_producers.py", "mcp_producers"
    ),
    McpServerInventoryEntry(
        "portfolio-writes-mcp", "mcp_server_writes.py", "mcp_writes"
    ),
    McpServerInventoryEntry(
        "portfolio-reads-mcp", "mcp_server_reads.py", "mcp_reads"
    ),
    McpServerInventoryEntry(
        "research-mcp", "mcp_server_research.py", "mcp_research"
    ),
)

HANK_CONNECTOR_COST_CLASS_BY_TOOL = {
    "compare_scenarios": "compute-heavy",
    "filings_read": "compute-light",
    "filings_search": "compute-light",
    "filings_source_excerpt": "compute-light",
    "get_action_history": "compute-light",
    "get_connector_context": "none",
    "get_diligence_state": "compute-light",
    "get_factor_analysis": "compute-heavy",
    "get_handoff_summary": "compute-light",
    "get_income_projection": "provider-light",
    "get_performance": "provider-light",
    "get_portfolio_events_calendar": "provider-heavy",
    "get_portfolio_news": "provider-heavy",
    "get_positions": "provider-light",
    "get_research_brief": "compute-light",
    "get_risk_analysis": "compute-heavy",
    "get_risk_score": "compute-heavy",
    "list_accounts": "provider-light",
    "list_available_tools": "none",
    "list_connections": "provider-light",
    "list_portfolios": "provider-light",
    "list_research_files": "compute-light",
    "read_research_thread": "compute-light",
    "run_monte_carlo": "compute-heavy",
    "run_stress_test": "compute-heavy",
    "run_whatif": "compute-heavy",
    "thesis_latest_scorecard": "compute-light",
    "thesis_read": "compute-light",
    "transcripts_read": "compute-light",
    "transcripts_search": "compute-light",
    "transcripts_source_excerpt": "compute-light",
}


class McpExposureManifestError(RuntimeError):
    """Manifest loading or authority validation failed closed."""


class McpToolExposure(StrictCommercialModel):
    exposure: Literal[
        "internal-only",
        "internal-only:excel-addin-only",
        "hosted-public",
    ]
    required_scopes: tuple[StableCode, ...]
    availability: Literal["internal", "v1", "future"]
    cost_class: Literal[
        "none",
        "compute-light",
        "compute-heavy",
        "provider-light",
        "provider-heavy",
        "model-heavy",
    ]
    safety_class: Literal[
        "read",
        "pure_transform",
        "artifact_write",
        "state_write",
        "external_write",
        "portfolio_config",
        "irreversible",
    ]

    @field_validator("required_scopes")
    @classmethod
    def _canonical_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("MCP exposure scopes must be sorted and unique")
        unknown = set(value) - KNOWN_MCP_SCOPE_KEYS
        if unknown:
            raise ValueError(f"unknown MCP exposure scopes: {sorted(unknown)}")
        return value

    @model_validator(mode="after")
    def _public_shape(self) -> "McpToolExposure":
        if self.exposure == "hosted-public":
            if not self.required_scopes:
                raise ValueError("hosted-public MCP tools require at least one scope")
            if self.availability == "internal":
                raise ValueError("hosted-public MCP tools cannot be internal-only")
        elif self.availability != "internal":
            raise ValueError("non-public MCP tools must use internal availability")
        return self


class McpExposureManifest(StrictCommercialModel):
    schema_version: Literal[1]
    manifest_version: StableCode
    content_sha256: Sha256Digest
    tools: dict[StrictStr, McpToolExposure] = Field(min_length=1)

    @field_validator("tools")
    @classmethod
    def _canonical_tool_keys(
        cls, value: dict[str, McpToolExposure]
    ) -> dict[str, McpToolExposure]:
        keys = tuple(value)
        if keys != tuple(sorted(keys)):
            raise ValueError("MCP exposure tool keys must be sorted")
        invalid = [key for key in keys if _TOOL_KEY.fullmatch(key) is None]
        if invalid:
            raise ValueError(f"invalid MCP exposure tool keys: {invalid}")
        return value

    def content_body(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"content_sha256"})


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise McpExposureManifestError(
                "MCP exposure manifest contains duplicate JSON keys"
            )
        value[key] = item
    return value


def _read_manifest_payload(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise McpExposureManifestError("MCP exposure manifest is unavailable") from exc
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise McpExposureManifestError("MCP exposure manifest size is invalid")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_object_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise McpExposureManifestError("MCP exposure manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise McpExposureManifestError("MCP exposure manifest root must be an object")
    return payload


def load_mcp_exposure_manifest(
    path: str | Path = DEFAULT_MCP_EXPOSURE_MANIFEST_PATH,
    *,
    expected_manifest_version: str = CURRENT_MCP_EXPOSURE_MANIFEST_VERSION,
    discovered_tools: tuple[str, ...] | None = None,
) -> McpExposureManifest:
    """Load exact signed-by-digest policy or fail closed with no fallback."""

    payload = _read_manifest_payload(Path(path))
    try:
        manifest = McpExposureManifest.model_validate(payload)
    except ValueError as exc:
        raise McpExposureManifestError("MCP exposure manifest contract is invalid") from exc
    expected_digest = canonical_sha256(manifest.content_body())
    if manifest.content_sha256 != expected_digest:
        raise McpExposureManifestError("MCP exposure manifest digest does not match")
    if manifest.manifest_version != expected_manifest_version:
        raise McpExposureManifestError("MCP exposure manifest version does not match")
    if discovered_tools is not None:
        validate_manifest_tool_coverage(manifest, discovered_tools)
    return manifest


def validate_manifest_tool_coverage(
    manifest: McpExposureManifest, discovered_tools: tuple[str, ...]
) -> None:
    if discovered_tools != tuple(sorted(set(discovered_tools))):
        raise McpExposureManifestError(
            "discovered MCP tool inventory is duplicated or unsorted"
        )
    manifest_tools = set(manifest.tools)
    discovered = set(discovered_tools)
    missing = sorted(discovered - manifest_tools)
    extra = sorted(manifest_tools - discovered)
    if missing or extra:
        raise McpExposureManifestError(
            f"MCP exposure coverage mismatch missing={missing} extra={extra}"
        )


def _is_tool_attribute(node: ast.AST, server_aliases: frozenset[str]) -> bool:
    return bool(
        isinstance(node, ast.Attribute)
        and node.attr == "tool"
        and isinstance(node.value, ast.Name)
        and node.value.id in server_aliases
    )


def _explicit_tool_name(tool_call: ast.Call) -> str | None:
    positional = (
        tool_call.args[0].value
        if tool_call.args
        and isinstance(tool_call.args[0], ast.Constant)
        and isinstance(tool_call.args[0].value, str)
        else None
    )
    keyword_name = None
    for keyword in tool_call.keywords:
        if keyword.arg is None:
            raise McpExposureManifestError(
                "MCP tool keyword unpacking is not statically discoverable"
            )
        if keyword.arg != "name":
            continue
        if not (
            isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            raise McpExposureManifestError(
                "MCP tool name is not statically discoverable"
            )
        keyword_name = keyword.value.value
    if positional is not None and keyword_name is not None:
        raise McpExposureManifestError("MCP tool name is declared twice")
    return positional or keyword_name


def _registered_callable_name(
    node: ast.AST | None,
    callable_bindings: dict[str, str | None],
) -> str:
    if isinstance(node, ast.Name):
        resolved = callable_bindings.get(node.id)
        if resolved is not None:
            return resolved
    raise McpExposureManifestError("MCP tool registration is not statically discoverable")


def _update_callable_bindings(
    statement: ast.stmt,
    callable_bindings: dict[str, str | None],
) -> None:
    """Apply unambiguous module-level name binding in execution order."""

    if isinstance(statement, ast.ImportFrom):
        for alias in statement.names:
            if alias.name != "*":
                callable_bindings[alias.asname or alias.name] = alias.name
        return
    if isinstance(statement, ast.Import):
        for alias in statement.names:
            callable_bindings[alias.asname or alias.name.split(".", 1)[0]] = None
        return
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        callable_bindings[statement.name] = statement.name
        return
    if isinstance(statement, ast.ClassDef):
        callable_bindings[statement.name] = None
        return
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return
    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    value = statement.value
    resolved = (
        callable_bindings.get(value.id)
        if isinstance(value, ast.Name)
        else None
    )
    for target in targets:
        if isinstance(target, ast.Name):
            callable_bindings[target.id] = resolved


def _update_server_bindings(
    statement: ast.stmt,
    server_bindings: dict[str, bool],
    *,
    server_variable: str,
    server_variable_initialized: bool,
) -> bool:
    """Track the approved server object at each module-level statement."""

    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        for alias in statement.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            server_bindings[local_name] = False
        return server_variable_initialized
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        server_bindings[statement.name] = False
        return server_variable_initialized
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return server_variable_initialized
    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    value = statement.value
    resolved = bool(
        isinstance(value, ast.Name) and server_bindings.get(value.id, False)
    )
    for target in targets:
        if not isinstance(target, ast.Name):
            continue
        if target.id == server_variable and not server_variable_initialized:
            server_bindings[target.id] = True
            server_variable_initialized = True
        else:
            server_bindings[target.id] = resolved
    return server_variable_initialized


def discover_server_mcp_tools(
    path: Path, *, server_name: str, server_variable: str
) -> tuple[str, ...]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise McpExposureManifestError(
            f"approved MCP server cannot be discovered: {server_name}"
        ) from exc
    callable_bindings: dict[str, str | None] = {}
    server_bindings: dict[str, bool] = {}
    server_variable_initialized = False
    tool_calls = {
        id(node): node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "tool"
    }
    tool_attributes = {
        id(node): node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "tool"
    }
    recognized_calls: set[int] = set()
    recognized_attributes: set[int] = set()
    names: list[str] = []
    for node in tree.body:
        server_aliases = frozenset(
            name for name, approved in server_bindings.items() if approved
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if _is_tool_attribute(decorator, server_aliases):
                    names.append(node.name)
                    recognized_attributes.add(id(decorator))
                elif isinstance(decorator, ast.Call) and _is_tool_attribute(
                    decorator.func, server_aliases
                ):
                    if decorator.args and not (
                        isinstance(decorator.args[0], ast.Constant)
                        and isinstance(decorator.args[0].value, str)
                    ):
                        raise McpExposureManifestError(
                            "decorated MCP tool registration is ambiguous"
                        )
                    names.append(_explicit_tool_name(decorator) or node.name)
                    recognized_calls.add(id(decorator))
                    recognized_attributes.add(id(decorator.func))
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            registration = node.value
            if _is_tool_attribute(registration.func, server_aliases):
                if not registration.args or isinstance(
                    registration.args[0], ast.Constant
                ):
                    raise McpExposureManifestError(
                        "direct MCP tool registration lacks a static callable"
                    )
                names.append(
                    _explicit_tool_name(registration)
                    or _registered_callable_name(
                        registration.args[0], callable_bindings
                    )
                )
                recognized_calls.add(id(registration))
                recognized_attributes.add(id(registration.func))
            elif isinstance(registration.func, ast.Call) and _is_tool_attribute(
                registration.func.func, server_aliases
            ):
                factory = registration.func
                if factory.args and not (
                    isinstance(factory.args[0], ast.Constant)
                    and isinstance(factory.args[0].value, str)
                ):
                    raise McpExposureManifestError(
                        "MCP tool factory registration is ambiguous"
                    )
                if len(registration.args) != 1:
                    raise McpExposureManifestError(
                        "MCP tool registration is not statically discoverable"
                    )
                names.append(
                    _explicit_tool_name(factory)
                    or _registered_callable_name(
                        registration.args[0],
                        callable_bindings,
                    )
                )
                recognized_calls.add(id(factory))
                recognized_attributes.add(id(factory.func))
        _update_callable_bindings(node, callable_bindings)
        server_variable_initialized = _update_server_bindings(
            node,
            server_bindings,
            server_variable=server_variable,
            server_variable_initialized=server_variable_initialized,
        )
    if (
        set(tool_calls) != recognized_calls
        or set(tool_attributes) != recognized_attributes
    ):
        if any(
            isinstance(attribute.value, ast.Name)
            and attribute.value.id != server_variable
            for attribute_id, attribute in tool_attributes.items()
            if attribute_id not in recognized_attributes
        ):
            raise McpExposureManifestError(
                f"unapproved MCP server alias in {server_name}"
            )
        raise McpExposureManifestError(
            f"MCP tool registration is not statically discoverable: {server_name}"
        )
    if len(names) != len(set(names)):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        raise McpExposureManifestError(
            f"duplicate MCP tools on {server_name}: {duplicates}"
        )
    return tuple(sorted(f"{server_name}:{name}" for name in names))


def discover_approved_mcp_tools(root: str | Path) -> tuple[str, ...]:
    repo_root = Path(root)
    validate_approved_mcp_server_inventory(repo_root)
    tools = tuple(
        tool
        for server in APPROVED_MCP_SERVER_INVENTORY
        for tool in discover_server_mcp_tools(
            repo_root / server.entrypoint,
            server_name=server.server_name,
            server_variable=server.server_variable,
        )
    )
    if len(tools) != len(set(tools)):
        raise McpExposureManifestError("approved MCP inventory contains duplicate tools")
    return tuple(sorted(tools))


def validate_approved_mcp_server_inventory(root: str | Path) -> None:
    repo_root = Path(root)
    approved = {server.entrypoint for server in APPROVED_MCP_SERVER_INVENTORY}
    discovered: set[str] = set()
    for path in repo_root.rglob("*.py"):
        relative = path.relative_to(repo_root)
        if set(relative.parts) & _IGNORED_MCP_SERVER_PARTS:
            continue
        candidate_name = (
            path.name == "server.py"
            or path.name == "mcp_server.py"
            or path.name == "x_mcp_server.py"
            or path.name.startswith("mcp_server_")
            or "mcp_servers" in relative.parts
        )
        if not candidate_name:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise McpExposureManifestError(
                "MCP server inventory cannot be read"
            ) from exc
        # Candidate filenames are deliberately narrow. Within that boundary, every
        # `.tool` registration is inventory-relevant regardless of constructor/import
        # aliases, so a new SDK form cannot silently evade manifest review.
        has_tools = any(
            isinstance(node, ast.Attribute) and node.attr == "tool"
            for node in ast.walk(tree)
        )
        if has_tools:
            discovered.add(str(path.relative_to(repo_root)))
    if discovered != approved:
        raise McpExposureManifestError(
            "MCP server inventory mismatch "
            f"missing={sorted(approved - discovered)} "
            f"unapproved={sorted(discovered - approved)}"
        )


def initial_exposure_for_tool(tool_key: str) -> McpToolExposure:
    """Reflect the existing read-only connector and deny every split server."""

    server_name, tool_name = tool_key.split(":", 1)
    if server_name == "hank-mcp":
        try:
            cost_class = HANK_CONNECTOR_COST_CLASS_BY_TOOL[tool_name]
        except KeyError as exc:
            raise McpExposureManifestError(
                f"hosted connector tool lacks reviewed cost class: {tool_name}"
            ) from exc
        return McpToolExposure(
            exposure="hosted-public",
            required_scopes=("scope:read",),
            availability="v1",
            cost_class=cost_class,
            safety_class="read",
        )
    if server_name == "fmp-mcp":
        scopes, cost_class, safety_class = (
            ("scope:read",),
            "provider-heavy",
            "read",
        )
    elif server_name == "ibkr-mcp":
        scopes, cost_class, safety_class = (
            ("scope:read",),
            "provider-light",
            "read",
        )
    elif server_name == "portfolio-trades-mcp":
        scopes, cost_class, safety_class = (
            ("scope:trade-execute",),
            "provider-light",
            "irreversible",
        )
    elif server_name == "portfolio-config-mcp":
        scopes, cost_class, safety_class = (
            ("scope:premium",),
            "provider-light",
            "portfolio_config",
        )
    elif server_name == "portfolio-producers-mcp":
        scopes, cost_class, safety_class = (
            ("scope:premium",),
            "model-heavy",
            (
                "state_write"
                if tool_name == "record_model_acceptance_decision"
                else "artifact_write"
            ),
        )
    elif server_name == "portfolio-writes-mcp":
        scopes, cost_class, safety_class = (
            ("scope:premium",),
            "compute-light",
            "state_write",
        )
    else:
        scopes = (
            ("scope:trade-preview",)
            if tool_name.startswith("preview_")
            else ("scope:read",)
        )
        cost_class, safety_class = "provider-light", "read"
    return McpToolExposure(
        exposure="internal-only",
        required_scopes=scopes,
        availability="internal",
        cost_class=cost_class,
        safety_class=safety_class,
    )


def build_initial_mcp_exposure_payload(
    root: str | Path, *, manifest_version: str
) -> dict[str, object]:
    tools = {
        key: initial_exposure_for_tool(key).model_dump(mode="json")
        for key in discover_approved_mcp_tools(root)
    }
    body: dict[str, object] = {
        "schema_version": MCP_EXPOSURE_SCHEMA_VERSION,
        "manifest_version": manifest_version,
        "tools": tools,
    }
    return {
        "schema_version": MCP_EXPOSURE_SCHEMA_VERSION,
        "manifest_version": manifest_version,
        "content_sha256": canonical_sha256(body),
        "tools": tools,
    }


__all__ = [
    "APPROVED_MCP_SERVER_INVENTORY",
    "CURRENT_MCP_EXPOSURE_MANIFEST_VERSION",
    "DEFAULT_MCP_EXPOSURE_MANIFEST_PATH",
    "HANK_CONNECTOR_COST_CLASS_BY_TOOL",
    "KNOWN_MCP_SCOPE_KEYS",
    "MCP_EXPOSURE_SCHEMA_VERSION",
    "McpExposureManifest",
    "McpExposureManifestError",
    "McpServerInventoryEntry",
    "McpToolExposure",
    "build_initial_mcp_exposure_payload",
    "discover_approved_mcp_tools",
    "discover_server_mcp_tools",
    "initial_exposure_for_tool",
    "load_mcp_exposure_manifest",
    "validate_approved_mcp_server_inventory",
    "validate_manifest_tool_coverage",
]
