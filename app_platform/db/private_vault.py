"""Database-boundary checks for private-vault runtime and maintenance operations."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .user_scope import MAX_POSTGRES_INTEGER, USER_ID_SETTING


PRIVATE_VAULT_TABLES = ("user_documents", "user_document_extractions")
PRIVATE_VAULT_POLICIES = {
    "user_documents": "user_documents_owner_policy",
    "user_document_extractions": "user_document_extractions_owner_policy",
}
_EXPECTED_POLICY_EXPRESSION_TOKENS = (
    "user_id",
    "=",
    "nullif",
    "current_setting",
    f"'{USER_ID_SETTING}'",
    ",",
    "true",
    ",",
    "''",
    "::",
    "integer",
)
_POLICY_TOKEN_RE = re.compile(
    r"'(?:''|[^'])*'|::|[A-Za-z_][A-Za-z0-9_.$]*|=|,"
)


class PrivateVaultMaintenanceError(RuntimeError):
    """Raised when a private-vault role, policy, or maintenance boundary is unsafe."""


def _row_value(row: Any, key: str, index: int) -> Any:
    if isinstance(row, Mapping):
        if key not in row:
            raise PrivateVaultMaintenanceError(
                "private-vault role inspection returned an invalid row"
            )
        return row[key]
    try:
        return row[index]
    except (IndexError, KeyError, TypeError) as exc:
        raise PrivateVaultMaintenanceError("private-vault role inspection returned an invalid row") from exc


def _as_bool(value: Any, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "t", "yes", "on", "1"}:
            return True
        if normalized in {"false", "f", "no", "off", "0"}:
            return False
    raise PrivateVaultMaintenanceError(
        f"private-vault role inspection returned invalid {field} state"
    )


def _policy_expression_tokens(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value.strip():
        raise PrivateVaultMaintenanceError(
            "private-vault runtime policy expression is missing"
        )

    tokens: list[str] = []
    cursor = 0
    for match in _POLICY_TOKEN_RE.finditer(value):
        if re.sub(r"[\s()]", "", value[cursor : match.start()]):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime policy expression is unexpected"
            )
        token = match.group(0)
        tokens.append(token if token.startswith("'") else token.lower())
        cursor = match.end()
    if re.sub(r"[\s()]", "", value[cursor:]):
        raise PrivateVaultMaintenanceError(
            "private-vault runtime policy expression is unexpected"
        )

    normalized: list[str] = []
    index = 0
    while index < len(tokens):
        if index + 1 < len(tokens) and tokens[index : index + 2] == ["::", "text"]:
            index += 2
            continue
        normalized.append(tokens[index])
        index += 1
    return tuple(normalized)


def _policy_roles(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized.startswith("{") and normalized.endswith("}"):
            normalized = normalized[1:-1]
        values = [] if not normalized else normalized.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
    else:
        raise PrivateVaultMaintenanceError("private-vault runtime policy roles are invalid")
    return tuple(sorted(str(role).strip().lower() for role in values))


def assert_private_vault_maintenance_connection(conn: Any) -> str:
    """Require the current role to own both private-document metadata tables."""

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT current_user AS current_role,
                   session_user AS session_role,
                   pg_get_userbyid(c.relowner) AS table_owner,
                   c.relname AS table_name,
                   c.relforcerowsecurity AS rls_forced,
                   c.relkind AS relation_kind,
                   pg_is_in_recovery() AS in_recovery,
                   current_setting('transaction_read_only') AS transaction_read_only
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname IN ('user_documents', 'user_document_extractions')
            ORDER BY c.relname
            """
        )
        rows = list(cursor.fetchall())
    finally:
        close = getattr(cursor, "close", None)
        if callable(close):
            close()

    if len(rows) != len(PRIVATE_VAULT_TABLES):
        raise PrivateVaultMaintenanceError(
            "private-vault maintenance requires both metadata tables to exist"
        )
    current_roles = {str(_row_value(row, "current_role", 0)) for row in rows}
    session_roles = {str(_row_value(row, "session_role", 1)) for row in rows}
    table_owners = {str(_row_value(row, "table_owner", 2)) for row in rows}
    table_names = {str(_row_value(row, "table_name", 3)) for row in rows}
    if table_names != set(PRIVATE_VAULT_TABLES):
        raise PrivateVaultMaintenanceError(
            "private-vault maintenance role inspection returned unexpected tables"
        )
    if (
        len(current_roles) != 1
        or current_roles != session_roles
        or len(table_owners) != 1
        or current_roles != table_owners
    ):
        raise PrivateVaultMaintenanceError(
            "private-vault reconciliation requires the direct table-owner connection"
        )
    for row in rows:
        if _as_bool(_row_value(row, "rls_forced", 4), field="forced RLS"):
            raise PrivateVaultMaintenanceError(
                "private-vault reconciliation refuses forced RLS on maintenance owners"
            )
        if str(_row_value(row, "relation_kind", 5)) not in {"r", "p"}:
            raise PrivateVaultMaintenanceError(
                "private-vault maintenance requires ordinary or partitioned tables"
            )
        if _as_bool(_row_value(row, "in_recovery", 6), field="recovery") or _as_bool(
            _row_value(row, "transaction_read_only", 7),
            field="transaction read-only",
        ):
            raise PrivateVaultMaintenanceError(
                "private-vault maintenance connection must target a writable primary"
            )
    return next(iter(current_roles))


def assert_private_vault_runtime_connection(conn: Any) -> str:
    """Require a non-owner runtime role with active private-vault RLS policies."""

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT current_user AS current_role,
                   session_user AS session_role,
                   r.rolsuper AS is_superuser,
                   r.rolbypassrls AS bypasses_rls,
                   pg_get_userbyid(c.relowner) AS table_owner,
                   pg_has_role(
                       current_user,
                       pg_get_userbyid(c.relowner),
                       'MEMBER'
                   ) AS member_of_owner,
                   c.relname AS table_name,
                   c.relrowsecurity AS rls_enabled,
                   c.relforcerowsecurity AS rls_forced,
                   has_schema_privilege(current_user, n.oid, 'USAGE') AS schema_usage,
                   has_schema_privilege(current_user, n.oid, 'CREATE') AS schema_create,
                   has_table_privilege(current_user, c.oid, 'SELECT') AS can_select,
                   has_table_privilege(current_user, c.oid, 'INSERT') AS can_insert,
                   has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete,
                   has_table_privilege(current_user, c.oid, 'UPDATE') AS can_update,
                   has_table_privilege(current_user, c.oid, 'TRUNCATE') AS can_truncate,
                   has_table_privilege(current_user, c.oid, 'REFERENCES') AS can_references,
                   has_table_privilege(current_user, c.oid, 'TRIGGER') AS can_trigger,
                   r.rolcreaterole AS can_create_role,
                   r.rolcreatedb AS can_create_database,
                   r.rolreplication AS can_replicate,
                   r.rolcanlogin AS can_login,
                   EXISTS (
                       SELECT 1
                       FROM pg_roles AS privileged_role
                       WHERE privileged_role.rolname <> current_user
                         AND (
                             privileged_role.rolsuper
                             OR privileged_role.rolbypassrls
                             OR privileged_role.rolcreaterole
                             OR privileged_role.rolcreatedb
                             OR privileged_role.rolreplication
                         )
                         AND pg_has_role(current_user, privileged_role.oid, 'MEMBER')
                   ) AS member_of_privileged_role,
                   EXISTS (
                       SELECT 1
                       FROM pg_auth_members AS runtime_membership
                       WHERE runtime_membership.roleid = r.oid
                   ) AS has_role_members,
                   has_database_privilege(
                       current_user, current_database(), 'CONNECT'
                   ) AS database_connect,
                   has_database_privilege(
                       current_user, current_database(), 'CREATE'
                   ) AS database_create,
                   has_database_privilege(
                       current_user, current_database(), 'TEMP'
                   ) AS database_temp,
                   EXISTS (
                       SELECT 1
                       FROM pg_auth_members AS parent_membership
                       WHERE parent_membership.member = r.oid
                   ) AS has_parent_roles,
                   pg_is_in_recovery() AS in_recovery,
                   current_setting('transaction_read_only') AS transaction_read_only
            FROM pg_roles AS r
            JOIN pg_class AS c ON c.relname IN (
                'user_documents',
                'user_document_extractions'
            )
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE r.rolname = current_user
              AND n.nspname = 'public'
            ORDER BY c.relname
            """
        )
        role_rows = list(cursor.fetchall())
        cursor.execute(
            """
            SELECT tablename AS table_name,
                   policyname AS policy_name,
                   permissive,
                   roles,
                   cmd,
                   qual,
                   with_check
            FROM pg_policies
            WHERE schemaname = 'public'
              AND tablename IN ('user_documents', 'user_document_extractions')
            ORDER BY tablename, policyname
            """
        )
        policy_rows = list(cursor.fetchall())
        cursor.execute(
            """
            SELECT NULLIF(current_setting('app.user_id', true), '') AS scoped_user_id,
                   (SELECT COUNT(*) FROM public.user_documents) AS visible_documents,
                   (SELECT COUNT(*) FROM public.user_document_extractions) AS visible_extractions
            """
        )
        visibility_rows = list(cursor.fetchall())
        cursor.execute(
            """
            SELECT c.relname AS table_name,
                   CASE
                       WHEN expanded_acl.grantee = 0 THEN 'PUBLIC'
                       ELSE grantee_role.rolname
                   END AS grantee,
                   expanded_acl.privilege_type,
                   expanded_acl.is_grantable
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            CROSS JOIN LATERAL aclexplode(
                COALESCE(c.relacl, acldefault('r', c.relowner))
            ) AS expanded_acl
            LEFT JOIN pg_roles AS grantee_role ON grantee_role.oid = expanded_acl.grantee
            WHERE n.nspname = 'public'
              AND c.relname IN ('user_documents', 'user_document_extractions')
            ORDER BY c.relname, grantee, expanded_acl.privilege_type
            """
        )
        acl_rows = list(cursor.fetchall())
        cursor.execute(
            """
            SELECT c.relname AS table_name,
                   attribute.attname AS column_name,
                   CASE
                       WHEN expanded_acl.grantee = 0 THEN 'PUBLIC'
                       ELSE grantee_role.rolname
                   END AS grantee,
                   expanded_acl.privilege_type
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            JOIN pg_attribute AS attribute ON attribute.attrelid = c.oid
            CROSS JOIN LATERAL aclexplode(attribute.attacl) AS expanded_acl
            LEFT JOIN pg_roles AS grantee_role ON grantee_role.oid = expanded_acl.grantee
            WHERE n.nspname = 'public'
              AND c.relname IN ('user_documents', 'user_document_extractions')
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
            ORDER BY c.relname, attribute.attname, grantee, expanded_acl.privilege_type
            """
        )
        column_acl_rows = list(cursor.fetchall())
    finally:
        close = getattr(cursor, "close", None)
        if callable(close):
            close()

    if len(role_rows) != len(PRIVATE_VAULT_TABLES):
        raise PrivateVaultMaintenanceError("private-vault runtime check requires both metadata tables")
    current_roles = {str(_row_value(row, "current_role", 0)) for row in role_rows}
    session_roles = {str(_row_value(row, "session_role", 1)) for row in role_rows}
    table_owners = {str(_row_value(row, "table_owner", 4)) for row in role_rows}
    table_names = {str(_row_value(row, "table_name", 6)) for row in role_rows}
    if (
        len(current_roles) != 1
        or current_roles != session_roles
        or len(table_owners) != 1
        or table_names != set(PRIVATE_VAULT_TABLES)
    ):
        raise PrivateVaultMaintenanceError("private-vault runtime role inspection is inconsistent")
    current_role = next(iter(current_roles))
    table_owner = next(iter(table_owners))
    if current_role == table_owner:
        raise PrivateVaultMaintenanceError("private-vault runtime role must not own metadata tables")
    for row in role_rows:
        if _as_bool(_row_value(row, "is_superuser", 2), field="superuser") or _as_bool(
            _row_value(row, "bypasses_rls", 3), field="BYPASSRLS"
        ):
            raise PrivateVaultMaintenanceError("private-vault runtime role must not bypass RLS")
        if _as_bool(_row_value(row, "member_of_owner", 5), field="owner membership"):
            raise PrivateVaultMaintenanceError("private-vault runtime role must not inherit the owner role")
        if not _as_bool(_row_value(row, "rls_enabled", 7), field="RLS"):
            raise PrivateVaultMaintenanceError("private-vault RLS is not enabled")
        if _as_bool(_row_value(row, "rls_forced", 8), field="forced RLS"):
            raise PrivateVaultMaintenanceError("private-vault RLS must not be forced on maintenance owners")
        if not _as_bool(_row_value(row, "schema_usage", 9), field="schema USAGE"):
            raise PrivateVaultMaintenanceError("private-vault runtime role lacks schema USAGE")
        if _as_bool(_row_value(row, "schema_create", 10), field="schema CREATE"):
            raise PrivateVaultMaintenanceError("private-vault runtime role must not create schema objects")
        for key, index in (("can_select", 11), ("can_insert", 12), ("can_delete", 13)):
            if not _as_bool(_row_value(row, key, index), field=key):
                raise PrivateVaultMaintenanceError(
                    "private-vault runtime role lacks required table privileges"
                )
        for key, index in (
            ("can_update", 14),
            ("can_truncate", 15),
            ("can_references", 16),
            ("can_trigger", 17),
        ):
            if _as_bool(_row_value(row, key, index), field=key):
                raise PrivateVaultMaintenanceError(
                    "private-vault runtime role has excessive table privileges"
                )
        for key, index in (
            ("can_create_role", 18),
            ("can_create_database", 19),
            ("can_replicate", 20),
        ):
            if _as_bool(_row_value(row, key, index), field=key):
                raise PrivateVaultMaintenanceError(
                    "private-vault runtime role must not hold cluster administration privileges"
                )
        if not _as_bool(_row_value(row, "can_login", 21), field="LOGIN"):
            raise PrivateVaultMaintenanceError("private-vault runtime role must be a login role")
        if _as_bool(
            _row_value(row, "member_of_privileged_role", 22),
            field="privileged membership",
        ):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime role must not belong to privileged roles"
            )
        if _as_bool(_row_value(row, "has_role_members", 23), field="role members"):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime role must not grant access through role membership"
            )
        if not _as_bool(_row_value(row, "database_connect", 24), field="database CONNECT"):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime role lacks database CONNECT"
            )
        if _as_bool(_row_value(row, "database_create", 25), field="database CREATE") or _as_bool(
            _row_value(row, "database_temp", 26), field="database TEMPORARY"
        ):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime role has excessive database privileges"
            )
        if _as_bool(_row_value(row, "has_parent_roles", 27), field="parent roles"):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime role must not belong to any parent role"
            )
        if _as_bool(_row_value(row, "in_recovery", 28), field="recovery") or _as_bool(
            _row_value(row, "transaction_read_only", 29),
            field="transaction read-only",
        ):
            raise PrivateVaultMaintenanceError(
                "private-vault runtime connection must target a writable primary"
            )

    policy_keys = [
        (str(_row_value(row, "table_name", 0)), str(_row_value(row, "policy_name", 1)))
        for row in policy_rows
    ]
    if len(policy_keys) != len(PRIVATE_VAULT_POLICIES) or set(policy_keys) != set(
        PRIVATE_VAULT_POLICIES.items()
    ):
        raise PrivateVaultMaintenanceError("private-vault runtime policies are missing or unexpected")
    for row in policy_rows:
        if str(_row_value(row, "permissive", 2)).upper() != "PERMISSIVE":
            raise PrivateVaultMaintenanceError("private-vault runtime policy mode is unexpected")
        if _policy_roles(_row_value(row, "roles", 3)) != ("public",):
            raise PrivateVaultMaintenanceError("private-vault runtime policy roles are unexpected")
        if str(_row_value(row, "cmd", 4)).upper() != "ALL":
            raise PrivateVaultMaintenanceError("private-vault runtime policy command is unexpected")
        if _policy_expression_tokens(_row_value(row, "qual", 5)) != _EXPECTED_POLICY_EXPRESSION_TOKENS:
            raise PrivateVaultMaintenanceError("private-vault runtime USING policy is unexpected")
        if (
            _policy_expression_tokens(_row_value(row, "with_check", 6))
            != _EXPECTED_POLICY_EXPRESSION_TOKENS
        ):
            raise PrivateVaultMaintenanceError("private-vault runtime WITH CHECK policy is unexpected")

    if len(visibility_rows) != 1:
        raise PrivateVaultMaintenanceError("private-vault runtime visibility check is invalid")
    visibility = visibility_rows[0]
    if _row_value(visibility, "scoped_user_id", 0) not in (None, ""):
        raise PrivateVaultMaintenanceError("private-vault runtime connection leaked user scope")
    if int(_row_value(visibility, "visible_documents", 1) or 0) != 0 or int(
        _row_value(visibility, "visible_extractions", 2) or 0
    ) != 0:
        raise PrivateVaultMaintenanceError("private-vault runtime is visible without user scope")

    runtime_acl: dict[str, set[str]] = {table_name: set() for table_name in PRIVATE_VAULT_TABLES}
    for row in acl_rows:
        table_name = str(_row_value(row, "table_name", 0))
        grantee = str(_row_value(row, "grantee", 1))
        privilege = str(_row_value(row, "privilege_type", 2)).upper()
        if table_name not in runtime_acl:
            raise PrivateVaultMaintenanceError(
                "private-vault table ACL inspection returned an unexpected table"
            )
        if grantee == current_role:
            if _as_bool(_row_value(row, "is_grantable", 3), field="table grant option"):
                raise PrivateVaultMaintenanceError(
                    "private-vault runtime table privileges must not be grantable"
                )
            runtime_acl[table_name].add(privilege)
        elif grantee != table_owner:
            raise PrivateVaultMaintenanceError(
                "private-vault tables grant access to an unexpected role"
            )
    expected_runtime_acl = {"SELECT", "INSERT", "DELETE"}
    if any(privileges != expected_runtime_acl for privileges in runtime_acl.values()):
        raise PrivateVaultMaintenanceError(
            "private-vault runtime table ACLs are missing or excessive"
        )
    if column_acl_rows:
        raise PrivateVaultMaintenanceError(
            "private-vault tables contain unexpected column-level privileges"
        )
    return current_role


def _rollback_required(conn: Any, *, purpose: str) -> None:
    rollback = getattr(conn, "rollback", None)
    if not callable(rollback):
        raise PrivateVaultMaintenanceError(
            f"private-vault {purpose} connection must support rollback"
        )
    try:
        rollback()
    except Exception as exc:
        raise PrivateVaultMaintenanceError(
            f"private-vault {purpose} connection rollback failed"
        ) from exc


def _fetchone_value(row: Any, key: str, index: int) -> Any:
    if row is None:
        raise PrivateVaultMaintenanceError("private-vault readiness probe returned no row")
    return _row_value(row, key, index)


def _database_identity(conn: Any, *, purpose: str) -> tuple[str, str, str]:
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT current_database() AS database_name,
                   control.system_identifier::text AS system_identifier,
                   EXTRACT(EPOCH FROM pg_postmaster_start_time())::text
                       AS postmaster_started_epoch,
                   pg_is_in_recovery() AS in_recovery,
                   current_setting('transaction_read_only') AS transaction_read_only
            FROM pg_control_system() AS control
            """
        )
        row = cursor.fetchone()
    finally:
        close = getattr(cursor, "close", None)
        if callable(close):
            close()
    if row is None:
        raise PrivateVaultMaintenanceError(
            f"private-vault {purpose} database identity returned no row"
        )
    database_name = str(_row_value(row, "database_name", 0) or "").strip()
    system_identifier = str(_row_value(row, "system_identifier", 1) or "").strip()
    postmaster_started_epoch = str(
        _row_value(row, "postmaster_started_epoch", 2) or ""
    ).strip()
    if not database_name or not system_identifier or not postmaster_started_epoch:
        raise PrivateVaultMaintenanceError(
            f"private-vault {purpose} database identity is incomplete"
        )
    if _as_bool(_row_value(row, "in_recovery", 3), field="recovery") or _as_bool(
        _row_value(row, "transaction_read_only", 4),
        field="transaction read-only",
    ):
        raise PrivateVaultMaintenanceError(
            f"private-vault {purpose} connection must target a writable primary"
        )
    return database_name, system_identifier, postmaster_started_epoch


def verify_private_vault_connections(runtime_conn: Any, maintenance_conn: Any) -> dict[str, Any]:
    """Verify the split runtime/maintenance boundary without mutating durable data."""

    if bool(getattr(runtime_conn, "autocommit", False)):
        raise PrivateVaultMaintenanceError(
            "private-vault runtime verification requires autocommit disabled"
        )
    if bool(getattr(maintenance_conn, "autocommit", False)):
        raise PrivateVaultMaintenanceError(
            "private-vault maintenance verification requires autocommit disabled"
        )

    try:
        runtime_role = assert_private_vault_runtime_connection(runtime_conn)
    finally:
        _rollback_required(runtime_conn, purpose="runtime")
    try:
        maintenance_role = assert_private_vault_maintenance_connection(maintenance_conn)
    finally:
        _rollback_required(maintenance_conn, purpose="maintenance")
    if runtime_role == maintenance_role:
        raise PrivateVaultMaintenanceError(
            "private-vault runtime and maintenance credentials resolve to the same role"
        )

    try:
        runtime_database_identity = _database_identity(runtime_conn, purpose="runtime")
    finally:
        _rollback_required(runtime_conn, purpose="runtime")
    try:
        maintenance_database_identity = _database_identity(
            maintenance_conn,
            purpose="maintenance",
        )
    finally:
        _rollback_required(maintenance_conn, purpose="maintenance")
    if runtime_database_identity != maintenance_database_identity:
        raise PrivateVaultMaintenanceError(
            "private-vault credentials target different database instances"
        )

    runtime_cursor = runtime_conn.cursor()
    try:
        runtime_cursor.execute(
            "SELECT set_config(%s, %s, true) AS scoped_user_id",
            (USER_ID_SETTING, str(MAX_POSTGRES_INTEGER)),
        )
        bound_scope = _fetchone_value(runtime_cursor.fetchone(), "scoped_user_id", 0)
        if str(bound_scope) != str(MAX_POSTGRES_INTEGER):
            raise PrivateVaultMaintenanceError(
                "private-vault transaction-local user scope could not be established"
            )
    finally:
        close = getattr(runtime_cursor, "close", None)
        if callable(close):
            close()
        _rollback_required(runtime_conn, purpose="runtime")

    runtime_cursor = runtime_conn.cursor()
    try:
        runtime_cursor.execute(
            "SELECT NULLIF(current_setting('app.user_id', true), '') AS scoped_user_id"
        )
        cleared_scope = _fetchone_value(runtime_cursor.fetchone(), "scoped_user_id", 0)
        if cleared_scope is not None:
            raise PrivateVaultMaintenanceError(
                "private-vault transaction-local user scope survived rollback"
            )
    finally:
        close = getattr(runtime_cursor, "close", None)
        if callable(close):
            close()
        _rollback_required(runtime_conn, purpose="runtime")

    maintenance_cursor = maintenance_conn.cursor()
    try:
        maintenance_cursor.execute("SET LOCAL row_security = off")
        maintenance_cursor.execute(
            """
            SELECT (SELECT COUNT(*) FROM public.user_documents) AS documents,
                   (SELECT COUNT(*) FROM public.user_document_extractions) AS extractions
            """
        )
        count_row = maintenance_cursor.fetchone()
        document_count = int(_fetchone_value(count_row, "documents", 0))
        extraction_count = int(_fetchone_value(count_row, "extractions", 1))
    finally:
        close = getattr(maintenance_cursor, "close", None)
        if callable(close):
            close()
        _rollback_required(maintenance_conn, purpose="maintenance")

    return {
        "status": "PASS",
        "runtime_role": runtime_role,
        "maintenance_role": maintenance_role,
        "roles_are_distinct": True,
        "database_name": runtime_database_identity[0],
        "database_identity_match": True,
        "writable_primary": True,
        "runtime_unset_scope_isolated": True,
        "transaction_scope_cleared": True,
        "maintenance_row_counts": {
            "user_documents": document_count,
            "user_document_extractions": extraction_count,
        },
        "tables": list(PRIVATE_VAULT_TABLES),
        "policies": dict(PRIVATE_VAULT_POLICIES),
    }


__all__ = [
    "PRIVATE_VAULT_TABLES",
    "PRIVATE_VAULT_POLICIES",
    "PrivateVaultMaintenanceError",
    "assert_private_vault_maintenance_connection",
    "assert_private_vault_runtime_connection",
    "verify_private_vault_connections",
]
