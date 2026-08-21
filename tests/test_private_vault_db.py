from __future__ import annotations

import pytest

from app_platform.db.private_vault import (
    PRIVATE_VAULT_POLICIES,
    PRIVATE_VAULT_TABLES,
    PrivateVaultMaintenanceError,
    assert_private_vault_maintenance_connection,
    assert_private_vault_runtime_connection,
    verify_private_vault_connections,
)


class _Cursor:
    def __init__(self, result_sets) -> None:
        self.result_sets = list(result_sets)
        self.rows = []
        self.sql = ""
        self.closed = False

    def execute(self, sql: str, params=None) -> None:
        self.sql = " ".join(sql.split())
        if self.sql == "SET LOCAL row_security = off":
            self.rows = []
            return
        self.rows = self.result_sets.pop(0)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, *result_sets) -> None:
        self.autocommit = False
        self.rollbacks = 0
        self.cursor_instance = _Cursor(result_sets)

    def cursor(self) -> _Cursor:
        return self.cursor_instance

    def rollback(self) -> None:
        self.rollbacks += 1


def _role_rows(*, current_role: str, owner: str):
    return [
        {
            "current_role": current_role,
            "session_role": current_role,
            "table_owner": owner,
            "table_name": table_name,
            "rls_forced": False,
            "relation_kind": "r",
            "in_recovery": False,
            "transaction_read_only": "off",
        }
        for table_name in sorted(PRIVATE_VAULT_TABLES)
    ]


def test_private_vault_maintenance_accepts_shared_table_owner() -> None:
    conn = _Connection(_role_rows(current_role="risk_module_owner", owner="risk_module_owner"))

    assert assert_private_vault_maintenance_connection(conn) == "risk_module_owner"
    assert "FROM pg_class AS c" in conn.cursor_instance.sql
    assert conn.cursor_instance.closed is True


def test_private_vault_maintenance_rejects_non_owner_runtime_role() -> None:
    conn = _Connection(_role_rows(current_role="risk_module_runtime", owner="risk_module_owner"))

    with pytest.raises(PrivateVaultMaintenanceError, match="direct table-owner"):
        assert_private_vault_maintenance_connection(conn)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"rls_forced": True}, "forced RLS"),
        ({"relation_kind": "v"}, "ordinary or partitioned"),
        ({"in_recovery": True}, "writable primary"),
        ({"transaction_read_only": "on"}, "writable primary"),
    ],
)
def test_private_vault_maintenance_rejects_unsafe_relation_state(overrides, message) -> None:
    rows = _role_rows(current_role="risk_module_owner", owner="risk_module_owner")
    rows[0].update(overrides)

    with pytest.raises(PrivateVaultMaintenanceError, match=message):
        assert_private_vault_maintenance_connection(_Connection(rows))


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [
            {
                "current_role": "owner",
                "table_owner": "owner",
                "table_name": "user_documents",
                "rls_forced": False,
                "relation_kind": "r",
            }
        ],
        _role_rows(current_role="owner", owner="owner")[:-1]
        + [
            {
                **_role_rows(current_role="owner", owner="owner")[0],
                "table_name": "other_table",
            }
        ],
    ],
)
def test_private_vault_maintenance_rejects_missing_or_unexpected_tables(rows) -> None:
    with pytest.raises(PrivateVaultMaintenanceError, match="tables"):
        assert_private_vault_maintenance_connection(_Connection(rows))


def _runtime_rows(**overrides):
    base = {
        "current_role": "risk_module_runtime",
        "session_role": "risk_module_runtime",
        "is_superuser": False,
        "bypasses_rls": False,
        "table_owner": "risk_module_owner",
        "member_of_owner": False,
        "rls_enabled": True,
        "rls_forced": False,
        "schema_usage": True,
        "schema_create": False,
        "can_select": True,
        "can_insert": True,
        "can_delete": True,
        "can_update": False,
        "can_truncate": False,
        "can_references": False,
        "can_trigger": False,
        "can_create_role": False,
        "can_create_database": False,
        "can_replicate": False,
        "can_login": True,
        "member_of_privileged_role": False,
        "has_role_members": False,
        "database_connect": True,
        "database_create": False,
        "database_temp": False,
        "has_parent_roles": False,
        "in_recovery": False,
        "transaction_read_only": "off",
    }
    base.update(overrides)
    return [
        {**base, "table_name": table_name}
        for table_name in sorted(PRIVATE_VAULT_TABLES)
    ]


def _policy_rows():
    return [
        {
            "table_name": table_name,
            "policy_name": policy_name,
            "permissive": "PERMISSIVE",
            "roles": ["public"],
            "cmd": "ALL",
            "qual": "(user_id = NULLIF(current_setting('app.user_id'::text, true), ''::text)::integer)",
            "with_check": "(user_id = NULLIF(current_setting('app.user_id'::text, true), ''::text)::integer)",
        }
        for table_name, policy_name in sorted(PRIVATE_VAULT_POLICIES.items())
    ]


def _visibility_rows(**overrides):
    row = {"scoped_user_id": None, "visible_documents": 0, "visible_extractions": 0}
    row.update(overrides)
    return [row]


def _acl_rows(*, runtime_role: str = "risk_module_runtime", owner: str = "risk_module_owner"):
    rows = []
    for table_name in sorted(PRIVATE_VAULT_TABLES):
        rows.extend(
            {
                "table_name": table_name,
                "grantee": runtime_role,
                "privilege_type": privilege,
                "is_grantable": False,
            }
            for privilege in ("SELECT", "INSERT", "DELETE")
        )
        rows.append({"table_name": table_name, "grantee": owner, "privilege_type": "SELECT"})
    return rows


def _database_identity_rows(**overrides):
    row = {
        "database_name": "risk_module_db",
        "system_identifier": "7527111209630638799",
        "postmaster_started_epoch": "1784071549.123456",
        "in_recovery": False,
        "transaction_read_only": "off",
    }
    row.update(overrides)
    return [row]


def test_private_vault_runtime_accepts_non_owner_with_exact_policies() -> None:
    conn = _Connection(_runtime_rows(), _policy_rows(), _visibility_rows(), _acl_rows(), [])

    assert assert_private_vault_runtime_connection(conn) == "risk_module_runtime"
    assert conn.cursor_instance.closed is True


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"current_role": "risk_module_owner", "session_role": "risk_module_owner"},
            "must not own",
        ),
        ({"is_superuser": True}, "must not bypass"),
        ({"bypasses_rls": True}, "must not bypass"),
        ({"member_of_owner": True}, "must not inherit"),
        ({"session_role": "risk_module_owner"}, "inconsistent"),
        ({"rls_enabled": False}, "not enabled"),
        ({"rls_forced": True}, "must not be forced"),
    ],
)
def test_private_vault_runtime_rejects_privileged_or_unprotected_roles(overrides, message) -> None:
    with pytest.raises(PrivateVaultMaintenanceError, match=message):
        assert_private_vault_runtime_connection(
            _Connection(
                _runtime_rows(**overrides),
                _policy_rows(),
                _visibility_rows(),
                _acl_rows(),
                [],
            )
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_usage": False}, "lacks schema USAGE"),
        ({"schema_create": True}, "must not create"),
        ({"can_select": False}, "lacks required"),
        ({"can_insert": False}, "lacks required"),
        ({"can_delete": False}, "lacks required"),
        ({"can_update": True}, "excessive"),
        ({"can_truncate": True}, "excessive"),
        ({"can_references": True}, "excessive"),
        ({"can_trigger": True}, "excessive"),
        ({"can_create_role": True}, "cluster administration"),
        ({"can_create_database": True}, "cluster administration"),
        ({"can_replicate": True}, "cluster administration"),
        ({"can_login": False}, "login role"),
        ({"member_of_privileged_role": True}, "privileged roles"),
        ({"has_role_members": True}, "role membership"),
        ({"database_connect": False}, "lacks database CONNECT"),
        ({"database_create": True}, "excessive database privileges"),
        ({"database_temp": True}, "excessive database privileges"),
        ({"has_parent_roles": True}, "any parent role"),
        ({"in_recovery": True}, "writable primary"),
        ({"transaction_read_only": "on"}, "writable primary"),
    ],
)
def test_private_vault_runtime_rejects_missing_or_excessive_privileges(overrides, message) -> None:
    with pytest.raises(PrivateVaultMaintenanceError, match=message):
        assert_private_vault_runtime_connection(
            _Connection(
                _runtime_rows(**overrides),
                _policy_rows(),
                _visibility_rows(),
                _acl_rows(),
                [],
            )
        )


def test_private_vault_runtime_rejects_policy_drift() -> None:
    with pytest.raises(PrivateVaultMaintenanceError, match="policies"):
        assert_private_vault_runtime_connection(
            _Connection(_runtime_rows(), [], _visibility_rows(), _acl_rows(), [])
        )

    unexpected = _policy_rows() + [
        {"table_name": "user_documents", "policy_name": "unexpected_policy"}
    ]
    with pytest.raises(PrivateVaultMaintenanceError, match="policies"):
        assert_private_vault_runtime_connection(
            _Connection(_runtime_rows(), unexpected, _visibility_rows(), _acl_rows(), [])
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("qual", "true", "USING"),
        ("with_check", "true", "WITH CHECK"),
        ("roles", ["risk_module_runtime"], "roles"),
        ("cmd", "SELECT", "command"),
        ("permissive", "RESTRICTIVE", "mode"),
    ],
)
def test_private_vault_runtime_rejects_policy_semantic_drift(field, value, message) -> None:
    rows = _policy_rows()
    rows[0][field] = value

    with pytest.raises(PrivateVaultMaintenanceError, match=message):
        assert_private_vault_runtime_connection(
            _Connection(_runtime_rows(), rows, _visibility_rows(), _acl_rows(), [])
        )


@pytest.mark.parametrize(
    "visibility",
    [
        {"scoped_user_id": "101"},
        {"visible_documents": 1},
        {"visible_extractions": 1},
    ],
)
def test_private_vault_runtime_rejects_leaked_or_unscoped_visibility(visibility) -> None:
    with pytest.raises(PrivateVaultMaintenanceError, match="scope|visible"):
        assert_private_vault_runtime_connection(
            _Connection(
                _runtime_rows(),
                _policy_rows(),
                _visibility_rows(**visibility),
                _acl_rows(),
                [],
            )
        )


@pytest.mark.parametrize(
    "acl_rows",
    [
        lambda: [
            row
            for row in _acl_rows()
            if not (
                row["table_name"] == "user_documents"
                and row["grantee"] == "risk_module_runtime"
                and row["privilege_type"] == "DELETE"
            )
        ],
        lambda: _acl_rows()
        + [
            {
                "table_name": "user_documents",
                "grantee": "unexpected_reader",
                "privilege_type": "SELECT",
            }
        ],
    ],
)
def test_private_vault_runtime_rejects_acl_drift(acl_rows) -> None:
    with pytest.raises(PrivateVaultMaintenanceError, match="ACL|unexpected role"):
        assert_private_vault_runtime_connection(
            _Connection(_runtime_rows(), _policy_rows(), _visibility_rows(), acl_rows(), [])
        )


def test_private_vault_runtime_rejects_runtime_grant_option() -> None:
    acl_rows = _acl_rows()
    runtime_grant = next(
        row for row in acl_rows if row["grantee"] == "risk_module_runtime"
    )
    runtime_grant["is_grantable"] = True

    with pytest.raises(PrivateVaultMaintenanceError, match="must not be grantable"):
        assert_private_vault_runtime_connection(
            _Connection(_runtime_rows(), _policy_rows(), _visibility_rows(), acl_rows, [])
        )


def test_private_vault_runtime_rejects_column_acl_drift() -> None:
    column_acl_rows = [
        {
            "table_name": "user_documents",
            "column_name": "user_id",
            "grantee": "unexpected_reader",
            "privilege_type": "SELECT",
        }
    ]

    with pytest.raises(PrivateVaultMaintenanceError, match="column-level privileges"):
        assert_private_vault_runtime_connection(
            _Connection(
                _runtime_rows(),
                _policy_rows(),
                _visibility_rows(),
                _acl_rows(),
                column_acl_rows,
            )
        )


def test_private_vault_connection_verifier_proves_split_and_scope_cleanup() -> None:
    runtime_conn = _Connection(
        _runtime_rows(),
        _policy_rows(),
        _visibility_rows(),
        _acl_rows(),
        [],
        _database_identity_rows(),
        [{"scoped_user_id": "2147483647"}],
        [{"scoped_user_id": None}],
    )
    maintenance_conn = _Connection(
        _role_rows(current_role="risk_module_owner", owner="risk_module_owner"),
        _database_identity_rows(),
        [{"documents": 7, "extractions": 9}],
    )

    payload = verify_private_vault_connections(runtime_conn, maintenance_conn)

    assert payload["status"] == "PASS"
    assert payload["runtime_role"] == "risk_module_runtime"
    assert payload["maintenance_role"] == "risk_module_owner"
    assert payload["database_name"] == "risk_module_db"
    assert payload["database_identity_match"] is True
    assert payload["writable_primary"] is True
    assert payload["maintenance_row_counts"] == {
        "user_documents": 7,
        "user_document_extractions": 9,
    }
    assert runtime_conn.rollbacks == 4
    assert maintenance_conn.rollbacks == 3


def test_private_vault_connection_verifier_rejects_scope_that_survives_rollback() -> None:
    runtime_conn = _Connection(
        _runtime_rows(),
        _policy_rows(),
        _visibility_rows(),
        _acl_rows(),
        [],
        _database_identity_rows(),
        [{"scoped_user_id": "2147483647"}],
        [{"scoped_user_id": "2147483647"}],
    )
    maintenance_conn = _Connection(
        _role_rows(current_role="risk_module_owner", owner="risk_module_owner"),
        _database_identity_rows(),
    )

    with pytest.raises(PrivateVaultMaintenanceError, match="survived rollback"):
        verify_private_vault_connections(runtime_conn, maintenance_conn)


@pytest.mark.parametrize(
    ("identity_override", "message"),
    [
        ({"database_name": "wrong_database"}, "different database instances"),
        ({"system_identifier": "999"}, "different database instances"),
        ({"postmaster_started_epoch": "1784071550.0"}, "different database instances"),
    ],
)
def test_private_vault_connection_verifier_rejects_database_identity_mismatch(
    identity_override,
    message,
) -> None:
    runtime_conn = _Connection(
        _runtime_rows(),
        _policy_rows(),
        _visibility_rows(),
        _acl_rows(),
        [],
        _database_identity_rows(),
    )
    maintenance_conn = _Connection(
        _role_rows(current_role="risk_module_owner", owner="risk_module_owner"),
        _database_identity_rows(**identity_override),
    )

    with pytest.raises(PrivateVaultMaintenanceError, match=message):
        verify_private_vault_connections(runtime_conn, maintenance_conn)


@pytest.mark.parametrize(
    "identity_override",
    [
        {"in_recovery": True},
        {"transaction_read_only": "on"},
    ],
)
def test_private_vault_connection_verifier_rejects_non_writable_runtime_database(
    identity_override,
) -> None:
    runtime_conn = _Connection(
        _runtime_rows(),
        _policy_rows(),
        _visibility_rows(),
        _acl_rows(),
        [],
        _database_identity_rows(**identity_override),
    )
    maintenance_conn = _Connection(
        _role_rows(current_role="risk_module_owner", owner="risk_module_owner"),
    )

    with pytest.raises(PrivateVaultMaintenanceError, match="writable primary"):
        verify_private_vault_connections(runtime_conn, maintenance_conn)


def test_private_vault_connection_verifier_rejects_read_only_maintenance_database() -> None:
    runtime_conn = _Connection(
        _runtime_rows(),
        _policy_rows(),
        _visibility_rows(),
        _acl_rows(),
        [],
        _database_identity_rows(),
    )
    maintenance_conn = _Connection(
        _role_rows(current_role="risk_module_owner", owner="risk_module_owner"),
        _database_identity_rows(transaction_read_only="on"),
    )

    with pytest.raises(PrivateVaultMaintenanceError, match="writable primary"):
        verify_private_vault_connections(runtime_conn, maintenance_conn)
