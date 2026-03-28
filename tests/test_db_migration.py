import importlib
import inspect


class FakeCursor:
    def __init__(self, statements):
        self.statements = statements

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql_text):
        self.statements.append(sql_text)


class FakeDbSession:
    def __init__(self):
        self.statements = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return FakeCursor(self.statements)

    def commit(self):
        self.commit_calls += 1

    def rollback(self):
        self.rollback_calls += 1


def _invoke_with_path_and_session(func, path_arg, session_arg):
    params = list(inspect.signature(func).parameters)
    if not params:
        raise AssertionError("Migration helper must accept arguments")
    if "migration_file_path" in params or "path" in params or "migration_path" in params:
        return func(path_arg, session_arg)
    return func(session_arg, path_arg)


def _invoke_with_dir_and_session(func, dir_arg, session_arg):
    params = list(inspect.signature(func).parameters)
    if not params:
        raise AssertionError("Migration directory helper must accept arguments")
    if "migrations_dir" in params or "directory" in params or "dir_path" in params:
        return func(dir_arg, session_arg)
    return func(session_arg, dir_arg)


def test_run_migration_executes_sql_file(tmp_path):
    migration_module = importlib.import_module("app_platform.db.migration")
    session = FakeDbSession()
    migration_file = tmp_path / "001_create_table.sql"
    sql_text = "CREATE TABLE widgets (id INT);"
    migration_file.write_text(sql_text)

    _invoke_with_path_and_session(migration_module.run_migration, str(migration_file), session)

    assert session.statements == [sql_text]
    assert session.commit_calls == 1
    assert session.rollback_calls == 0


def test_run_migrations_dir_executes_sql_files_in_sorted_order(tmp_path):
    migration_module = importlib.import_module("app_platform.db.migration")
    session = FakeDbSession()

    second = tmp_path / "002_second.sql"
    first = tmp_path / "001_first.sql"
    second.write_text("SELECT 2;")
    first.write_text("SELECT 1;")

    _invoke_with_dir_and_session(migration_module.run_migrations_dir, str(tmp_path), session)

    assert session.statements == ["SELECT 1;", "SELECT 2;"]
    assert session.commit_calls >= 1
