"""Generic SQL migration helpers for app_platform."""

from pathlib import Path

from .exceptions import MigrationError


def run_migration(migration_file_path, conn):
    """Execute a single SQL migration file against an existing DB connection."""

    migration_path = Path(migration_file_path)
    if not migration_path.exists():
        raise MigrationError(
            f"Migration file not found: {migration_path}",
            migration_step=str(migration_path),
        )
    if not migration_path.is_file():
        raise MigrationError(
            f"Migration path is not a file: {migration_path}",
            migration_step=str(migration_path),
        )

    sql_content = migration_path.read_text()

    try:
        with conn.cursor() as cursor:
            cursor.execute(sql_content)
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise MigrationError(
            f"Failed to run migration: {migration_path.name}",
            migration_step=str(migration_path),
            original_error=exc,
        ) from exc

    return migration_path


def run_migrations_dir(migrations_dir, conn):
    """Execute all `.sql` files in a directory, sorted by filename."""

    migrations_path = Path(migrations_dir)
    if not migrations_path.exists():
        raise MigrationError(
            f"Migrations directory not found: {migrations_path}",
            migration_step=str(migrations_path),
        )
    if not migrations_path.is_dir():
        raise MigrationError(
            f"Migrations path is not a directory: {migrations_path}",
            migration_step=str(migrations_path),
        )

    executed = []
    for migration_path in sorted(migrations_path.glob("*.sql")):
        run_migration(migration_path, conn)
        executed.append(migration_path)
    return executed


__all__ = ["run_migration", "run_migrations_dir"]
