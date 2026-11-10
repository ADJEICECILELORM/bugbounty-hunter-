"""Explicit, backup-first migration command for SQLite evidence databases."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import sys
from pathlib import Path
from typing import Iterator

from sqlalchemy.engine import URL

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.backup import SQLiteBackupError, create_verified_sqlite_backup  # noqa: E402
from data.db import (  # noqa: E402
    DatabaseIntegrityError,
    DatabaseNotReadyError,
    create_database_engine,
    require_schema_ready,
)
from data.migrations import (  # noqa: E402
    LATEST_SCHEMA_VERSION,
    MigrationError,
    migrate_database,
    preflight_migration,
)


class MigrationLockError(RuntimeError):
    """Raised when another migration command holds the database lock."""


@contextmanager
def _migration_lock(database_path: Path) -> Iterator[None]:
    lock_path = Path(f"{database_path}.migration.lock")
    try:
        lock_file = lock_path.open("a+b")
    except OSError as error:
        raise MigrationLockError(
            f"Cannot open migration lock {lock_path}: {error}"
        ) from error
    try:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise MigrationLockError(
                f"Another migration command holds {lock_path}; wait for it to finish."
            ) from error
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Explicitly migrate an existing SQLite database after read-only "
            "preflight and a verified, non-overwriting online backup. Stop all "
            "database writers during the maintenance window."
        )
    )
    parser.add_argument(
        "--database",
        required=True,
        type=Path,
        help="existing SQLite database file to migrate",
    )
    parser.add_argument(
        "--backup",
        type=Path,
        help="backup destination (default: unique pre-migration file beside database)",
    )
    parser.add_argument(
        "--confirm-writers-stopped",
        action="store_true",
        help=(
            "confirm that all processes which can write to this database have "
            "been stopped (human acknowledgment; this does not detect processes)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.confirm_writers_stopped:
        print(
            "Refusing migration: stop all database writers and rerun with "
            "--confirm-writers-stopped (the flag does not detect other processes).",
            file=sys.stderr,
        )
        return 2
    database_path = args.database.expanduser().resolve()
    if not database_path.is_file():
        print(
            f"Refusing migration: database file does not exist: {database_path}",
            file=sys.stderr,
        )
        return 2

    try:
        with _migration_lock(database_path):
            engine = create_database_engine(
                URL.create("sqlite+pysqlite", database=str(database_path))
            )
            try:
                return _migrate_under_lock(engine, database_path, args)
            finally:
                engine.dispose()
    except (MigrationLockError, DatabaseIntegrityError, DatabaseNotReadyError, MigrationError, SQLiteBackupError) as error:
        print(f"Migration refused or failed: {error}", file=sys.stderr)
        return 1


def _migrate_under_lock(engine, database_path: Path, args: argparse.Namespace) -> int:
    try:
            current_version = preflight_migration(engine)
            target_version = LATEST_SCHEMA_VERSION
            if current_version == target_version:
                require_schema_ready(engine)
                print(
                    f"Database is already ready at schema version {current_version}; "
                    "no migration or backup was needed."
                )
                return 0

            backup = create_verified_sqlite_backup(database_path, args.backup)
            print(f"Verified backup: {backup.path}")
            print(f"Backup SHA-256: {backup.sha256}")
            print(f"Checksum record: {backup.checksum_path}")

            migrate_database(engine)
            resulting_version = require_schema_ready(engine)
            print(f"Migration complete; schema version {resulting_version}.")
            return 0
    except (DatabaseIntegrityError, DatabaseNotReadyError, MigrationError, SQLiteBackupError):
        raise


if __name__ == "__main__":
    raise SystemExit(main())
