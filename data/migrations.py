"""Versioned, transactional database schema migrations.

Migrations are deliberately explicit and additive. They never drop or rewrite
application records; legacy databases are upgraded in place only after their
core tables have been validated.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterator

from sqlalchemy import (
    CheckConstraint,
    Connection,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    Table,
    Column,
    UniqueConstraint,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Engine

from data.models import Base

_MIGRATION_TABLE_NAME = "schema_migrations"
_POSTGRES_MIGRATION_LOCK_ID = 814_208_001
_LEGACY_CORE_COLUMNS = {
    "programs": {"id", "name", "authorized_scope", "excluded_scope", "rate_limit", "created_at"},
    "investigations": {"id", "program_id", "status", "started_at", "ended_at"},
    "assets": {"id", "investigation_id", "hostname", "discovered_at"},
    "hypotheses": {"id", "asset_id", "category", "description", "status", "created_at"},
    "observations": {
        "id",
        "asset_id",
        "hypothesis_id",
        "observation_type",
        "data",
        "created_at",
    },
}
_ADDITIVE_COLUMNS = {
    "investigations": {
        "max_tasks": "INTEGER",
        "max_llm_calls": "INTEGER",
    }
}
_TABLES_ADDED_IN_V2 = (
    "tasks",
    "task_events",
    "verdicts",
    "findings",
    "promotion_audit",
    "hypothesis_supporting_observations",
    "observation_provenance",
)
SQLITE_RETENTION_TRIGGERS = {
    "retain_observations": "observations",
    "retain_observation_provenance": "observation_provenance",
    "retain_hypothesis_supporting_observations": (
        "hypothesis_supporting_observations"
    ),
    "retain_verdicts": "verdicts",
    "retain_findings": "findings",
    "retain_task_events": "task_events",
    "retain_promotion_audit": "promotion_audit",
}
SQLITE_RETENTION_ERROR_MESSAGE = (
    "historical record retention: permanent deletion is prohibited"
)


class MigrationError(RuntimeError):
    """Raised when a database cannot be safely migrated."""


@dataclass(frozen=True)
class Migration:
    """One ordered schema change and its stable history name."""

    version: int
    name: str
    upgrade: Callable[[Connection], None]


_migration_metadata = MetaData()
_schema_migrations = Table(
    _MIGRATION_TABLE_NAME,
    _migration_metadata,
    Column("version", Integer, primary_key=True),
    Column("name", String(128), nullable=False),
    Column("applied_at", DateTime(timezone=True), nullable=False),
)


def _validate_legacy_schema(connection: Connection) -> None:
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    missing_tables = sorted(set(_LEGACY_CORE_COLUMNS) - tables)
    if missing_tables:
        raise MigrationError(
            "Unversioned database is missing required core tables: "
            + ", ".join(missing_tables)
        )

    for table_name, required_columns in _LEGACY_CORE_COLUMNS.items():
        existing_columns = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        missing_columns = sorted(required_columns - existing_columns)
        if missing_columns:
            raise MigrationError(
                f"Unversioned database table {table_name!r} is missing required "
                "columns: "
                + ", ".join(missing_columns)
            )
    _validate_schema_contract(connection, 0)


def _column_type_name(column_type: object, dialect_name: str) -> str:
    return column_type.compile(dialect=connection_dialect(dialect_name)).upper()


def connection_dialect(dialect_name: str):
    if dialect_name == "sqlite":
        from sqlalchemy.dialects import sqlite

        return sqlite.dialect()
    if dialect_name == "postgresql":
        from sqlalchemy.dialects import postgresql

        return postgresql.dialect()
    raise MigrationError(f"Unsupported migration dialect: {dialect_name}")


def _normalize_sql(value: str) -> str:
    return " ".join(value.upper().replace('"', "").replace("`", "").split())


def _unique_contracts(table: Table) -> set[tuple[str, ...]]:
    return {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }


def _validate_table_contract(
    connection: Connection,
    table: Table,
    *,
    include_columns: set[str] | None = None,
) -> None:
    inspector = inspect(connection)
    table_name = table.name
    columns = {column["name"]: column for column in inspector.get_columns(table_name)}
    expected_primary_key = tuple(
        column.name for column in table.primary_key.columns
    )
    actual_primary_key = tuple(
        inspector.get_pk_constraint(table_name).get("constrained_columns") or ()
    )
    expected_columns = [
        expected
        for expected in table.columns
        if include_columns is None or expected.name in include_columns
    ]
    for expected in expected_columns:
        actual = columns.get(expected.name)
        if actual is None:
            raise MigrationError(
                f"Table {table_name!r} is missing required column {expected.name!r}"
            )
        expected_type = _column_type_name(expected.type, connection.dialect.name)
        actual_type = _column_type_name(actual["type"], connection.dialect.name)
        if expected_type != actual_type:
            raise MigrationError(
                f"Table {table_name!r} column {expected.name!r} has type "
                f"{actual_type}, expected {expected_type}"
            )
        actual_nullable = bool(actual["nullable"])
        if expected.name in expected_primary_key and expected.name in actual_primary_key:
            actual_nullable = False
        if actual_nullable != bool(expected.nullable):
            raise MigrationError(
                f"Table {table_name!r} column {expected.name!r} has incorrect "
                f"nullability"
            )

    if actual_primary_key != expected_primary_key:
        raise MigrationError(
            f"Table {table_name!r} has primary key {actual_primary_key!r}, "
            f"expected {expected_primary_key!r}"
        )

    expected_uniques = _unique_contracts(table)
    actual_uniques = {
        tuple(constraint.get("column_names") or ())
        for constraint in inspector.get_unique_constraints(table_name)
    }
    actual_uniques.update(
        tuple(index["column_names"])
        for index in inspector.get_indexes(table_name)
        if index.get("unique")
    )
    if not expected_uniques.issubset(actual_uniques):
        raise MigrationError(
            f"Table {table_name!r} is missing required unique constraints: "
            f"{sorted(expected_uniques - actual_uniques)!r}"
        )

    expected_foreign_keys = {
        (
            tuple(element.parent.name for element in constraint.elements),
            constraint.elements[0].column.table.name,
            tuple(element.column.name for element in constraint.elements),
            (constraint.ondelete or "").upper(),
        )
        for constraint in table.foreign_key_constraints
    }
    actual_foreign_keys = set()
    for foreign_key in inspector.get_foreign_keys(table_name):
        options = foreign_key.get("options") or {}
        actual_foreign_keys.add(
            (
                tuple(foreign_key.get("constrained_columns") or ()),
                foreign_key.get("referred_table"),
                tuple(foreign_key.get("referred_columns") or ()),
                (options.get("ondelete") or "NO ACTION").upper(),
            )
        )
    unmatched_foreign_keys = []
    for expected in expected_foreign_keys:
        child_columns, parent_table, parent_columns, delete_action = expected
        matches = [
            actual
            for actual in actual_foreign_keys
            if actual[:3] == (child_columns, parent_table, parent_columns)
            and actual[3] in {delete_action, "NO ACTION"}
        ]
        if not matches:
            unmatched_foreign_keys.append(expected)
    if unmatched_foreign_keys:
        raise MigrationError(
            f"Table {table_name!r} is missing required foreign keys: "
            f"{unmatched_foreign_keys!r}"
        )

    expected_checks = {
        _normalize_sql(constraint.sqltext.text)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    actual_checks = {
        _normalize_sql(constraint["sqltext"])
        for constraint in inspector.get_check_constraints(table_name)
        if constraint.get("sqltext")
    }
    if not expected_checks.issubset(actual_checks):
        raise MigrationError(
            f"Table {table_name!r} is missing required CHECK constraints: "
            f"{sorted(expected_checks - actual_checks)!r}"
        )

    expected_indexes = {
        (tuple(column.name for column in index.columns), bool(index.unique))
        for index in table.indexes
    }
    actual_indexes = {
        (tuple(index.get("column_names") or ()), bool(index.get("unique")))
        for index in inspector.get_indexes(table_name)
        if index.get("column_names") and not index.get("duplicates_constraint")
    }
    if not expected_indexes.issubset(actual_indexes):
        raise MigrationError(
            f"Table {table_name!r} is missing required indexes: "
            f"{sorted(expected_indexes - actual_indexes)!r}"
        )


def _validate_schema_contract(connection: Connection, version: int) -> None:
    inspector = inspect(connection)
    present_tables = set(inspector.get_table_names())
    required_tables = set(_LEGACY_CORE_COLUMNS)
    if version >= 2:
        required_tables.update(_TABLES_ADDED_IN_V2)
    missing_tables = sorted(required_tables - present_tables)
    if missing_tables:
        raise MigrationError(
            f"Schema version {version} is missing required tables: "
            + ", ".join(missing_tables)
        )

    for table_name in present_tables - {_MIGRATION_TABLE_NAME}:
        if table_name not in Base.metadata.tables:
            continue
        if version == 0 and table_name == "investigations":
            _validate_table_contract(
                connection,
                Base.metadata.tables[table_name],
                include_columns=_LEGACY_CORE_COLUMNS[table_name],
            )
            continue
        elif version == 0 and table_name in _TABLES_ADDED_IN_V2:
            _validate_table_contract(connection, Base.metadata.tables[table_name])
            continue
        else:
            expected_table = Base.metadata.tables.get(table_name)
        if expected_table is not None:
            _validate_table_contract(connection, expected_table)

    if inspector.has_table(_MIGRATION_TABLE_NAME):
        _validate_table_contract(connection, _schema_migrations)

    if version >= 3 and connection.dialect.name == "sqlite":
        _validate_sqlite_retention_triggers(connection)


def _validate_sqlite_retention_triggers(connection: Connection) -> None:
    triggers = {
        name: (table_name, sql or "")
        for name, table_name, sql in connection.exec_driver_sql(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger'"
        )
    }
    missing = []
    invalid = []
    for trigger_name, table_name in SQLITE_RETENTION_TRIGGERS.items():
        trigger = triggers.get(trigger_name)
        if trigger is None:
            missing.append(trigger_name)
            continue
        actual_table, sql = trigger
        expected = (
            f"CREATE TRIGGER {trigger_name} BEFORE DELETE ON {table_name} "
            f"BEGIN SELECT RAISE(ABORT, '{SQLITE_RETENTION_ERROR_MESSAGE}'); END"
        )
        if actual_table != table_name or _normalize_sql(sql) != _normalize_sql(expected):
            invalid.append(trigger_name)
    if missing or invalid:
        details = []
        if missing:
            details.append("missing: " + ", ".join(sorted(missing)))
        if invalid:
            details.append("invalid: " + ", ".join(sorted(invalid)))
        raise MigrationError("SQLite retention triggers are invalid (" + "; ".join(details) + ")")


def _validate_source_data_integrity(connection: Connection, version: int) -> None:
    if connection.dialect.name == "sqlite":
        violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
        if violations:
            details = ", ".join(
                f"{table} row {rowid} references {parent} (constraint {fk_id})"
                for table, rowid, parent, fk_id in violations
            )
            raise MigrationError(
                f"Source schema version {version} has orphaned records / "
                f"foreign-key violations: {details}"
            )

    inspector = inspect(connection)
    for table_name in sorted(set(inspector.get_table_names()) & set(Base.metadata.tables)):
        table = Base.metadata.tables[table_name]
        for foreign_key in table.foreign_keys:
            target_table = foreign_key.column.table.name
            target_column = foreign_key.column.name
            source_column = foreign_key.parent.name
            if not inspector.has_table(target_table):
                continue
            source_columns = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            target_columns = {
                column["name"] for column in inspector.get_columns(target_table)
            }
            if source_column not in source_columns or target_column not in target_columns:
                continue
            orphan = connection.exec_driver_sql(
                f'SELECT child."{source_column}" FROM "{table_name}" AS child '
                f'LEFT JOIN "{target_table}" AS parent '
                f'ON parent."{target_column}" = child."{source_column}" '
                f'WHERE child."{source_column}" IS NOT NULL '
                f'AND parent."{target_column}" IS NULL LIMIT 1'
            ).first()
            if orphan:
                raise MigrationError(
                    f"Source schema version {version} has an orphan in "
                    f"{table_name}.{source_column} referencing "
                    f"{target_table}.{target_column}"
                )

    if version >= 2 and inspector.has_table("promotion_audit"):
        tables = set(inspector.get_table_names())
        audit_columns = {
            column["name"] for column in inspector.get_columns("promotion_audit")
        }
        for field, referenced_table in (
            ("evidence_ids", "observations"),
            ("verdict_ids", "verdicts"),
        ):
            if field not in audit_columns or referenced_table not in tables:
                continue
            rows = connection.exec_driver_sql(
                f'SELECT id, "{field}" FROM promotion_audit'
            )
            for audit_id, encoded_ids in rows:
                import json

                try:
                    references = json.loads(encoded_ids) if encoded_ids else []
                except (TypeError, ValueError) as error:
                    raise MigrationError(
                        f"PromotionAudit {audit_id} has invalid {field} JSON"
                    ) from error
                if not isinstance(references, list):
                    raise MigrationError(
                        f"PromotionAudit {audit_id} has non-list {field}"
                    )
                for referenced_id in references:
                    found = connection.execute(
                        text(f'SELECT 1 FROM "{referenced_table}" WHERE id = :id'),
                        {"id": referenced_id},
                    ).first()
                    if not found:
                        raise MigrationError(
                            f"PromotionAudit {audit_id} references missing "
                            f"{referenced_table} row {referenced_id}"
                        )
def _add_investigation_budget_columns(connection: Connection) -> None:
    inspector = inspect(connection)
    if not inspector.has_table("investigations"):
        raise MigrationError(
            "Cannot add investigation budget columns: table 'investigations' "
            "does not exist"
        )

    existing_columns = {
        column["name"] for column in inspector.get_columns("investigations")
    }
    preparer = connection.dialect.identifier_preparer
    table_name = preparer.quote("investigations")
    for column_name, sql_type in _ADDITIVE_COLUMNS["investigations"].items():
        if column_name not in existing_columns:
            quoted_column = preparer.quote(column_name)
            connection.exec_driver_sql(
                f"ALTER TABLE {table_name} ADD COLUMN {quoted_column} {sql_type}"
            )


def _create_v2_tables(connection: Connection) -> None:
    for table_name in _TABLES_ADDED_IN_V2:
        try:
            table = Base.metadata.tables[table_name]
        except KeyError as error:
            raise MigrationError(
                f"Migration requires mapped table {table_name!r}"
            ) from error
        table.create(connection, checkfirst=True)


def _install_sqlite_retention_triggers(connection: Connection) -> None:
    if connection.dialect.name != "sqlite":
        return

    preparer = connection.dialect.identifier_preparer
    for trigger_name, table_name in SQLITE_RETENTION_TRIGGERS.items():
        quoted_trigger = preparer.quote(trigger_name)
        quoted_table = preparer.quote(table_name)
        connection.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS {quoted_trigger} "
            f"BEFORE DELETE ON {quoted_table} "
            f"BEGIN SELECT RAISE(ABORT, '{SQLITE_RETENTION_ERROR_MESSAGE}'); END"
        )


_MIGRATIONS = (
    Migration(1, "investigation_budgets", _add_investigation_budget_columns),
    Migration(2, "task_verification_and_v81_tables", _create_v2_tables),
    Migration(3, "sqlite_historical_record_retention", _install_sqlite_retention_triggers),
)
LATEST_SCHEMA_VERSION = len(_MIGRATIONS)


def _read_history(connection: Connection) -> list[tuple[int, str]]:
    return list(
        (version, name)
        for version, name in connection.execute(
            select(_schema_migrations.c.version, _schema_migrations.c.name).order_by(
                _schema_migrations.c.version
            )
        )
    )


def _validate_history(history: list[tuple[int, str]]) -> int:
    known = {migration.version: migration.name for migration in _MIGRATIONS}
    for expected_version, (version, name) in enumerate(history, start=1):
        if version != expected_version:
            raise MigrationError(
                "Migration history is not contiguous: expected version "
                f"{expected_version}, found {version}"
            )
        if known.get(version) != name:
            raise MigrationError(
                f"Migration history entry {version} has unexpected name {name!r}"
            )
    current_version = history[-1][0] if history else 0
    if current_version > len(_MIGRATIONS):
        raise MigrationError(
            f"Database schema version {current_version} is newer than this "
            f"application supports ({len(_MIGRATIONS)})"
        )
    return current_version


def _record_migration(connection: Connection, migration: Migration) -> None:
    connection.execute(
        insert(_schema_migrations).values(
            version=migration.version,
            name=migration.name,
            applied_at=datetime.now(UTC),
        )
    )


def _bootstrap_fresh_database(connection: Connection) -> None:
    Base.metadata.create_all(connection)
    _validate_schema_contract(connection, 0)
    for migration in _MIGRATIONS:
        migration.upgrade(connection)
        _validate_schema_contract(connection, migration.version)
        _record_migration(connection, migration)


def initialize_fresh_schema(engine: Engine) -> None:
    """Initialize an empty database once; never upgrade an existing schema."""
    with engine.connect() as connection:
        with _migration_transaction(connection):
            inspector = inspect(connection)
            objects = set(inspector.get_table_names())
            objects.update(inspector.get_view_names())
            if connection.dialect.name == "sqlite":
                objects = {
                    name
                    for (name,) in connection.exec_driver_sql(
                        "SELECT name FROM sqlite_master "
                        "WHERE name NOT LIKE 'sqlite_%'"
                    )
                }
            if objects:
                raise MigrationError(
                    "Fresh initialization requires an empty database; existing "
                    "objects were found. Use the explicit migration command for "
                    "a supported existing database."
                )
            _schema_migrations.create(connection)
            _bootstrap_fresh_database(connection)


def preflight_migration(engine: Engine) -> int:
    """Read-only validation of a non-empty database before explicit migration."""
    with engine.connect() as connection:
        inspector = inspect(connection)
        has_history_table = inspector.has_table(_MIGRATION_TABLE_NAME)
        application_tables = set(inspector.get_table_names()) - {
            _MIGRATION_TABLE_NAME
        }
        if not application_tables:
            raise MigrationError(
                "Database has no application tables. Use fresh database "
                "initialization instead of migration."
            )

        if has_history_table:
            _validate_table_contract(connection, _schema_migrations)
        history = _read_history(connection) if has_history_table else []
        current_version = _validate_history(history)
        if current_version == 0:
            _validate_legacy_schema(connection)
        else:
            _validate_schema_contract(connection, current_version)
        _validate_source_data_integrity(connection, current_version)
        return current_version


def _acquire_migration_lock(connection: Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "SELECT pg_advisory_xact_lock(%s)", (_POSTGRES_MIGRATION_LOCK_ID,)
        )


@contextmanager
def _migration_transaction(connection: Connection) -> Iterator[Connection]:
    if connection.dialect.name == "sqlite":
        # sqlite3's legacy transaction mode does not begin a transaction for DDL.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        connection.begin()

    try:
        yield connection
        connection.commit()
    except BaseException:
        if connection.in_transaction():
            connection.rollback()
        raise


def migrate_database(engine: Engine) -> None:
    """Upgrade ``engine`` to the latest schema version without losing records.

    An unversioned, non-empty database is treated as legacy version 0, checked
    for the required core schema, then upgraded one migration at a time. Each
    migration and its history row commit atomically. If a migration fails, its
    DDL and history entry roll back, leaving the database at the last known-good
    version.
    """
    with engine.connect() as connection:
        with _migration_transaction(connection):
            _acquire_migration_lock(connection)
            inspector = inspect(connection)
            has_history_table = inspector.has_table(_MIGRATION_TABLE_NAME)
            application_tables = set(inspector.get_table_names()) - {
                _MIGRATION_TABLE_NAME
            }

            if not application_tables:
                raise MigrationError(
                    "Database has no application tables. Use fresh database "
                    "initialization instead of migration."
                )

            if has_history_table:
                _validate_table_contract(connection, _schema_migrations)
            history = _read_history(connection) if has_history_table else []
            current_version = _validate_history(history)
            if current_version == 0:
                _validate_legacy_schema(connection)
            else:
                _validate_schema_contract(connection, current_version)
            _validate_source_data_integrity(connection, current_version)

        while True:
            with _migration_transaction(connection):
                _acquire_migration_lock(connection)
                inspector = inspect(connection)
                has_history_table = inspector.has_table(_MIGRATION_TABLE_NAME)
                application_tables = set(inspector.get_table_names()) - {
                    _MIGRATION_TABLE_NAME
                }
                if not has_history_table:
                    _schema_migrations.create(connection)
                else:
                    _validate_table_contract(connection, _schema_migrations)

                history = _read_history(connection) if has_history_table else []
                current_version = _validate_history(history)
                if current_version == 0 and application_tables:
                    _validate_legacy_schema(connection)
                else:
                    _validate_schema_contract(connection, current_version)
                _validate_source_data_integrity(connection, current_version)
                if current_version >= len(_MIGRATIONS):
                    return

                if current_version == 0 and application_tables:
                    _validate_legacy_schema(connection)

                migration = _MIGRATIONS[current_version]
                try:
                    migration.upgrade(connection)
                    _validate_schema_contract(connection, migration.version)
                    _validate_source_data_integrity(connection, migration.version)
                    _record_migration(connection, migration)
                except Exception as error:
                    raise MigrationError(
                        f"Migration {migration.version} ({migration.name}) failed; "
                        "its changes were rolled back"
                    ) from error
