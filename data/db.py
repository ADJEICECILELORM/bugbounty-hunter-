"""Database engine construction, schema readiness, and integrity validation."""

from __future__ import annotations

import warnings

from sqlalchemy import (
    Engine,
    MetaData,
    Table,
    and_,
    create_engine,
    inspect,
    literal,
    select,
)

from data.migrations import (
    LATEST_SCHEMA_VERSION,
    MigrationError,
    SQLITE_RETENTION_ERROR_MESSAGE,
    SQLITE_RETENTION_TRIGGERS,
    initialize_fresh_schema,
    preflight_migration,
)
from data.models import Base
from data.sqlite import enable_sqlite_foreign_keys


class DatabaseIntegrityError(RuntimeError):
    """Raised when the database contains unenforced or violated references."""


class DatabaseNotReadyError(RuntimeError):
    """Raised when an existing database needs explicit operator migration."""


def check_database_integrity(engine: Engine) -> None:
    """Raise when declared foreign keys are disabled or contain orphaned rows."""
    with engine.connect() as connection:
        inspector = inspect(connection)
        actual_foreign_keys: dict[str, set[tuple[str, str, str]]] = {}
        for table_name in inspector.get_table_names():
            actual_foreign_keys[table_name] = set()
            for foreign_key in inspector.get_foreign_keys(table_name):
                parent_table = foreign_key["referred_table"]
                parent_columns = foreign_key["referred_columns"]
                child_columns = foreign_key["constrained_columns"]
                if parent_table and parent_columns and child_columns:
                    actual_foreign_keys[table_name].update(
                        (child_column, parent_table, parent_column)
                        for child_column, parent_column in zip(
                            child_columns, parent_columns, strict=True
                        )
                    )
                options = foreign_key.get("options")
                ondelete = options.get("ondelete") if options else None
                if ondelete and ondelete.upper() not in {"RESTRICT", "NO ACTION"}:
                    raise DatabaseIntegrityError(
                        f"Foreign key on {table_name!r} has unsafe ON DELETE "
                        f"behavior {ondelete!r}"
                    )

        for table in Base.metadata.tables.values():
            for foreign_key in table.foreign_keys:
                expected = (
                    foreign_key.parent.name,
                    foreign_key.column.table.name,
                    foreign_key.column.name,
                )
                if expected not in actual_foreign_keys.get(table.name, set()):
                    raise DatabaseIntegrityError(
                        f"Database table {table.name!r} is missing restrictive "
                        f"foreign key {expected[0]!r} -> "
                        f"{expected[1]}.{expected[2]}"
                    )

        if connection.dialect.name == "sqlite":
            enabled = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
            if enabled != 1:
                raise DatabaseIntegrityError(
                    "SQLite foreign-key enforcement is disabled on this connection"
                )
            violations = connection.exec_driver_sql(
                "PRAGMA foreign_key_check"
            ).all()
            if violations:
                details = ", ".join(
                    f"{table} row {rowid} references {parent} (constraint {fk_id})"
                    for table, rowid, parent, fk_id in violations
                )
                raise DatabaseIntegrityError(
                    f"Database contains foreign-key violations: {details}"
                )

            installed_triggers = {
                name: (table_name, sql or "")
                for name, table_name, sql in connection.exec_driver_sql(
                    "SELECT name, tbl_name, sql FROM sqlite_master "
                    "WHERE type = 'trigger'"
                )
            }
            missing_triggers = []
            invalid_triggers = []
            preparer = connection.dialect.identifier_preparer
            for name, expected_table in SQLITE_RETENTION_TRIGGERS.items():
                actual = installed_triggers.get(name)
                if actual is None:
                    missing_triggers.append(name)
                    continue
                table_name, sql = actual
                expected_sql = (
                    f"CREATE TRIGGER {preparer.quote(name)} "
                    f"BEFORE DELETE ON {preparer.quote(expected_table)} "
                    f"BEGIN SELECT RAISE(ABORT, "
                    f"'{SQLITE_RETENTION_ERROR_MESSAGE}'); END"
                )
                normalized_sql = " ".join(sql.upper().split())
                if (
                    table_name != expected_table
                    or normalized_sql != " ".join(expected_sql.upper().split())
                ):
                    invalid_triggers.append(name)

            if missing_triggers or invalid_triggers:
                details = []
                if missing_triggers:
                    details.append("missing: " + ", ".join(sorted(missing_triggers)))
                if invalid_triggers:
                    details.append("invalid: " + ", ".join(sorted(invalid_triggers)))
                raise DatabaseIntegrityError(
                    "SQLite historical-retention triggers are not valid ("
                    + "; ".join(details)
                    + ")"
                )
            return

        metadata = MetaData()
        for table_name in inspector.get_table_names():
            child = Table(table_name, metadata, autoload_with=connection)
            for foreign_key in inspector.get_foreign_keys(table_name):
                parent_name = foreign_key["referred_table"]
                child_columns = foreign_key["constrained_columns"]
                parent_columns = foreign_key["referred_columns"]
                if not parent_name or not child_columns or not parent_columns:
                    continue
                parent = Table(parent_name, metadata, autoload_with=connection)
                join = and_(
                    *(
                        child.c[child_column] == parent.c[parent_column]
                        for child_column, parent_column in zip(
                            child_columns, parent_columns, strict=True
                        )
                    )
                )
                missing_reference = and_(
                    *(child.c[column].is_not(None) for column in child_columns),
                    parent.c[parent_columns[0]].is_(None),
                )
                violation = connection.execute(
                    select(literal(1))
                    .select_from(child.outerjoin(parent, join))
                    .where(missing_reference)
                    .limit(1)
                ).first()
                if violation:
                    raise DatabaseIntegrityError(
                        f"Database contains an orphan in {table_name!r} "
                        f"referencing {parent_name!r}"
                    )


def create_database_engine(connection_string: str) -> Engine:
    """Construct an engine and configure SQLite connection safety hooks."""
    engine = create_engine(connection_string)
    enable_sqlite_foreign_keys(engine)
    return engine


def open_ready_database(connection_string: str) -> Engine:
    """Construct an engine and refuse startup unless its existing schema is ready."""
    engine = create_database_engine(connection_string)
    try:
        require_schema_ready(engine)
    except Exception:
        engine.dispose()
        raise
    return engine


def initialize_fresh_database(engine: Engine) -> None:
    """Initialize a genuinely empty database and validate its integrity."""
    initialize_fresh_schema(engine)
    check_database_integrity(engine)


def require_schema_ready(engine: Engine) -> int:
    """Read-only check that an existing database is at the supported schema."""
    try:
        current_version = preflight_migration(engine)
    except MigrationError as error:
        raise DatabaseNotReadyError(
            f"Database schema is not ready: {error}. If this is an existing "
            "database, review it and run `python -m scripts.migrate_database "
            "--database <path>` explicitly."
        ) from error

    latest_version = LATEST_SCHEMA_VERSION
    if current_version != latest_version:
        raise DatabaseNotReadyError(
            f"Database schema version {current_version} is not current "
            f"(expected {latest_version}). Run `python -m "
            "scripts.migrate_database --database <path>` explicitly."
        )
    check_database_integrity(engine)
    return current_version


def init_db(connection_string: str) -> Engine:
    """Deprecated fresh-only initializer; it never migrates an existing DB.

    New code should construct an engine with :func:`create_database_engine`,
    then call either :func:`initialize_fresh_database` or
    :func:`require_schema_ready` according to its intent.
    """
    warnings.warn(
        "init_db() is deprecated and fresh-only; use create_database_engine() "
        "with initialize_fresh_database() or require_schema_ready().",
        DeprecationWarning,
        stacklevel=2,
    )
    engine = create_database_engine(connection_string)
    try:
        initialize_fresh_database(engine)
    except Exception:
        engine.dispose()
        raise
    return engine
