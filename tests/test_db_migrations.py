"""Tests for fresh initialization and additive database schema migrations."""

from __future__ import annotations

import shutil
import sqlite3
import hashlib
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from data import migrations
from data.backup import SQLiteBackupError, create_verified_sqlite_backup
from data.db import (
    DatabaseNotReadyError,
    create_database_engine,
    initialize_fresh_database,
    init_db,
    open_ready_database,
    require_schema_ready,
)
from data.migrations import (
    MigrationError,
    initialize_fresh_schema,
    migrate_database,
    preflight_migration,
)
from data.models import (
    Asset,
    Base,
    Hypothesis,
    HypothesisSupportingObservation,
    Investigation,
    Observation,
    ObservationProvenance,
    Program,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _create_legacy_test_database(path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    core_tables = [
        Base.metadata.tables[name]
        for name in (
            "programs",
            "investigations",
            "assets",
            "hypotheses",
            "observations",
        )
    ]
    try:
        with engine.begin() as connection:
            Base.metadata.create_all(connection, tables=core_tables)
            connection.exec_driver_sql(
                'ALTER TABLE "investigations" DROP COLUMN "max_tasks"'
            )
            connection.exec_driver_sql(
                'ALTER TABLE "investigations" DROP COLUMN "max_llm_calls"'
            )
    finally:
        engine.dispose()


def _migration_history(connection: Connection) -> list[tuple[int, str]]:
    return list(
        (version, name)
        for version, name in connection.execute(
            text("SELECT version, name FROM schema_migrations ORDER BY version")
        )
    )


def _database_snapshot(path: Path) -> dict[str, dict[str, object]]:
    with sqlite3.connect(path) as database:
        tables = [
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        ]
        snapshot = {}
        for table in tables:
            columns = [
                row[1] for row in database.execute(f'PRAGMA table_info("{table}")')
            ]
            rows = [
                dict(zip(columns, row, strict=True))
                for row in database.execute(
                    f'SELECT * FROM "{table}" ORDER BY rowid'
                )
            ]
            snapshot[table] = {"columns": columns, "rows": rows}
        return snapshot


def test_fresh_database_is_initialized_at_the_current_schema() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    try:
        initialize_fresh_database(engine)
        inspector = inspect(engine)
        assert set(Base.metadata.tables).issubset(inspector.get_table_names())
        assert require_schema_ready(engine) == len(migrations._MIGRATIONS)
        with engine.connect() as connection:
            assert _migration_history(connection) == [
                (migration.version, migration.name)
                for migration in migrations._MIGRATIONS
            ]
    finally:
        engine.dispose()


def test_fresh_initialization_refuses_nonempty_unversioned_database(
    tmp_path: Path,
) -> None:
    path = tmp_path / "nonempty.db"
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE operator_data (value TEXT)")
        database.execute("INSERT INTO operator_data VALUES ('preserve me')")
    before = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        with pytest.raises(MigrationError, match="requires an empty database"):
            initialize_fresh_database(engine)
        assert path.read_bytes() == before
        with engine.connect() as connection:
            assert not inspect(connection).has_table("schema_migrations")
    finally:
        engine.dispose()


def test_readiness_check_is_read_only_for_current_schema(tmp_path: Path) -> None:
    path = tmp_path / "ready.db"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    engine.dispose()
    before = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        assert require_schema_ready(engine) == len(migrations._MIGRATIONS)
        assert path.read_bytes() == before
    finally:
        engine.dispose()


def test_runtime_readiness_refuses_legacy_schema_without_migrating(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-runtime.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    before = path.read_bytes()
    with pytest.raises(DatabaseNotReadyError, match="migrate_database"):
        open_ready_database(f"sqlite+pysqlite:///{path}")
    assert path.read_bytes() == before
    with sqlite3.connect(path) as database:
        assert database.execute(
            "SELECT name FROM sqlite_master WHERE name='schema_migrations'"
        ).fetchone() is None


def test_readiness_check_rejects_outdated_version_without_writing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "outdated.db"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM schema_migrations WHERE version > 2")
        connection.exec_driver_sql("DROP TRIGGER retain_observations")
    engine.dispose()
    before = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        with pytest.raises(DatabaseNotReadyError, match="schema version 2"):
            require_schema_ready(engine)
        assert path.read_bytes() == before
    finally:
        engine.dispose()


def test_readiness_rejects_altered_retention_trigger(
    tmp_path: Path,
) -> None:
    path = tmp_path / "altered-current-trigger.db"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql('DROP TRIGGER "retain_observations"')
        connection.exec_driver_sql(
            "CREATE TRIGGER retain_observations BEFORE DELETE ON observations "
            "WHEN 0 BEGIN SELECT RAISE(ABORT, "
            "'historical record retention: permanent deletion is prohibited'); END"
        )
    try:
        with pytest.raises(DatabaseNotReadyError, match="retention triggers"):
            require_schema_ready(engine)
        with engine.connect() as connection:
            trigger_sql = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type='trigger' AND name='retain_observations'"
            ).scalar_one()
            assert "WHEN 0" in trigger_sql
    finally:
        engine.dispose()


def test_online_backup_is_verified_and_never_overwrites_existing_file(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    source = sqlite3.connect(source_path)
    try:
        source.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)")
        source.execute("INSERT INTO evidence(value) VALUES ('preserved')")
        source.commit()
        backup = create_verified_sqlite_backup(source_path, backup_path)
        assert backup.sha256 == hashlib.sha256(backup_path.read_bytes()).hexdigest()
        assert backup.checksum_path.read_text(encoding="ascii").startswith(
            backup.sha256
        )
        with sqlite3.connect(backup_path) as copied:
            assert copied.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert copied.execute("SELECT value FROM evidence").fetchone() == (
                "preserved",
            )

        original_backup = backup_path.read_bytes()
        with pytest.raises(SQLiteBackupError, match="Refusing to overwrite"):
            create_verified_sqlite_backup(source_path, backup_path)
        assert backup_path.read_bytes() == original_backup
    finally:
        source.close()


def test_online_backup_includes_wal_committed_records(tmp_path: Path) -> None:
    source_path = tmp_path / "wal-source.db"
    with sqlite3.connect(source_path) as source:
        source.execute("PRAGMA journal_mode=WAL")
        source.execute("PRAGMA wal_autocheckpoint=0")
        source.execute("CREATE TABLE evidence (value TEXT)")
        source.execute("INSERT INTO evidence VALUES ('wal-record')")
        source.commit()

        backup = create_verified_sqlite_backup(source_path, tmp_path / "wal-copy.db")
        with sqlite3.connect(backup.path) as copied:
            assert copied.execute("SELECT value FROM evidence").fetchone() == (
                "wal-record",
            )


def test_backup_failure_prevents_cli_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import migrate_database as migration_cli

    path = tmp_path / "legacy-cli.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    before = path.read_bytes()

    def fail_backup(*_args: object, **_kwargs: object) -> object:
        raise SQLiteBackupError("simulated backup verification failure")

    monkeypatch.setattr(migration_cli, "create_verified_sqlite_backup", fail_backup)
    assert migration_cli.main([
        "--database", str(path), "--confirm-writers-stopped"
    ]) == 1
    assert "simulated backup verification failure" in capsys.readouterr().err
    assert path.read_bytes() == before
    with sqlite3.connect(path) as database:
        assert database.execute(
            "SELECT name FROM sqlite_master WHERE name='schema_migrations'"
        ).fetchone() is None


def test_explicit_migration_command_creates_verified_backup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import migrate_database as migration_cli

    path = tmp_path / "legacy-cli-success.db"
    backup_path = tmp_path / "legacy-cli-backup.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    assert migration_cli.main(
        ["--database", str(path), "--backup", str(backup_path),
         "--confirm-writers-stopped"]
    ) == 0
    output = capsys.readouterr().out
    assert "Verified backup:" in output
    assert "Migration complete; schema version 3." in output
    assert backup_path.is_file()
    assert Path(f"{backup_path}.sha256").is_file()
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    with sqlite3.connect(path) as migrated:
        assert migrated.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone() == (3,)


def test_fresh_database_schema_and_history_roll_back_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fresh.db"
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    original_create_all = Base.metadata.create_all

    def fail_after_schema_creation(*args: object, **kwargs: object) -> None:
        original_create_all(*args, **kwargs)
        raise RuntimeError("simulated fresh initialization failure")

    monkeypatch.setattr(Base.metadata, "create_all", fail_after_schema_creation)
    try:
        with pytest.raises(RuntimeError, match="simulated fresh initialization"):
            initialize_fresh_schema(engine)

        with engine.connect() as connection:
            assert inspect(connection).get_table_names() == []

        monkeypatch.setattr(Base.metadata, "create_all", original_create_all)
        initialize_fresh_schema(engine)
        with engine.connect() as connection:
            assert set(Base.metadata.tables).issubset(
                inspect(connection).get_table_names()
            )
            assert _migration_history(connection) == [
                (migration.version, migration.name)
                for migration in migrations._MIGRATIONS
            ]
    finally:
        engine.dispose()


def test_migration_cli_requires_human_writer_stop_acknowledgment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import migrate_database as migration_cli

    path = tmp_path / "writer-confirmation.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    before = path.read_bytes()
    assert migration_cli.main(["--database", str(path)]) == 2
    assert "does not detect other processes" in capsys.readouterr().err
    assert path.read_bytes() == before


def test_legacy_orphaned_rows_are_rejected_before_backup_or_migration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-orphan.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    with sqlite3.connect(path) as database:
        database.execute("PRAGMA foreign_keys=OFF")
        database.execute(
            "INSERT INTO assets (investigation_id, hostname, discovered_at) "
            "VALUES (999999, 'orphan.example.test', '2026-01-01 00:00:00')"
        )
    before = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        with pytest.raises(MigrationError, match="orphaned records"):
            preflight_migration(engine)
        assert path.read_bytes() == before
        with engine.connect() as connection:
            assert not inspect(connection).has_table("schema_migrations")
    finally:
        engine.dispose()


def test_migration_cli_rejects_orphan_before_backup_or_schema_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scripts import migrate_database as migration_cli

    path = tmp_path / "legacy-orphan-cli.db"
    backup_path = tmp_path / "must-not-be-created.db"
    _create_legacy_test_database(path)
    with sqlite3.connect(path) as database:
        database.execute(
            "INSERT INTO assets (investigation_id, hostname, discovered_at) "
            "VALUES (999999, 'orphan.example.test', '2026-01-01 00:00:00')"
        )
    before = path.read_bytes()

    def unexpected_backup(*_args: object, **_kwargs: object) -> object:
        pytest.fail("backup must not run after orphaned-source preflight fails")

    def unexpected_migration(*_args: object, **_kwargs: object) -> object:
        pytest.fail("migration must not run after orphaned-source preflight fails")

    monkeypatch.setattr(
        migration_cli, "create_verified_sqlite_backup", unexpected_backup
    )
    monkeypatch.setattr(migration_cli, "migrate_database", unexpected_migration)
    assert migration_cli.main(
        [
            "--database",
            str(path),
            "--backup",
            str(backup_path),
            "--confirm-writers-stopped",
        ]
    ) == 1
    assert "orphaned records" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert not backup_path.exists()
    with sqlite3.connect(path) as database:
        assert database.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='schema_migrations'"
        ).fetchone() is None


def test_migration_cli_rejects_legacy_orphan_before_backup_or_schema_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import migrate_database as migration_cli

    path = tmp_path / "legacy-orphan-cli.db"
    backup_path = tmp_path / "legacy-orphan-backup.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    with sqlite3.connect(path) as database:
        database.execute("PRAGMA foreign_keys=OFF")
        database.execute(
            "INSERT INTO assets (investigation_id, hostname, discovered_at) "
            "VALUES (999999, 'orphan.example.test', '2026-01-01 00:00:00')"
        )
    before = path.read_bytes()

    assert migration_cli.main(
        [
            "--database",
            str(path),
            "--backup",
            str(backup_path),
            "--confirm-writers-stopped",
        ]
    ) == 1

    assert "orphan" in capsys.readouterr().err.lower()
    assert path.read_bytes() == before
    assert not backup_path.exists()
    assert not Path(f"{backup_path}.sha256").exists()
    with sqlite3.connect(path) as database:
        assert database.execute(
            "SELECT name FROM sqlite_master WHERE name='schema_migrations'"
        ).fetchone() is None


def test_readiness_rejects_missing_sqlite_retention_trigger(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing-retention-trigger.db"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        initialize_fresh_database(engine)
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER retain_observations")

        with pytest.raises(DatabaseNotReadyError, match="retention triggers"):
            require_schema_ready(engine)
    finally:
        engine.dispose()


def test_post_migration_schema_validation_failure_rolls_back_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "post-validation-failure.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", path)
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    original_validate = migrations._validate_schema_contract

    def fail_version_two_validation(connection: Connection, version: int) -> None:
        if version == 2:
            raise MigrationError("simulated post-migration schema validation failure")
        original_validate(connection, version)

    monkeypatch.setattr(
        migrations, "_validate_schema_contract", fail_version_two_validation
    )
    try:
        with pytest.raises(MigrationError, match="changes were rolled back"):
            migrate_database(engine)

        with engine.connect() as connection:
            assert _migration_history(connection) == [(1, "investigation_budgets")]
            assert not inspect(connection).has_table("tasks")
            assert not inspect(connection).has_table(
                "hypothesis_supporting_observations"
            )
    finally:
        engine.dispose()


def test_preflight_rejects_malformed_optional_findings_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-incomplete-findings.db"
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    core_tables = [Base.metadata.tables[name] for name in (
        "programs", "investigations", "assets", "hypotheses", "observations"
    )]
    try:
        with engine.begin() as connection:
            Base.metadata.create_all(connection, tables=core_tables)
            connection.exec_driver_sql(
                "CREATE TABLE findings ("
                "id INTEGER NOT NULL PRIMARY KEY, hypothesis_id INTEGER NOT NULL, "
                "title VARCHAR(255) NOT NULL, category VARCHAR(64) NOT NULL, "
                "approved_by VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL, "
                "FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id) ON DELETE RESTRICT)"
            )
        before = path.read_bytes()
        with pytest.raises(MigrationError, match="unique constraint"):
            preflight_migration(engine)
        assert path.read_bytes() == before
        with engine.connect() as connection:
            assert not inspect(connection).has_table("schema_migrations")
            assert inspect(connection).has_table("findings")
    finally:
        engine.dispose()


def test_incorrect_migration_history_is_rejected_without_writing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "incorrect-history.db"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE schema_migrations SET name='incorrect' WHERE version=2"
        )
    engine.dispose()
    before = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        with pytest.raises(MigrationError, match="unexpected name"):
            preflight_migration(engine)
        assert path.read_bytes() == before
    finally:
        engine.dispose()


def test_history_cannot_claim_success_when_required_constraint_is_missing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "false-success-history.db"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    engine.dispose()
    with sqlite3.connect(path) as database:
        database.execute("PRAGMA foreign_keys=OFF")
        database.execute("DROP TABLE findings")
        database.execute(
            "CREATE TABLE findings ("
            "id INTEGER PRIMARY KEY, hypothesis_id INTEGER NOT NULL, "
            "title VARCHAR(255) NOT NULL, category VARCHAR(64) NOT NULL, "
            "approved_by VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL, "
            "FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id) ON DELETE RESTRICT)"
        )
    before = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    try:
        with pytest.raises(MigrationError, match="unique constraints"):
            preflight_migration(engine)
        assert path.read_bytes() == before
        with engine.connect() as connection:
            assert _migration_history(connection)[-1][0] == len(migrations._MIGRATIONS)
    finally:
        engine.dispose()


@pytest.mark.parametrize("database_name", ["lab_evidence.db", "lab_evidence_v3.db"])
def test_legacy_database_copy_migrates_without_changing_existing_rows(
    tmp_path: Path, database_name: str
) -> None:
    source = REPO_ROOT / database_name
    copied_database = tmp_path / database_name
    shutil.copy2(source, copied_database)
    original_snapshot = _database_snapshot(copied_database)

    engine = create_database_engine(f"sqlite+pysqlite:///{copied_database}")
    try:
        assert preflight_migration(engine) == 0
        migrate_database(engine)
        require_schema_ready(engine)
        inspector = inspect(engine)
        assert set(Base.metadata.tables).issubset(inspector.get_table_names())
        assert {
            column["name"]
            for column in inspector.get_columns("investigations")
        } >= {"max_tasks", "max_llm_calls"}
        migrated_snapshot = _database_snapshot(copied_database)
        for table_name, original_table in original_snapshot.items():
            migrated_table = migrated_snapshot[table_name]
            original_columns = original_table["columns"]
            assert set(original_columns).issubset(migrated_table["columns"])
            assert [
                {column: row[column] for column in original_columns}
                for row in migrated_table["rows"]
            ] == original_table["rows"]

        investigation_columns = migrated_snapshot["investigations"]["columns"]
        for budget_column in ("max_tasks", "max_llm_calls"):
            assert budget_column in investigation_columns
            assert all(
                row[budget_column] is None
                for row in migrated_snapshot["investigations"]["rows"]
            )

        with Session(engine) as session:
            session.scalars(select(Investigation).limit(1)).all()
    finally:
        engine.dispose()


def test_repeated_initialization_and_migration_are_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "idempotent.db"
    connection_string = f"sqlite+pysqlite:///{path}"
    engine = create_database_engine(connection_string)
    initialize_fresh_database(engine)
    try:
        with engine.connect() as connection:
            before = _migration_history(connection)
            table_names = set(inspect(connection).get_table_names())

        migrate_database(engine)
        engine.dispose()
        engine = create_database_engine(connection_string)
        require_schema_ready(engine)

        with engine.connect() as connection:
            assert _migration_history(connection) == before
            assert set(inspect(connection).get_table_names()) == table_names
    finally:
        engine.dispose()


def test_failed_migration_rolls_back_its_ddl_and_can_be_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied_database = tmp_path / "legacy.db"
    shutil.copy2(REPO_ROOT / "lab_evidence.db", copied_database)
    engine = create_database_engine(f"sqlite+pysqlite:///{copied_database}")
    original_migrations = migrations._MIGRATIONS

    def fail_after_ddl(connection: Connection) -> None:
        connection.exec_driver_sql("CREATE TABLE interrupted_migration (id INTEGER)")
        raise RuntimeError("simulated migration interruption")

    monkeypatch.setattr(
        migrations,
        "_MIGRATIONS",
        (
            original_migrations[0],
            migrations.Migration(
                2, original_migrations[1].name, fail_after_ddl
            ),
        ),
    )

    try:
        with pytest.raises(MigrationError, match="changes were rolled back"):
            migrate_database(engine)

        with engine.connect() as connection:
            assert _migration_history(connection) == [(1, "investigation_budgets")]
            assert not inspect(connection).has_table("interrupted_migration")
            assert {
                column["name"]
                for column in inspect(connection).get_columns("investigations")
            } >= {"max_tasks", "max_llm_calls"}

        monkeypatch.setattr(migrations, "_MIGRATIONS", original_migrations)
        migrate_database(engine)
        with engine.connect() as connection:
            assert _migration_history(connection) == [
                (migration.version, migration.name)
                for migration in original_migrations
            ]
            assert inspect(connection).has_table("hypothesis_supporting_observations")
            assert inspect(connection).has_table("observation_provenance")
    finally:
        engine.dispose()


def test_post_migration_schema_validation_failure_rolls_back_before_history_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "post-validation-rollback.db"
    _create_legacy_test_database(path)
    original_snapshot = _database_snapshot(path)
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    original_validator = migrations._validate_schema_contract

    def fail_after_migration_schema_check(
        connection: Connection, version: int
    ) -> None:
        original_validator(connection, version)
        if version == 1:
            raise MigrationError("simulated post-migration schema rejection")

    monkeypatch.setattr(
        migrations, "_validate_schema_contract", fail_after_migration_schema_check
    )
    try:
        with pytest.raises(MigrationError, match="changes were rolled back"):
            migrate_database(engine)

        assert _database_snapshot(path) == original_snapshot
        with engine.connect() as connection:
            assert not inspect(connection).has_table("schema_migrations")
            assert not {
                "max_tasks",
                "max_llm_calls",
            } & {
                column["name"]
                for column in inspect(connection).get_columns("investigations")
            }

        monkeypatch.setattr(
            migrations, "_validate_schema_contract", original_validator
        )
        migrate_database(engine)
        with engine.connect() as connection:
            assert _migration_history(connection)[0] == (1, "investigation_budgets")
    finally:
        engine.dispose()


def test_unversioned_database_with_incomplete_core_schema_is_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "incomplete.db"
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE investigations (id INTEGER PRIMARY KEY)")
    original_snapshot = _database_snapshot(path)

    engine = create_engine(f"sqlite+pysqlite:///{path}")
    try:
        with pytest.raises(MigrationError, match="missing required core tables"):
            migrate_database(engine)

        with engine.connect() as connection:
            assert not inspect(connection).has_table("schema_migrations")
            assert not inspect(connection).has_table("hypothesis_supporting_observations")
        assert _database_snapshot(path) == original_snapshot
    finally:
        engine.dispose()


def test_current_schema_keeps_existing_record_relationships_usable() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    try:
        with Session(engine) as session:
            program = Program(
                name="Example",
                authorized_scope=["example.test"],
                excluded_scope=[],
                rate_limit=1,
            )
            investigation = Investigation(program=program, status="running")
            asset = Asset(investigation=investigation, hostname="example.test")
            hypothesis = Hypothesis(
                asset=asset,
                category="access_control",
                description="Review access enforcement",
            )
            observation = Observation(
                asset=asset,
                observation_type="dns_record",
                data={"record_type": "A", "value": "192.0.2.1"},
            )
            session.add_all([program, hypothesis, observation])
            session.flush()
            session.add_all(
                [
                    HypothesisSupportingObservation(
                        hypothesis=hypothesis, observation=observation
                    ),
                    ObservationProvenance(
                        observation=observation,
                        collector="migration-test",
                        authorization_snapshot={"target": "example.test"},
                    ),
                ]
            )
            session.commit()

            assert session.scalar(select(HypothesisSupportingObservation)) is not None
            assert session.scalar(select(ObservationProvenance)) is not None
    finally:
        engine.dispose()
