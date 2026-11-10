"""Tests for SQLite referential integrity and retained investigation history."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, delete, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from data.db import (
    DatabaseIntegrityError,
    check_database_integrity,
    init_db,
)
from data.migrations import SQLITE_RETENTION_TRIGGERS, _install_sqlite_retention_triggers
from data.models import (
    Asset,
    Finding,
    HistoricalRecordIsImmutable,
    Hypothesis,
    HypothesisSupportingObservation,
    Investigation,
    Observation,
    ObservationProvenance,
    Program,
    PromotionAudit,
    Task,
    TaskEvent,
    TaskEventIsAppendOnly,
    Verdict,
)
from data.sqlite import enable_sqlite_foreign_keys


def _seed_records(session: Session) -> tuple[
    Program, Investigation, Asset, Hypothesis, Observation
]:
    program = Program(
        name="Integrity test",
        authorized_scope=["example.test"],
        excluded_scope=[],
        rate_limit=1,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="example.test")
    hypothesis = Hypothesis(
        asset=asset, category="access_control", description="Review access control"
    )
    observation = Observation(
        asset=asset,
        observation_type="dns_record",
        data={"record_type": "A", "value": "192.0.2.1"},
    )
    session.add_all([program, hypothesis, observation])
    session.flush()
    return program, investigation, asset, hypothesis, observation


def test_sqlite_foreign_keys_are_enabled_on_each_new_connection(
    tmp_path: Path,
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'foreign-keys.db'}")
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("PRAGMA foreign_keys")) == 1

        engine.dispose()
        with engine.connect() as connection:
            assert connection.scalar(text("PRAGMA foreign_keys")) == 1
    finally:
        engine.dispose()


def test_all_mapped_foreign_keys_restrict_parent_deletion() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    try:
        inspector = inspect(engine)
        for table_name in inspector.get_table_names():
            if table_name == "schema_migrations":
                continue
            for foreign_key in inspector.get_foreign_keys(table_name):
                assert foreign_key["options"].get("ondelete") == "RESTRICT"
    finally:
        engine.dispose()


def test_direct_sql_rejects_an_invalid_foreign_key(tmp_path: Path) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'direct-invalid-fk.db'}")
    try:
        with engine.begin() as connection:
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO investigations "
                        "(program_id, status, started_at) "
                        "VALUES (999, 'running', '2026-01-01 00:00:00')"
                    )
                )
    finally:
        engine.dispose()


def test_orm_rejects_an_invalid_foreign_key(tmp_path: Path) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'orm-invalid-fk.db'}")
    try:
        with Session(engine) as session:
            session.add(
                Investigation(
                    program_id=999,
                    status="running",
                    started_at=datetime(2026, 1, 1, tzinfo=UTC),
                )
            )
            with pytest.raises(IntegrityError):
                session.flush()
    finally:
        engine.dispose()


@pytest.mark.parametrize("delete_mode", ["orm", "sql"])
def test_investigation_deletion_cannot_remove_historical_observations(
    tmp_path: Path, delete_mode: str
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / f'investigation-{delete_mode}.db'}")
    try:
        with Session(engine) as session:
            _, investigation, _, _, observation = _seed_records(session)
            observation_id = observation.id
            investigation_id = investigation.id
            session.commit()

            if delete_mode == "orm":
                session.delete(investigation)
                with pytest.raises(IntegrityError):
                    session.flush()
            else:
                with pytest.raises(IntegrityError):
                    session.execute(
                        text("DELETE FROM investigations WHERE id = :id"),
                        {"id": investigation_id},
                    )

            session.rollback()
            assert session.get(Observation, observation_id) is not None
            assert session.get(Investigation, investigation_id) is not None
    finally:
        engine.dispose()


def test_observation_with_provenance_cannot_be_deleted(tmp_path: Path) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'provenance-retention.db'}")
    try:
        with Session(engine) as session:
            _, _, _, _, observation = _seed_records(session)
            observation_id = observation.id
            session.add(
                ObservationProvenance(
                    observation=observation,
                    collector="integrity-test",
                    authorization_snapshot={"target": "example.test"},
                )
            )
            session.commit()

            session.delete(observation)
            with pytest.raises(HistoricalRecordIsImmutable):
                session.flush()
            session.rollback()
            assert session.get(Observation, observation_id) is not None
            assert session.get(ObservationProvenance, observation_id) is not None
    finally:
        engine.dispose()


def test_observation_with_hypothesis_support_link_cannot_be_deleted(
    tmp_path: Path,
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'support-retention.db'}")
    try:
        with Session(engine) as session:
            _, _, _, hypothesis, observation = _seed_records(session)
            observation_id = observation.id
            link = HypothesisSupportingObservation(
                hypothesis=hypothesis, observation=observation
            )
            session.add(link)
            session.commit()

            session.delete(observation)
            with pytest.raises(HistoricalRecordIsImmutable):
                session.flush()
            session.rollback()
            assert session.get(Observation, observation_id) is not None
            assert session.scalar(select(HypothesisSupportingObservation)) is not None
    finally:
        engine.dispose()


def test_hypothesis_with_support_link_cannot_be_deleted(tmp_path: Path) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'hypothesis-retention.db'}")
    try:
        with Session(engine) as session:
            _, _, _, hypothesis, observation = _seed_records(session)
            hypothesis_id = hypothesis.id
            session.add(
                HypothesisSupportingObservation(
                    hypothesis=hypothesis, observation=observation
                )
            )
            session.commit()

            session.delete(hypothesis)
            with pytest.raises(IntegrityError):
                session.flush()
            session.rollback()
            assert session.get(Hypothesis, hypothesis_id) is not None
            assert session.scalar(select(HypothesisSupportingObservation)) is not None
    finally:
        engine.dispose()


def test_task_with_append_only_event_cannot_be_deleted(tmp_path: Path) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'task-event-retention.db'}")
    try:
        with Session(engine) as session:
            _, investigation, _, _, _ = _seed_records(session)
            task = Task(
                investigation=investigation, kind="review", title="Review evidence"
            )
            event = TaskEvent(task=task, event_type="created", detail={})
            session.add(task)
            session.flush()
            task_id = task.id
            event_id = event.id
            session.commit()

            session.delete(task)
            with pytest.raises(IntegrityError):
                session.flush()
            session.rollback()
            assert session.get(Task, task_id) is not None
            assert session.get(TaskEvent, event_id) is not None
    finally:
        engine.dispose()


def test_hypothesis_and_finding_deletion_preserves_promotion_audit(
    tmp_path: Path,
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'promotion-audit.db'}")
    try:
        with Session(engine) as session:
            _, _, _, hypothesis, _ = _seed_records(session)
            finding = Finding(
                hypothesis=hypothesis,
                title="Verified finding",
                category=hypothesis.category,
                approved_by="Reviewer",
            )
            session.add(finding)
            session.flush()
            audit = PromotionAudit(
                action="promoted",
                actor="Reviewer",
                hypothesis_id=hypothesis.id,
                finding_id=finding.id,
                evidence_ids=[],
                verdict_ids=[],
            )
            session.add(audit)
            session.flush()
            finding_id = finding.id
            hypothesis_id = hypothesis.id
            audit_id = audit.id
            session.commit()

            session.delete(finding)
            with pytest.raises(HistoricalRecordIsImmutable):
                session.flush()
            session.rollback()
            assert session.get(Finding, finding_id) is not None

            session.delete(session.get(Hypothesis, hypothesis_id))
            with pytest.raises(IntegrityError):
                session.flush()
            session.rollback()
            assert session.get(PromotionAudit, audit_id) is not None
    finally:
        engine.dispose()


def test_integrity_check_reports_existing_orphans_without_rewriting_them(
    tmp_path: Path,
) -> None:
    path = tmp_path / "preexisting-orphan.db"
    engine = init_db(f"sqlite+pysqlite:///{path}")
    engine.dispose()

    with sqlite3.connect(path) as database:
        database.execute("PRAGMA foreign_keys=OFF")
        database.execute(
            "INSERT INTO observations "
            "(asset_id, hypothesis_id, observation_type, data, created_at) "
            "VALUES (999, NULL, 'dns_record', '{}', '2026-01-01 00:00:00')"
        )

    try:
        with pytest.raises(DatabaseIntegrityError, match="foreign-key violations"):
            check_database_integrity(engine)
        with sqlite3.connect(path) as database:
            assert database.execute(
                "SELECT COUNT(*) FROM observations WHERE asset_id = 999"
            ).fetchone()[0] == 1
    finally:
        engine.dispose()


_RETAINED_RECORDS = {
    "observations": (Observation, "id"),
    "observation_provenance": (ObservationProvenance, "observation_id"),
    "hypothesis_supporting_observations": (
        HypothesisSupportingObservation,
        "id",
    ),
    "verdicts": (Verdict, "id"),
    "findings": (Finding, "id"),
    "task_events": (TaskEvent, "id"),
    "promotion_audit": (PromotionAudit, "id"),
}


def _seed_standalone_record(session: Session, table_name: str) -> int:
    program, investigation, asset, hypothesis, observation = _seed_records(session)
    if table_name == "observations":
        record = observation
    elif table_name == "observation_provenance":
        record = ObservationProvenance(
            observation=observation,
            collector="integrity-test",
            authorization_snapshot={"target": "example.test"},
        )
    elif table_name == "hypothesis_supporting_observations":
        record = HypothesisSupportingObservation(
            hypothesis=hypothesis, observation=observation
        )
    elif table_name == "verdicts":
        record = Verdict(
            hypothesis=hypothesis,
            observation=observation,
            claim_type="test",
            is_control=False,
            verdict="inconclusive",
            rationale="test record",
            integrity_digest="0" * 64,
        )
    elif table_name == "findings":
        record = Finding(
            hypothesis=hypothesis,
            title="Retained finding",
            category=hypothesis.category,
            approved_by="Reviewer",
        )
    elif table_name == "task_events":
        task = Task(
            investigation=investigation, kind="review", title="Review evidence"
        )
        session.add(task)
        session.flush()
        record = TaskEvent(task=task, event_type="created", detail={})
    else:
        record = PromotionAudit(
            action="promoted",
            actor="Reviewer",
            hypothesis_id=hypothesis.id,
            finding_id=None,
            evidence_ids=[],
            verdict_ids=[],
        )
    session.add(record)
    session.flush()
    return getattr(record, _RETAINED_RECORDS[table_name][1])


@pytest.mark.parametrize("table_name", sorted(_RETAINED_RECORDS))
def test_orm_delete_rejects_each_standalone_historical_record(
    tmp_path: Path, table_name: str
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / f'orm-retention-{table_name}.db'}")
    model, primary_key = _RETAINED_RECORDS[table_name]
    try:
        with Session(engine) as session:
            record_id = _seed_standalone_record(session, table_name)
            session.commit()
            session.delete(session.get(model, record_id))
            expected_error = (
                TaskEventIsAppendOnly
                if model is TaskEvent
                else HistoricalRecordIsImmutable
            )
            with pytest.raises(expected_error):
                session.flush()
            session.rollback()
            assert session.get(model, record_id) is not None
    finally:
        engine.dispose()


@pytest.mark.parametrize("table_name", sorted(_RETAINED_RECORDS))
def test_orm_bulk_delete_rejects_each_standalone_historical_record(
    tmp_path: Path, table_name: str
) -> None:
    engine = init_db(
        f"sqlite+pysqlite:///{tmp_path / f'orm-bulk-retention-{table_name}.db'}"
    )
    model, primary_key = _RETAINED_RECORDS[table_name]
    try:
        with Session(engine) as session:
            record_id = _seed_standalone_record(session, table_name)
            session.commit()
            statement = delete(model).where(getattr(model, primary_key) == record_id)
            expected_error = (
                TaskEventIsAppendOnly
                if model is TaskEvent
                else HistoricalRecordIsImmutable
            )
            with pytest.raises(expected_error):
                session.execute(statement)
            session.rollback()
            assert session.get(model, record_id) is not None
    finally:
        engine.dispose()


@pytest.mark.parametrize("table_name", sorted(_RETAINED_RECORDS))
def test_direct_sql_delete_rejects_each_standalone_historical_record(
    tmp_path: Path, table_name: str
) -> None:
    engine = init_db(
        f"sqlite+pysqlite:///{tmp_path / f'sql-retention-{table_name}.db'}"
    )
    model, primary_key = _RETAINED_RECORDS[table_name]
    try:
        with Session(engine) as session:
            record_id = _seed_standalone_record(session, table_name)
            session.commit()

        with engine.begin() as connection:
            with pytest.raises(IntegrityError, match="historical record retention"):
                connection.execute(
                    text(
                        f'DELETE FROM "{table_name}" '
                        f'WHERE "{primary_key}" = :record_id'
                    ),
                    {"record_id": record_id},
                )
        with Session(engine) as session:
            assert session.get(model, record_id) is not None
    finally:
        engine.dispose()


def test_fresh_database_installs_all_retention_triggers(tmp_path: Path) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'fresh-retention.db'}")
    try:
        with engine.connect() as connection:
            triggers = {
                name: table_name
                for name, table_name in connection.exec_driver_sql(
                    "SELECT name, tbl_name FROM sqlite_master WHERE type='trigger'"
                )
            }
        assert triggers == SQLITE_RETENTION_TRIGGERS
    finally:
        engine.dispose()


@pytest.mark.parametrize("database_name", ["lab_evidence.db", "lab_evidence_v3.db"])
def test_legacy_copy_migration_installs_retention_triggers(
    tmp_path: Path, database_name: str
) -> None:
    import shutil

    from data.migrations import migrate_database

    source = Path(__file__).resolve().parent.parent / database_name
    copied = tmp_path / database_name
    shutil.copy2(source, copied)
    engine = create_engine(f"sqlite+pysqlite:///{copied}")
    try:
        migrate_database(engine)
        with engine.connect() as connection:
            triggers = {
                name: table_name
                for name, table_name in connection.exec_driver_sql(
                    "SELECT name, tbl_name FROM sqlite_master WHERE type='trigger'"
                )
            }
        assert triggers == SQLITE_RETENTION_TRIGGERS
    finally:
        engine.dispose()


def test_migration_rerun_does_not_duplicate_retention_triggers(
    tmp_path: Path,
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'repeat-retention.db'}")
    try:
        with engine.connect() as connection:
            before = list(
                connection.exec_driver_sql(
                    "SELECT name, tbl_name, sql FROM sqlite_master "
                    "WHERE type='trigger' ORDER BY name"
                )
            )
        from data.migrations import migrate_database

        migrate_database(engine)
        with engine.connect() as connection:
            after = list(
                connection.exec_driver_sql(
                    "SELECT name, tbl_name, sql FROM sqlite_master "
                    "WHERE type='trigger' ORDER BY name"
                )
            )
        assert after == before
    finally:
        engine.dispose()


def test_integrity_check_detects_missing_trigger_without_repairing_it(
    tmp_path: Path,
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'missing-trigger.db'}")
    missing_trigger = next(iter(SQLITE_RETENTION_TRIGGERS))
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(f'DROP TRIGGER "{missing_trigger}"')
        with pytest.raises(DatabaseIntegrityError, match="retention triggers"):
            check_database_integrity(engine)
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=:name",
                {"name": missing_trigger},
            ).first() is None
    finally:
        engine.dispose()


def test_integrity_check_detects_ineffective_trigger_without_repairing_it(
    tmp_path: Path,
) -> None:
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'altered-trigger.db'}")
    trigger_name = "retain_observations"
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(f'DROP TRIGGER "{trigger_name}"')
            connection.exec_driver_sql(
                f"""
                CREATE TRIGGER "{trigger_name}"
                BEFORE DELETE ON observations
                WHEN 0
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'historical record retention: permanent deletion is prohibited'
                    );
                END
                """
            )

        with pytest.raises(DatabaseIntegrityError, match="retention triggers"):
            check_database_integrity(engine)

        with engine.connect() as connection:
            trigger_sql = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type='trigger' AND name=:name",
                {"name": trigger_name},
            ).scalar_one()
            assert "WHEN 0" in trigger_sql
    finally:
        engine.dispose()


def test_retention_trigger_aborts_indirect_cascade(tmp_path: Path) -> None:
    engine = enable_sqlite_foreign_keys(
        create_engine(f"sqlite+pysqlite:///{tmp_path / 'cascade-trigger.db'}")
    )
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE cascade_parent (id INTEGER PRIMARY KEY)")
            connection.exec_driver_sql(
                "CREATE TABLE observations ("
                "id INTEGER PRIMARY KEY, "
                "parent_id INTEGER REFERENCES cascade_parent(id) ON DELETE CASCADE)"
            )
            for table_name in SQLITE_RETENTION_TRIGGERS.values():
                if table_name != "observations":
                    connection.exec_driver_sql(
                        f'CREATE TABLE "{table_name}" (id INTEGER PRIMARY KEY)'
                    )
            _install_sqlite_retention_triggers(connection)
            connection.exec_driver_sql("INSERT INTO cascade_parent (id) VALUES (1)")
            connection.exec_driver_sql(
                "INSERT INTO observations (id, parent_id) VALUES (1, 1)"
            )

        with engine.begin() as connection:
            with pytest.raises(IntegrityError, match="historical record retention"):
                connection.exec_driver_sql("DELETE FROM cascade_parent WHERE id = 1")
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT id FROM observations WHERE id = 1"
            ).first() is not None
    finally:
        engine.dispose()
