"""Tests for the read-only operator status board.

``orchestration/status_board.py`` is a pure, read-only view over what is
already stored: ``list_investigations`` summarizes every investigation,
``get_investigation_status`` returns one investigation's tasks, stuck tasks,
budget remaining, hypothesis counts, and findings, and ``find_stuck_tasks``
lists overrun running tasks across all investigations. Stuck detection uses the
same rule as ``verification.task_recovery.find_stuck_tasks``. The tests assert
the counts and budgets, that the library never commits, and - in the source -
that neither the library nor ``scripts/investigation_status.py`` can commit,
promote, or run a task.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import scripts.investigation_status as status_script
from data.db import init_db
from data.models import (
    Asset,
    Finding,
    Hypothesis,
    HypothesisSupportingObservation,
    Investigation,
    Observation,
    ObservationProvenance,
    Program,
)
from orchestration.status_board import (
    find_stuck_tasks,
    get_investigation_status,
    get_researcher_dashboard,
    list_investigations,
)
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import (
    MAX_LLM_CALLS_PER_INVESTIGATION,
    MAX_TASKS_PER_INVESTIGATION,
    complete_task,
    create_task,
    start_task,
)
from verification.task_recovery import find_stuck_tasks as recovery_find_stuck_tasks

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "orchestration" / "status_board.py"
SCRIPT_PATH = REPO_ROOT / "scripts" / "investigation_status.py"


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


@pytest.fixture()
def investigation(session: Session) -> Investigation:
    program = Program(
        name="Example Program",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    session.add(program)
    session.flush()
    return start_investigation(program.id, session)


def seed_asset(
    session: Session, investigation: Investigation, hostname: str = "example.test"
) -> Asset:
    asset = Asset(investigation_id=investigation.id, hostname=hostname)
    session.add(asset)
    session.flush()
    return asset


def seed_hypothesis(session: Session, asset: Asset, status: str = "unverified") -> Hypothesis:
    hypothesis = Hypothesis(
        asset_id=asset.id, category="authz", description="desc", status=status
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis


# --- list_investigations ----------------------------------------------------


def test_list_investigations_reports_statuses_and_task_counts(
    session: Session, investigation: Investigation
) -> None:
    create_task(investigation.id, session, kind="recon", title="pending")
    running = create_task(investigation.id, session, kind="recon", title="running")
    start_task(running.id, session)
    done = create_task(investigation.id, session, kind="recon", title="done")
    start_task(done.id, session)
    complete_task(done.id, session, final_status="completed")

    [summary] = list_investigations(session)

    assert summary.investigation_id == investigation.id
    assert summary.status == "running"
    assert summary.max_tasks is None
    assert summary.max_llm_calls is None
    assert summary.total_tasks == 3
    assert summary.task_counts == {"pending": 1, "running": 1, "completed": 1}


def test_list_investigations_includes_investigations_without_tasks(
    session: Session, investigation: Investigation
) -> None:
    other = start_investigation(investigation.program_id, session)

    summaries = list_investigations(session)

    assert [summary.investigation_id for summary in summaries] == [
        investigation.id,
        other.id,
    ]
    assert summaries[0].total_tasks == 0
    assert summaries[0].task_counts == {}


# --- get_investigation_status -----------------------------------------------


def test_get_investigation_status_counts_tasks_hypotheses_and_findings(
    session: Session, investigation: Investigation
) -> None:
    asset = seed_asset(session, investigation)
    seed_hypothesis(session, asset, status="unverified")
    confirmed = seed_hypothesis(session, asset, status="confirmed")
    session.add(
        Finding(
            hypothesis_id=confirmed.id,
            title="confirmed finding",
            category="authz",
            approved_by="Ada",
        )
    )
    session.flush()

    board = get_investigation_status(session, investigation.id)

    assert board.investigation_id == investigation.id
    assert board.status == "running"
    assert board.tasks == []
    assert board.stuck_tasks == []
    assert board.hypothesis_counts == {"unverified": 1, "confirmed": 1}
    assert board.findings == 1
    assert board.budget.tasks_remaining == MAX_TASKS_PER_INVESTIGATION
    assert board.budget.llm_calls_remaining == MAX_LLM_CALLS_PER_INVESTIGATION


def test_get_investigation_status_detects_stuck_tasks(
    session: Session, investigation: Investigation
) -> None:
    stuck = create_task(investigation.id, session, kind="recon", title="stuck")
    start_task(stuck.id, session)
    stuck.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    fresh = create_task(investigation.id, session, kind="recon", title="fresh")
    start_task(fresh.id, session)

    board = get_investigation_status(
        session, investigation.id, threshold_seconds=3600
    )

    assert [task.task_id for task in board.stuck_tasks] == [stuck.id]
    assert {task.task_id for task in board.tasks} == {stuck.id, fresh.id}


def test_get_investigation_status_budget_remaining_uses_overrides(
    session: Session, investigation: Investigation
) -> None:
    asset = seed_asset(session, investigation)
    investigation.max_tasks = 5
    investigation.max_llm_calls = 3
    session.flush()

    create_task(investigation.id, session, kind="recon", title="recon")
    llm = create_task(
        investigation.id,
        session,
        kind="hypothesis_generation",
        title="gen",
        params={"asset_id": asset.id},
    )
    start_task(llm.id, session)
    complete_task(llm.id, session, final_status="completed")

    board = get_investigation_status(session, investigation.id)

    assert board.max_tasks == 5
    assert board.max_llm_calls == 3
    assert board.budget.tasks_remaining == 3
    assert board.budget.llm_calls_remaining == 2


def test_get_investigation_status_rejects_a_missing_investigation(
    session: Session,
) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        get_investigation_status(session, 4242)


# --- find_stuck_tasks -------------------------------------------------------


def test_find_stuck_tasks_scans_all_investigations(
    session: Session, investigation: Investigation
) -> None:
    other = start_investigation(investigation.program_id, session)

    first = create_task(investigation.id, session, kind="recon", title="first")
    start_task(first.id, session)
    first.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    second = create_task(other.id, session, kind="recon", title="second")
    start_task(second.id, session)
    second.started_at = datetime.now(UTC) - timedelta(hours=3)
    session.flush()

    fresh = create_task(investigation.id, session, kind="recon", title="fresh")
    start_task(fresh.id, session)

    stuck = find_stuck_tasks(session, threshold_seconds=3600)

    assert [(entry.investigation_id, entry.task.task_id) for entry in stuck] == [
        (investigation.id, first.id),
        (other.id, second.id),
    ]


def test_find_stuck_tasks_rejects_a_negative_threshold(session: Session) -> None:
    with pytest.raises(ValueError, match="threshold_seconds"):
        find_stuck_tasks(session, threshold_seconds=-1)


def test_board_stuck_detection_agrees_with_the_recovery_module(
    session: Session, investigation: Investigation
) -> None:
    stuck = create_task(investigation.id, session, kind="recon", title="stuck")
    start_task(stuck.id, session)
    stuck.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    board = get_investigation_status(session, investigation.id, threshold_seconds=3600)
    recovery = recovery_find_stuck_tasks(
        investigation.id, session, running_longer_than_seconds=3600
    )

    assert [task.task_id for task in board.stuck_tasks] == [stuck.id]
    assert [task.id for task in recovery] == [stuck.id]


# --- no commit / source guards ----------------------------------------------


def test_status_board_functions_never_commit(
    session: Session, investigation: Investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse() -> None:
        raise AssertionError("the status board library must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    list_investigations(session)
    get_investigation_status(session, investigation.id)
    find_stuck_tasks(session, threshold_seconds=3600)


def test_status_board_module_is_read_only() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    assert ".commit(" not in source
    assert re.search(r"hypothesis\.status\s*=(?!=)", source) is None
    assert re.search(r"\btask\.(status|started_at|ended_at)\s*=(?!=)", source) is None
    assert re.search(r"\binvestigation\.status\s*=(?!=)", source) is None
    assert "finding_promotion" not in source
    assert "promote_to_finding" not in source
    assert "run_task" not in source
    assert "plan_next_tasks" not in source
    assert "from gateway" not in source
    assert "import requests" not in source


def test_status_script_has_no_promotion_or_run_path() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    for forbidden in (
        "promote_to_finding",
        "finding_promotion",
        "run_task",
        "plan_next_tasks",
        "mark_task_failed_after_crash",
        "create_retry_task",
        ".commit(",
    ):
        assert forbidden not in source, forbidden

    assert "mode=ro" in source
    assert "orchestration.status_board" in source


def test_status_script_read_only_engine_refuses_a_missing_database(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit, match="does not exist"):
        status_script.read_only_engine(tmp_path / "nope.db")


def test_status_script_read_only_engine_opens_an_existing_database_read_only(
    tmp_path: Path,
) -> None:
    db = tmp_path / "existing.db"
    seed = create_engine(f"sqlite+pysqlite:///{db}")
    with Session(seed) as session:
        session.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY)"))
        session.commit()
    seed.dispose()

    engine = status_script.read_only_engine(db)
    with Session(engine) as session:
        assert session.execute(text("SELECT 1")).scalar() == 1
        with pytest.raises(OperationalError, match="readonly"):
            session.execute(text("INSERT INTO t (id) VALUES (2)"))
    engine.dispose()


def test_get_researcher_dashboard_reports_asset_and_evidence_counts(
    session: Session,
    investigation: Investigation,
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    observation = Observation(
        asset_id=asset.id,
        observation_type="endpoint_inventory",
        data={"url": "https://api.example.test/", "status_code": 403},
    )
    session.add(observation)
    session.flush()
    hypothesis = Hypothesis(
        asset_id=asset.id,
        category="access_control_review",
        description="Review access policy",
        status="verified",
    )
    session.add(hypothesis)
    session.flush()
    session.add(
        Finding(
            hypothesis_id=hypothesis.id,
            title="Review item",
            category="access_control_review",
            approved_by="Ada",
        )
    )
    session.flush()

    dashboard = get_researcher_dashboard(session, investigation.id)

    assert dashboard.assets == 1
    assert dashboard.observations == 1
    assert dashboard.hypotheses == 1
    assert dashboard.findings == 1
    assert asset.id in dashboard.observation_groups
    assert dashboard.observation_groups[asset.id][0].observation_id == observation.id
    assert dashboard.hypotheses_by_asset[asset.id][0].hypothesis_id == hypothesis.id
    assert dashboard.health_indicators["status"] == "running"
    summary = dashboard.hypotheses_by_asset[asset.id][0]
    assert summary.evidence_interpretation.startswith("Human-approved Finding")
    assert summary.confidence is None
    assert summary.impact is None
    assert summary.supporting_observation_ids == ()
    assert summary.evidence_missing is True
    assert summary.recommended_next_step


def test_get_researcher_dashboard_handles_missing_support_links_and_empty_investigations(
    session: Session,
    investigation: Investigation,
) -> None:
    dashboard = get_researcher_dashboard(session, investigation.id)

    assert dashboard.assets == 0
    assert dashboard.observations == 0
    assert dashboard.hypotheses == 0
    assert dashboard.findings == 0
    assert dashboard.observation_groups == {}
    assert dashboard.hypotheses_by_asset == {}
    assert dashboard.health_indicators["evidence_traceability"] == "empty"


def test_get_researcher_dashboard_includes_provenance_and_linked_support(
    session: Session,
    investigation: Investigation,
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    observation = Observation(
        asset_id=asset.id,
        observation_type="dns_record",
        data={"record_type": "TXT", "value": "do-not-display"},
    )
    session.add(observation)
    session.flush()
    session.add(
        ObservationProvenance(
            observation_id=observation.id,
            collector="passive-dns",
            captured_at=datetime.now(UTC),
            authorization_snapshot={"target": "api.example.test"},
        )
    )
    hypothesis = seed_hypothesis(session, asset)
    session.add(
        HypothesisSupportingObservation(
            hypothesis_id=hypothesis.id,
            observation_id=observation.id,
        )
    )
    session.flush()

    dashboard = get_researcher_dashboard(session, investigation.id)
    observation_summary = dashboard.observation_groups[asset.id][0]
    hypothesis_summary = dashboard.hypotheses_by_asset[asset.id][0]

    assert observation_summary.provenance_collector == "passive-dns"
    assert observation_summary.captured_at is not None
    assert "do-not-display" not in observation_summary.summary
    assert "value omitted" in observation_summary.summary
    assert "not a vulnerability verdict" in observation_summary.evidence_interpretation
    assert hypothesis_summary.supporting_observation_ids == (observation.id,)
    assert hypothesis_summary.evidence_missing is False
    assert hypothesis_summary.finding_id is None
    assert hypothesis_summary.priority == "review order 1"
    assert "not a severity" in (hypothesis_summary.priority_reason or "")


def test_researcher_dashboard_keeps_duplicate_hostnames_separate(
    session: Session,
    investigation: Investigation,
) -> None:
    first_asset = seed_asset(
        session, investigation, hostname="shared.example.test"
    )
    second_asset = seed_asset(
        session, investigation, hostname="shared.example.test"
    )
    first_observation = Observation(
        asset_id=first_asset.id,
        observation_type="dns_record",
        data={"record_type": "A", "value": "192.0.2.1"},
    )
    second_observation = Observation(
        asset_id=second_asset.id,
        observation_type="endpoint_inventory",
        data={"url": "https://shared.example.test/", "status_code": 200},
    )
    session.add_all([first_observation, second_observation])
    session.flush()
    first_hypothesis = seed_hypothesis(session, first_asset)
    second_hypothesis = seed_hypothesis(session, second_asset)
    session.add_all(
        [
            HypothesisSupportingObservation(
                hypothesis_id=first_hypothesis.id,
                observation_id=first_observation.id,
            ),
            HypothesisSupportingObservation(
                hypothesis_id=first_hypothesis.id,
                observation_id=second_observation.id,
            ),
            HypothesisSupportingObservation(
                hypothesis_id=second_hypothesis.id,
                observation_id=second_observation.id,
            ),
        ]
    )
    session.flush()

    dashboard = get_researcher_dashboard(session, investigation.id)

    assert set(dashboard.observation_groups) == {first_asset.id, second_asset.id}
    assert [
        item.observation_id
        for item in dashboard.observation_groups[first_asset.id]
    ] == [first_observation.id]
    assert [
        item.observation_id
        for item in dashboard.observation_groups[second_asset.id]
    ] == [second_observation.id]
    first_summary = dashboard.hypotheses_by_asset[first_asset.id][0]
    second_summary = dashboard.hypotheses_by_asset[second_asset.id][0]
    assert first_summary.hypothesis_id == first_hypothesis.id
    assert first_summary.supporting_observation_ids == (first_observation.id,)
    assert first_summary.unavailable_support_count == 1
    assert second_summary.hypothesis_id == second_hypothesis.id
    assert second_summary.supporting_observation_ids == (second_observation.id,)


def test_get_researcher_dashboard_tolerates_legacy_missing_optional_tables(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'legacy-dashboard.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE investigations "
                "(id INTEGER PRIMARY KEY, status VARCHAR(32) NOT NULL)"
            )
        )
        connection.execute(
            text("INSERT INTO investigations (id, status) VALUES (7, 'running')")
        )
    with Session(engine) as legacy_session:
        dashboard = get_researcher_dashboard(legacy_session, 7)
        status_script._print_researcher_dashboard(dashboard)
    output = capsys.readouterr().out
    engine.dispose()

    assert dashboard.status == "running"
    assert dashboard.max_tasks is None
    assert dashboard.max_llm_calls is None
    assert dashboard.assets is None
    assert dashboard.observations is None
    assert dashboard.hypotheses is None
    assert dashboard.asset_hostnames is None
    assert dashboard.observation_groups is None
    assert dashboard.hypotheses_by_asset is None
    assert dashboard.data_availability["assets"].startswith("unavailable")
    assert dashboard.data_availability["observations"].startswith("unavailable")
    assert "observations=unavailable" in output
    assert "observations: unavailable" in output
    assert "observations: none stored" not in output


def test_researcher_dashboard_reports_incomplete_legacy_tables_as_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'incomplete-dashboard.db'}"
    )
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE investigations "
                "(id INTEGER PRIMARY KEY, status VARCHAR(32) NOT NULL)"
            )
        )
        connection.execute(
            text("INSERT INTO investigations (id, status) VALUES (9, 'running')")
        )
        connection.execute(
            text(
                "CREATE TABLE assets "
                "(id INTEGER PRIMARY KEY, investigation_id INTEGER NOT NULL, "
                "hostname VARCHAR(253) NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO assets (id, investigation_id, hostname) "
                "VALUES (3, 9, 'legacy.example.test')"
            )
        )
        connection.execute(
            text("CREATE TABLE observations (id INTEGER PRIMARY KEY, asset_id INTEGER)")
        )
        connection.execute(
            text("CREATE TABLE hypotheses (id INTEGER PRIMARY KEY, asset_id INTEGER)")
        )
        connection.execute(
            text(
                "CREATE TABLE observation_provenance "
                "(observation_id INTEGER PRIMARY KEY)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE hypothesis_supporting_observations "
                "(hypothesis_id INTEGER PRIMARY KEY)"
            )
        )
        connection.execute(
            text("CREATE TABLE findings (id INTEGER PRIMARY KEY)")
        )

    with Session(engine) as legacy_session:
        dashboard = get_researcher_dashboard(legacy_session, 9)
        status_script._print_researcher_dashboard(dashboard)
    output = capsys.readouterr().out
    engine.dispose()

    assert dashboard.assets == 1
    assert dashboard.observations is None
    assert dashboard.hypotheses is None
    assert dashboard.findings is None
    assert dashboard.observation_groups is None
    assert dashboard.hypotheses_by_asset is None
    assert dashboard.data_availability["assets"] == "available"
    assert "missing required columns" in dashboard.data_availability["observations"]
    assert "missing required columns" in dashboard.data_availability["provenance"]
    assert "missing required columns" in dashboard.data_availability["support"]
    assert "observations=unavailable" in output
    assert "assets: available" in output
    assert "observations: none stored" not in output


def test_researcher_dashboard_does_not_flush_or_change_pending_session_state(
    session: Session,
    investigation: Investigation,
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    observation = Observation(
        asset_id=asset.id,
        observation_type="dns_record",
        data={"record_type": "A", "value": "192.0.2.20"},
    )
    session.add(observation)
    session.flush()
    investigation_id = investigation.id
    session.commit()

    asset.hostname = "pending.example.test"
    pending_hypothesis = Hypothesis(
        asset_id=asset.id,
        category="pending",
        description="must not be flushed",
    )
    session.add(pending_hypothesis)
    session.delete(observation)

    def database_snapshot() -> tuple[tuple[str, tuple[tuple[Any, ...], ...]], ...]:
        connection = session.connection()
        table_names = inspect(connection).get_table_names()
        return tuple(
            (
                table_name,
                tuple(
                    tuple(row)
                    for row in connection.exec_driver_sql(
                        f'SELECT * FROM "{table_name}"'
                    ).fetchall()
                ),
            )
            for table_name in sorted(table_names)
        )

    before_database = database_snapshot()
    before_new = frozenset(id(item) for item in session.new)
    before_dirty = frozenset(id(item) for item in session.dirty)
    before_deleted = frozenset(id(item) for item in session.deleted)

    dashboard = get_researcher_dashboard(session, investigation_id)

    assert dashboard.observations == 1
    assert dashboard.hypotheses == 0
    assert database_snapshot() == before_database
    assert frozenset(id(item) for item in session.new) == before_new
    assert frozenset(id(item) for item in session.dirty) == before_dirty
    assert frozenset(id(item) for item in session.deleted) == before_deleted
    assert pending_hypothesis.id is None
    assert asset.hostname == "pending.example.test"
    assert observation in session.deleted


def test_researcher_dashboard_rendering_does_not_mutate_database(
    session: Session,
    investigation: Investigation,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    observation = Observation(
        asset_id=asset.id,
        observation_type="endpoint_inventory",
        data={
            "url": "https://api.example.test/",
            "status_code": 403,
            "body": "must not appear",
        },
    )
    session.add(observation)
    session.flush()
    hypothesis = seed_hypothesis(session, asset)
    session.add(
        HypothesisSupportingObservation(
            hypothesis_id=hypothesis.id,
            observation_id=observation.id,
        )
    )
    session.commit()

    def database_snapshot() -> tuple[tuple[str, tuple[tuple[Any, ...], ...]], ...]:
        connection = session.connection()
        table_names = inspect(connection).get_table_names()
        return tuple(
            (
                table_name,
                tuple(
                    tuple(row)
                    for row in connection.exec_driver_sql(
                        f'SELECT * FROM "{table_name}"'
                    ).fetchall()
                ),
            )
            for table_name in sorted(table_names)
        )

    before = database_snapshot()
    dashboard = get_researcher_dashboard(session, investigation.id)
    status_script._print_researcher_dashboard(dashboard)
    output = capsys.readouterr().out
    after = database_snapshot()

    assert after == before
    assert not session.new
    assert not session.dirty
    assert not session.deleted
    assert f"#{observation.id}" in output
    assert "supporting observation IDs (context only)" in output
    assert "not a verified vulnerability" in output
    assert "requires confirmed authorization" in output
    assert "must not appear" not in output


def test_researcher_dashboard_cli_is_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "researcher-dashboard.db"
    engine = init_db(f"sqlite+pysqlite:///{db_path}")
    with Session(engine) as seed_session:
        program = Program(
            name="Example Program",
            authorized_scope=["*.example.test"],
            excluded_scope=[],
            rate_limit=30,
        )
        seed_session.add(program)
        seed_session.flush()
        investigation = start_investigation(program.id, seed_session)
        asset = seed_asset(
            seed_session, investigation, hostname="api.example.test"
        )
        observation = Observation(
            asset_id=asset.id,
            observation_type="endpoint_inventory",
            data={"url": "https://api.example.test/", "status_code": 200},
        )
        seed_session.add(observation)
        seed_session.flush()
        hypothesis = seed_hypothesis(seed_session, asset)
        seed_session.add(
            HypothesisSupportingObservation(
                hypothesis_id=hypothesis.id,
                observation_id=observation.id,
            )
        )
        seed_session.commit()
        investigation_id = investigation.id
    engine.dispose()
    before = db_path.read_bytes()
    monkeypatch.setattr(status_script, "DB_PATH", db_path)

    assert (
        status_script.main(
            ["--investigation", str(investigation_id), "--researcher-dashboard"]
        )
        == 0
    )
    output = capsys.readouterr().out

    assert db_path.read_bytes() == before
    assert "Researcher dashboard" in output
    assert "observation #" in output
    assert "hypothesis #" in output


def test_researcher_dashboard_cli_requires_investigation() -> None:
    with pytest.raises(SystemExit, match="requires --investigation"):
        status_script.main(["--researcher-dashboard"])


def test_get_researcher_dashboard_marks_missing_support_links_and_is_read_only(
    session: Session,
    investigation: Investigation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    session.add(
        Observation(
            asset_id=asset.id,
            observation_type="dns_record",
            data={"record_type": "TXT", "value": "v=spf1 -all"},
        )
    )
    hypothesis = Hypothesis(
        asset_id=asset.id,
        category="access_control_review",
        description="Review access policy",
        status="confirmed",
    )
    session.add(hypothesis)
    session.flush()

    dashboard = get_researcher_dashboard(session, investigation.id)
    summary = dashboard.hypotheses_by_asset[asset.id][0]
    assert summary.evidence_missing is True
    assert summary.supporting_observation_ids == ()
    assert summary.status == "confirmed"

    def refuse() -> None:
        raise AssertionError("dashboard must not commit")

    monkeypatch.setattr(session, "commit", refuse)
    _ = get_researcher_dashboard(session, investigation.id)
