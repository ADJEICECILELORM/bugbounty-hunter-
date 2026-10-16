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
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import scripts.investigation_status as status_script
from data.db import init_db
from data.models import Asset, Finding, Hypothesis, Investigation, Program
from orchestration.status_board import (
    find_stuck_tasks,
    get_investigation_status,
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

