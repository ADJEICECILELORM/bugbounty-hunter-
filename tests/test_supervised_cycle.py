"""Tests for the budget-aware, human-triggered supervised cycle (V6 first slice).

``orchestration.supervised_cycle.run_supervised_cycle`` is one pass, not a loop:
it always proposes via ``plan_next_tasks``, writes nothing on a dry run, and only
with ``execute=True`` runs the proposed tasks once each through ``run_task``,
stopping on the first failure. The tests assert the dry-run/execute split, that
execute runs only the proposed tasks, that a stuck task blocks execute, that an
empty plan is fine, that the library never commits or touches ``Hypothesis``,
and the stop-on-first-failure policy.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

import orchestration.supervised_cycle as cycle
import orchestration.task_runner as runner
from data.db import init_db
from data.models import Asset, Program
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import (
    complete_task,
    create_task,
    start_task,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "orchestration" / "supervised_cycle.py"


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


@pytest.fixture()
def investigation(session: Session):
    program = Program(
        name="Example Program",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    session.add(program)
    session.flush()
    return start_investigation(program.id, session)


def make_task(session, investigation, *, title, depends_on=None):
    return create_task(
        investigation.id, session, kind="recon", title=title, depends_on=depends_on
    )


def seed_asset(session: Session, investigation) -> Asset:
    asset = Asset(investigation_id=investigation.id, hostname="example.test")
    session.add(asset)
    session.flush()
    return asset


def test_dry_run_proposes_and_writes_nothing(session: Session, investigation) -> None:
    a = make_task(session, investigation, title="a")
    b = make_task(session, investigation, title="b")

    report = cycle.run_supervised_cycle(investigation.id, session, execute=False)

    assert report.investigation_id == investigation.id
    assert report.proposed == [
        cycle.ProposedTask(task_id=a.id, kind="recon", title="a"),
        cycle.ProposedTask(task_id=b.id, kind="recon", title="b"),
    ]
    assert report.executed == []
    assert report.skipped == []
    assert a.status == "pending"
    assert b.status == "pending"
    assert [event.event_type for event in a.events] == ["created"]
    assert [event.event_type for event in b.events] == ["created"]


def test_execute_runs_only_proposed_tasks(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = make_task(session, investigation, title="a")
    make_task(session, investigation, title="b", depends_on=[a.id])

    called: list[int] = []

    def fake_run_task(task_id, session, **kwargs):
        called.append(task_id)
        start_task(task_id, session)
        complete_task(task_id, session, final_status="completed")

    monkeypatch.setattr(cycle, "run_task", fake_run_task)

    report = cycle.run_supervised_cycle(investigation.id, session, execute=True)

    assert [task.task_id for task in report.proposed] == [a.id]
    assert [result.task_id for result in report.executed] == [a.id]
    assert called == [a.id]
    assert a.status == "completed"


def test_stuck_tasks_block_execute(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    stuck = make_task(session, investigation, title="stuck")
    start_task(stuck.id, session)
    stuck.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    ready = make_task(session, investigation, title="ready")

    called: list[int] = []

    def refuse_run(task_id, session, **kwargs):
        called.append(task_id)
        raise AssertionError("must not run while a task is stuck")

    monkeypatch.setattr(cycle, "run_task", refuse_run)

    report = cycle.run_supervised_cycle(
        investigation.id, session, execute=True, threshold_seconds=3600
    )

    assert report.executed == []
    assert [skip.reason for skip in report.skipped] == ["stuck"]
    assert "recover_investigation.py" in report.skipped[0].detail
    assert called == []
    assert ready.status == "pending"

def test_empty_plan_is_ok(session: Session, investigation) -> None:
    report = cycle.run_supervised_cycle(investigation.id, session, execute=True)

    assert report.proposed == []
    assert report.executed == []
    assert [skip.reason for skip in report.skipped] == ["empty"]


def test_not_running_investigation_refuses_execute(
    session: Session, investigation
) -> None:
    investigation.status = "pending"
    session.flush()

    with pytest.raises(ValueError, match="not 'running'"):
        cycle.run_supervised_cycle(investigation.id, session, execute=True)


def test_missing_investigation_raises(session: Session) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        cycle.run_supervised_cycle(4242, session, execute=False)


def test_execute_stops_on_first_failure(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    first = create_task(
        investigation.id,
        session,
        kind="hypothesis_generation",
        title="first",
        params={"asset_id": asset.id},
    )
    second = create_task(
        investigation.id,
        session,
        kind="hypothesis_generation",
        title="second",
        params={"asset_id": asset.id},
    )

    def boom(asset_id, session):
        raise RuntimeError("model down")

    monkeypatch.setattr(runner, "generate_hypotheses", boom)

    report = cycle.run_supervised_cycle(investigation.id, session, execute=True)

    assert [result.task_id for result in report.executed] == [first.id]
    assert report.executed[0].ok is False
    assert report.executed[0].error_type == "RuntimeError"
    assert first.status == "failed"
    assert second.status == "pending"


def test_run_supervised_cycle_never_commits(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = make_task(session, investigation, title="a")

    def refuse_commit():
        raise AssertionError("must not commit")

    def stub_run(task_id, session, **kwargs):
        start_task(task_id, session)
        complete_task(task_id, session, final_status="completed")

    monkeypatch.setattr(session, "commit", refuse_commit)
    monkeypatch.setattr(cycle, "run_task", stub_run)

    cycle.run_supervised_cycle(investigation.id, session, execute=True)

    assert task.status == "completed"


def test_module_source_never_commits_or_writes_hypothesis_status() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    assert ".commit(" not in source
    assert re.search(r"hypothesis\.status\s*=(?!=)", source) is None
    assert "finding_promotion" not in source
    assert "promote_to_finding" not in source
    assert re.search(r"\btask\.(status|started_at|ended_at)\s*=(?!=)", source) is None
    assert re.search(r"\binvestigation\.status\s*=(?!=)", source) is None

