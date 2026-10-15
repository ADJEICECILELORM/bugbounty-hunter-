"""Tests for the deterministic, propose-only task planner (V4 Task C).

``orchestration.supervisor.plan_next_tasks`` returns the pending tasks whose
``depends_on`` are all completed, in creation order, and executes nothing. There
is no LLM, no randomness, and no side effect; the cap is enforced by
``create_task`` (``MAX_TASKS_PER_INVESTIGATION``) and the planner never returns
more than that.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Program
from orchestration.supervisor import plan_next_tasks
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import (
    MAX_TASKS_PER_INVESTIGATION,
    complete_task,
    create_task,
    start_task,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR_PATH = REPO_ROOT / "orchestration" / "supervisor.py"


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


def test_returns_only_ready_pending_tasks_in_creation_order(
    session: Session, investigation
) -> None:
    a = make_task(session, investigation, title="a")
    b = make_task(session, investigation, title="b", depends_on=[a.id])
    c = make_task(session, investigation, title="c")

    assert plan_next_tasks(investigation.id, session) == [a, c]


def test_unmet_dependency_is_excluded(session: Session, investigation) -> None:
    a = make_task(session, investigation, title="a")
    make_task(session, investigation, title="b", depends_on=[a.id])

    assert plan_next_tasks(investigation.id, session) == [a]


def test_met_dependency_is_included(session: Session, investigation) -> None:
    a = make_task(session, investigation, title="a")
    b = make_task(session, investigation, title="b", depends_on=[a.id])
    start_task(a.id, session)
    complete_task(a.id, session, final_status="completed")

    assert plan_next_tasks(investigation.id, session) == [b]


def test_completed_tasks_are_never_proposed(session: Session, investigation) -> None:
    a = make_task(session, investigation, title="a")
    start_task(a.id, session)
    complete_task(a.id, session, final_status="completed")

    assert plan_next_tasks(investigation.id, session) == []


def test_cancelled_tasks_are_never_proposed(session: Session, investigation) -> None:
    a = make_task(session, investigation, title="a")
    complete_task(a.id, session, final_status="cancelled")

    assert plan_next_tasks(investigation.id, session) == []


def test_planner_is_read_only_and_deterministic(session: Session, investigation) -> None:
    a = make_task(session, investigation, title="a")
    b = make_task(session, investigation, title="b")

    first = plan_next_tasks(investigation.id, session)
    second = plan_next_tasks(investigation.id, session)

    assert [task.id for task in first] == [task.id for task in second] == [a.id, b.id]
    assert a.status == "pending"
    assert b.status == "pending"


def test_missing_investigation_raises(session: Session) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        plan_next_tasks(4242, session)


def test_create_task_enforces_the_cap(session: Session, investigation) -> None:
    for _ in range(MAX_TASKS_PER_INVESTIGATION):
        make_task(session, investigation, title="x")

    with pytest.raises(ValueError, match="already holds"):
        make_task(session, investigation, title="overflow")


def test_planner_never_returns_more_than_the_cap(
    session: Session, investigation
) -> None:
    for _ in range(MAX_TASKS_PER_INVESTIGATION):
        make_task(session, investigation, title="x")

    ready = plan_next_tasks(investigation.id, session)
    assert len(ready) == MAX_TASKS_PER_INVESTIGATION


def test_planner_respects_a_lowered_per_investigation_budget(
    session: Session, investigation
) -> None:
    for index in range(5):
        make_task(session, investigation, title=f"x{index}")

    investigation.max_tasks = 3
    session.flush()

    ready = plan_next_tasks(investigation.id, session)
    assert len(ready) == 3


def test_supervisor_is_propose_only() -> None:
    source = SUPERVISOR_PATH.read_text(encoding="utf-8")

    for forbidden in (
        ".commit(",
        "generate_completion",
        "llm_client",
        "run_task",
        "task_runner",
        "import random",
        "import requests",
    ):
        assert forbidden not in source, forbidden
