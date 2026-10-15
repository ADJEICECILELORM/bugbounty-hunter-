"""Tests for the append-only ``TaskEvent`` audit record (V4 Task A).

``data.models.TaskEvent`` records what happened to a task and is insert-only: the
ORM refuses ``before_update``/``before_delete``, and
``verification.investigation_tasks`` offers only ``append_task_event`` plus the
events written automatically by ``create_task``/``start_task``/``complete_task``.
No helper can mutate or remove a row.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Program, Task, TaskEvent, TaskEventIsAppendOnly
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import (
    append_task_event,
    complete_task,
    create_task,
    start_task,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "verification" / "investigation_tasks.py"


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


def test_create_task_records_a_created_event(session: Session, investigation) -> None:
    task = create_task(investigation.id, session, kind="recon", title="look around")

    events = session.query(TaskEvent).filter(TaskEvent.task_id == task.id).all()
    assert [event.event_type for event in events] == ["created"]
    assert events[0].detail == {"kind": "recon", "depends_on": []}
    assert task.events == events


def test_start_and_complete_record_events_in_order(
    session: Session, investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)
    complete_task(task.id, session, final_status="completed", result_summary="done")

    assert [event.event_type for event in task.events] == [
        "created",
        "started",
        "completed",
    ]
    assert task.events[-1].detail == {"result_summary": "done"}


def test_append_task_event_inserts_a_linked_row(session: Session, investigation) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    event = append_task_event(
        task.id, session, event_type="dispatched", detail={"target": "recon"}
    )

    assert event.id is not None
    assert event.task_id == task.id
    assert event.event_type == "dispatched"
    assert event.detail == {"target": "recon"}
    assert event.created_at is not None
    assert event in task.events


def test_append_task_event_rejects_an_unknown_type(
    session: Session, investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    with pytest.raises(ValueError, match="event_type must be one of"):
        append_task_event(task.id, session, event_type="mystery")


def test_task_events_cannot_be_updated(session: Session, investigation) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    event = task.events[0]

    event.event_type = "started"
    with pytest.raises(TaskEventIsAppendOnly):
        session.flush()
    session.rollback()


def test_task_events_cannot_be_deleted(session: Session, investigation) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    event = task.events[0]

    session.delete(event)
    with pytest.raises(TaskEventIsAppendOnly):
        session.flush()
    session.rollback()


def test_the_task_module_has_no_event_mutation_helper() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    assert "def update" not in source
    assert "def delete" not in source
    assert "session.delete" not in source
