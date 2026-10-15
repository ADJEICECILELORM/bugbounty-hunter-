"""Tests for operator-tracked investigation tasks (V4 orchestration foundation).

``verification/investigation_tasks.py`` records work inside a running
investigation: ``create_task``, ``start_task``, ``complete_task`` and
``list_tasks``. Nothing runs a task; every transition is an explicit call. The
tests assert the happy paths, every rejection, that ``close_investigation``
refuses while a task is open, that no writer commits, and - in the source - that
only the two lifecycle modules write an ``Investigation`` or ``Task`` status.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Investigation, Program, Task
from verification import investigation_lifecycle
from verification.investigation_lifecycle import (
    OpenTasksError,
    close_investigation,
    start_investigation,
)
from verification.investigation_tasks import (
    FINAL_STATUSES,
    INVESTIGATION_RUNNING,
    PENDING,
    RUNNING,
    TASK_KINDS,
    complete_task,
    create_task,
    list_tasks,
    start_task,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "verification" / "investigation_tasks.py"


def python_sources(*directories: str) -> list[Path]:
    paths: list[Path] = []
    for directory in directories:
        paths.extend(sorted((REPO_ROOT / directory).glob("*.py")))
    return paths


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


# --- happy paths -----------------------------------------------------------


def test_create_task_adds_a_pending_row_to_the_investigation(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(
        investigation.id, session, kind="recon", title="Passive DNS for example.test"
    )

    assert task.id is not None
    assert task.status == PENDING
    assert task.kind == "recon"
    assert task.title == "Passive DNS for example.test"
    assert task.created_at is not None
    assert task.started_at is None
    assert task.ended_at is None
    assert task.result_summary is None
    assert investigation.tasks == [task]


def test_start_task_moves_pending_to_running_and_sets_started_at(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="inventory", title="Seeds")

    started = start_task(task.id, session)

    assert started is task
    assert task.status == RUNNING
    assert task.started_at is not None
    assert task.ended_at is None


@pytest.mark.parametrize("final_status", sorted(FINAL_STATUSES))
def test_complete_task_ends_a_running_task(
    session: Session, investigation: Investigation, final_status: str
) -> None:
    task = create_task(investigation.id, session, kind="verification", title="Plan 1")
    start_task(task.id, session)

    completed = complete_task(
        task.id, session, final_status=final_status, result_summary="done by hand"
    )

    assert completed is task
    assert task.status == final_status
    assert task.ended_at is not None
    assert task.result_summary == "done by hand"


def test_a_pending_task_can_be_cancelled_without_starting(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="report", title="Write-up")

    complete_task(task.id, session, final_status="cancelled")

    assert task.status == "cancelled"
    assert task.started_at is None
    assert task.ended_at is not None


def test_list_tasks_returns_only_this_investigation_in_creation_order(
    session: Session, investigation: Investigation
) -> None:
    other = start_investigation(investigation.program_id, session)
    first = create_task(investigation.id, session, kind="recon", title="a")
    create_task(other.id, session, kind="recon", title="elsewhere")
    second = create_task(investigation.id, session, kind="report", title="b")

    assert list_tasks(investigation.id, session) == [first, second]
    assert list_tasks(4242, session) == []


def test_every_allowlisted_kind_is_accepted(
    session: Session, investigation: Investigation
) -> None:
    for kind in sorted(TASK_KINDS):
        assert create_task(investigation.id, session, kind=kind, title=kind).kind == kind


# --- rejections ------------------------------------------------------------


def test_create_task_rejects_a_missing_investigation(session: Session) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        create_task(4242, session, kind="recon", title="x")


def test_create_task_rejects_a_closed_investigation(
    session: Session, investigation: Investigation
) -> None:
    close_investigation(investigation.id, session, final_status="completed")

    with pytest.raises(ValueError, match="'completed', not 'running'"):
        create_task(investigation.id, session, kind="recon", title="x")
    assert session.query(Task).count() == 0


def test_create_task_rejects_a_never_started_investigation(
    session: Session, investigation: Investigation
) -> None:
    # A row built directly keeps the model default ``pending`` status.
    pending = Investigation(program_id=investigation.program_id)
    session.add(pending)
    session.flush()

    with pytest.raises(ValueError, match="not 'running'"):
        create_task(pending.id, session, kind="recon", title="x")


@pytest.mark.parametrize("kind", ["scan", "exploit", "", "Recon", "promote"])
def test_create_task_rejects_a_kind_outside_the_allowlist(
    session: Session, investigation: Investigation, kind: str
) -> None:
    with pytest.raises(ValueError, match="kind must be one of"):
        create_task(investigation.id, session, kind=kind, title="x")
    assert session.query(Task).count() == 0


def test_create_task_rejects_a_blank_title(
    session: Session, investigation: Investigation
) -> None:
    with pytest.raises(ValueError, match="title"):
        create_task(investigation.id, session, kind="recon", title="   ")


def test_start_task_rejects_a_missing_task(session: Session) -> None:
    with pytest.raises(LookupError, match="Task 4242 does not exist"):
        start_task(4242, session)


def test_start_task_only_accepts_a_pending_task(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)
    started_at = task.started_at

    with pytest.raises(ValueError, match="'running', not 'pending'"):
        start_task(task.id, session)
    assert task.started_at == started_at

    complete_task(task.id, session, final_status="completed")
    with pytest.raises(ValueError, match="'completed', not 'pending'"):
        start_task(task.id, session)


@pytest.mark.parametrize("final_status", ["running", "pending", "done", ""])
def test_complete_task_rejects_an_invalid_final_status(
    session: Session, investigation: Investigation, final_status: str
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)

    with pytest.raises(ValueError, match="final_status must be one of"):
        complete_task(task.id, session, final_status=final_status)
    assert task.status == RUNNING
    assert task.ended_at is None


@pytest.mark.parametrize("final_status", ["completed", "failed"])
def test_a_pending_task_cannot_be_completed_or_failed(
    session: Session, investigation: Investigation, final_status: str
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")

    with pytest.raises(ValueError, match="cannot become"):
        complete_task(task.id, session, final_status=final_status)
    assert task.status == PENDING


def test_a_terminal_task_never_changes_again(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)
    complete_task(task.id, session, final_status="failed", result_summary="timeout")
    ended_at = task.ended_at

    for final_status in sorted(FINAL_STATUSES):
        with pytest.raises(ValueError, match="cannot become"):
            complete_task(task.id, session, final_status=final_status)
    assert task.status == "failed"
    assert task.ended_at == ended_at
    assert task.result_summary == "timeout"


def test_complete_task_rejects_a_missing_task(session: Session) -> None:
    with pytest.raises(LookupError, match="Task 4242 does not exist"):
        complete_task(4242, session, final_status="cancelled")


# --- lifecycle consistency -------------------------------------------------


@pytest.mark.parametrize("open_state", [PENDING, RUNNING])
@pytest.mark.parametrize("final_status", sorted(investigation_lifecycle.CLOSED_STATUSES))
def test_close_investigation_is_blocked_while_a_task_is_open(
    session: Session, investigation: Investigation, open_state: str, final_status: str
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    if open_state == RUNNING:
        start_task(task.id, session)

    with pytest.raises(OpenTasksError, match=rf"open tasks \[{task.id}\]"):
        close_investigation(investigation.id, session, final_status=final_status)

    # Nothing changed: the investigation and the task are both still open.
    assert investigation.status == INVESTIGATION_RUNNING
    assert investigation.ended_at is None
    assert task.status == open_state


def test_close_investigation_succeeds_once_every_task_is_ended(
    session: Session, investigation: Investigation
) -> None:
    done = create_task(investigation.id, session, kind="recon", title="a")
    dropped = create_task(investigation.id, session, kind="report", title="b")
    start_task(done.id, session)
    complete_task(done.id, session, final_status="completed")
    complete_task(dropped.id, session, final_status="cancelled")

    close_investigation(investigation.id, session, final_status="completed")

    assert investigation.status == "completed"
    assert [task.status for task in list_tasks(investigation.id, session)] == [
        "completed",
        "cancelled",
    ]


def test_open_tasks_error_is_a_value_error() -> None:
    assert issubclass(OpenTasksError, ValueError)


def test_the_local_running_constant_mirrors_the_lifecycle_module() -> None:
    assert INVESTIGATION_RUNNING == investigation_lifecycle.RUNNING


def test_no_task_writer_commits_the_session(
    session: Session, investigation: Investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse() -> None:
        raise AssertionError("the task writers must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    first = create_task(investigation.id, session, kind="recon", title="a")
    second = create_task(investigation.id, session, kind="recon", title="b")
    start_task(first.id, session)
    complete_task(first.id, session, final_status="completed")
    complete_task(second.id, session, final_status="cancelled")
    close_investigation(investigation.id, session, final_status="completed")

    assert len(list_tasks(investigation.id, session)) == 2

    # Everything was only flushed, so a rollback removes it all.
    session.rollback()
    assert session.query(Task).count() == 0
    assert session.query(Investigation).count() == 0


# --- structural guards -----------------------------------------------------


def test_the_task_module_imports_only_the_session_layer_and_its_models() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    model_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            if node.module == "data.models":
                model_names.update(alias.name for alias in node.names)

    assert imported == {
        "__future__",
        "datetime",
        "sqlalchemy",
        "sqlalchemy.orm",
        "data.models",
    }
    assert model_names == {"Investigation", "Task"}


def test_the_task_module_has_no_commit_or_side_effect_path() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    for forbidden in (
        ".commit(",
        "import requests",
        "from gateway",
        "llm_client",
        "generate_completion",
        "finding_promotion",
        "probe_endpoint",
        "probe_lab_target",
        "check_verdict",
        "store_verdict",
        "Hypothesis(",
        "Finding(",
        "Verdict(",
        "Observation(",
        "threading",
        "asyncio",
        "subprocess",
        "import sched",
    ):
        assert forbidden not in source, forbidden


def test_only_the_task_module_writes_a_task_status_or_timestamp() -> None:
    sources = python_sources(
        "verification", "intelligence", "gateway", "data", "workers", "scripts"
    )
    pattern = re.compile(r"\btask\.(status|started_at|ended_at)\s*=(?!=)")
    writers = sorted(
        {path.name for path in sources if pattern.search(path.read_text(encoding="utf-8"))}
    )

    assert writers == ["investigation_tasks.py"]


def test_only_the_lifecycle_modules_write_investigation_or_task_status() -> None:
    sources = python_sources(
        "verification", "intelligence", "gateway", "data", "workers", "scripts"
    )
    investigation_writers = sorted(
        path.name
        for path in sources
        if re.search(r"investigation\.status\s*=(?!=)", path.read_text(encoding="utf-8"))
    )
    any_status_writers = {
        path.name
        for path in sources
        if re.search(r"\b(task|investigation)\.status\s*=(?!=)", path.read_text(encoding="utf-8"))
    }

    assert investigation_writers == ["investigation_lifecycle.py"]
    assert any_status_writers == {"investigation_lifecycle.py", "investigation_tasks.py"}
