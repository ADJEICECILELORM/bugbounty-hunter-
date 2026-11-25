"""Tests for human-initiated task recovery (V5).

``verification/task_recovery.py`` is the only way an operator recovers from a
task left ``running`` by a crashed process: ``find_stuck_tasks`` lists overrun
tasks (read-only), ``mark_task_failed_after_crash`` ends one as ``failed``, and
``create_retry_task`` copies a terminal task into a new pending retry. Nothing
here runs a task, and the module reuses the task layer so status transitions and
the append-only ``TaskEvent`` audit stay single-sourced. The tests assert the
happy paths, every refusal, that no writer commits, and - in the source - that
the module never writes a status directly, commits, or reaches the network or
the promotion gate.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from data.db import create_database_engine, init_db, initialize_fresh_database
from data.models import Asset, Investigation, Program, Task, TaskEvent
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import (
    PENDING,
    RUNNING,
    complete_task,
    create_task,
    start_task,
)
from verification.task_recovery import (
    create_retry_task,
    find_stuck_tasks,
    mark_task_failed_after_crash,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "verification" / "task_recovery.py"


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


# --- find_stuck_tasks ------------------------------------------------------


def test_find_stuck_tasks_returns_running_tasks_older_than_the_threshold(
    session: Session, investigation: Investigation
) -> None:
    stuck = create_task(investigation.id, session, kind="recon", title="stuck")
    start_task(stuck.id, session)
    stuck.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    fresh = create_task(investigation.id, session, kind="recon", title="fresh")
    start_task(fresh.id, session)

    done = create_task(investigation.id, session, kind="recon", title="done")
    start_task(done.id, session)
    complete_task(done.id, session, final_status="completed")

    assert find_stuck_tasks(
        investigation.id, session, running_longer_than_seconds=3600
    ) == [stuck]


def test_find_stuck_tasks_is_scoped_to_one_investigation(
    session: Session, investigation: Investigation
) -> None:
    other = start_investigation(investigation.program_id, session)
    other_stuck = create_task(other.id, session, kind="recon", title="elsewhere")
    start_task(other_stuck.id, session)
    other_stuck.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    assert find_stuck_tasks(
        investigation.id, session, running_longer_than_seconds=3600
    ) == []


def test_find_stuck_tasks_rejects_a_missing_investigation(session: Session) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        find_stuck_tasks(4242, session, running_longer_than_seconds=3600)


def test_find_stuck_tasks_rejects_a_negative_threshold(
    session: Session, investigation: Investigation
) -> None:
    with pytest.raises(ValueError, match=">= 0"):
        find_stuck_tasks(investigation.id, session, running_longer_than_seconds=-1)


def test_find_stuck_tasks_is_read_only(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="stuck")
    start_task(task.id, session)
    task.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    find_stuck_tasks(investigation.id, session, running_longer_than_seconds=3600)

    assert task.status == RUNNING
    assert [event.event_type for event in task.events] == ["created", "started"]


# --- mark_task_failed_after_crash -------------------------------------------


def test_mark_task_failed_after_crash_ends_a_running_task(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)

    marked = mark_task_failed_after_crash(task.id, session, reason="worker died")

    assert marked is task
    assert task.status == "failed"
    assert task.ended_at is not None
    assert task.result_summary == "worker died"
    assert [event.event_type for event in task.events] == [
        "created",
        "started",
        "failed",
        "crash_recovery",
    ]
    assert task.events[-1].detail == {"reason": "worker died"}


def test_mark_task_failed_after_crash_refuses_a_non_running_task(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")

    with pytest.raises(ValueError, match="cannot become 'failed'"):
        mark_task_failed_after_crash(task.id, session, reason="x")

    assert task.status == PENDING
    assert task.ended_at is None


def test_mark_task_failed_after_crash_refuses_a_blank_reason(
    session: Session, investigation: Investigation
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)

    with pytest.raises(ValueError, match="reason"):
        mark_task_failed_after_crash(task.id, session, reason="   ")

    assert task.status == RUNNING


@pytest.mark.parametrize(
    "reason",
    [
        "Authorization: Bearer test-secret",
        "password=hunter2",
        "https://user:secret@example.test/path",
        "x" * 501,
    ],
)
def test_mark_task_failed_after_crash_does_not_persist_sensitive_reason(
    session: Session, investigation: Investigation, reason: str
) -> None:
    task = create_task(investigation.id, session, kind="recon", title="x")
    start_task(task.id, session)

    with pytest.raises(ValueError, match="non-sensitive description") as error:
        mark_task_failed_after_crash(task.id, session, reason=reason)

    assert reason not in str(error.value)
    assert task.status == RUNNING
    assert task.result_summary is None
    assert [event.event_type for event in task.events] == ["created", "started"]


def test_competing_stale_sessions_cannot_start_one_task_twice(
    tmp_path: Path,
) -> None:
    engine = create_database_engine(
        f"sqlite+pysqlite:///{tmp_path / 'atomic-task-start.db'}"
    )
    initialize_fresh_database(engine)
    with Session(engine) as setup:
        program = Program(
            name="atomic start", authorized_scope=["example.test"],
            excluded_scope=[], rate_limit=1,
        )
        setup.add(program)
        setup.flush()
        investigation = start_investigation(program.id, setup)
        task = create_task(investigation.id, setup, kind="report", title="once")
        task_id = task.id
        setup.commit()

    first = Session(engine)
    second = Session(engine)
    try:
        assert first.get(Task, task_id).status == PENDING
        stale = second.get(Task, task_id)
        assert stale.status == PENDING
        start_task(task_id, first)
        first.commit()

        with pytest.raises(ValueError, match="'running'"):
            start_task(task_id, second)
        assert stale.status == RUNNING
        second.commit()
        with Session(engine) as check:
            events = check.query(TaskEvent).filter_by(task_id=task_id).all()
            assert [event.event_type for event in events].count("started") == 1
    finally:
        first.close()
        second.close()
        engine.dispose()


def test_durable_dispatch_start_is_recoverable_after_process_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orchestration.task_runner as runner

    engine = create_database_engine(
        f"sqlite+pysqlite:///{tmp_path / 'durable-dispatch.db'}"
    )
    initialize_fresh_database(engine)
    with Session(engine) as setup:
        program = Program(
            name="durable dispatch", authorized_scope=["api.example.test"],
            excluded_scope=[], rate_limit=1,
        )
        setup.add(program)
        setup.flush()
        investigation = start_investigation(program.id, setup)
        asset = Asset(investigation_id=investigation.id, hostname="api.example.test")
        setup.add(asset)
        setup.flush()
        task = create_task(
            investigation.id,
            setup,
            kind="inventory",
            title="collect",
            params={"asset_id": asset.id, "base_url": "https://api.example.test/"},
        )
        task_id = task.id
        investigation_id = investigation.id
        setup.commit()

    class SimulatedProcessExit(BaseException):
        pass

    def crash_after_durable_start(*args: object, session: Session, **kwargs: object):
        with Session(engine) as observer:
            durable_task = observer.get(Task, task_id)
            assert durable_task.status == RUNNING
            assert [event.event_type for event in durable_task.events] == [
                "created", "started", "dispatched"
            ]
        raise SimulatedProcessExit()

    monkeypatch.setattr(runner, "collect_seed_inventory", crash_after_durable_start)
    try:
        with Session(engine) as active:
            with pytest.raises(SimulatedProcessExit):
                runner.run_task(
                    task_id,
                    active,
                    authorize=lambda _url: True,
                    commit_before_dispatch=True,
                )
        with Session(engine) as recovered:
            assert find_stuck_tasks(
                    investigation_id, recovered, running_longer_than_seconds=0
            )
            mark_task_failed_after_crash(
                task_id, recovered, reason="process interrupted before completion"
            )
            retry = create_retry_task(task_id, recovered)
            recovered.commit()
            assert retry.status == PENDING
            assert retry.dedupe_key == f"retry:v1:{task_id}"
    finally:
        engine.dispose()


# --- create_retry_task -----------------------------------------------------


def _asset(investigation: Investigation, session: Session) -> Asset:
    asset = Asset(investigation_id=investigation.id, hostname="example.test")
    session.add(asset)
    session.flush()
    return asset


def test_create_retry_task_copies_kind_params_and_depends_on(
    session: Session, investigation: Investigation
) -> None:
    asset = _asset(investigation, session)
    dep = create_task(investigation.id, session, kind="recon", title="dependency")
    original = create_task(
        investigation.id,
        session,
        kind="inventory",
        title="collect seeds",
        params={"asset_id": asset.id, "base_url": "https://example.test/"},
        depends_on=[dep.id],
    )
    start_task(original.id, session)
    complete_task(original.id, session, final_status="failed", result_summary="boom")

    retry = create_retry_task(original.id, session)

    assert retry is not original
    assert retry.status == PENDING
    assert retry.kind == "inventory"
    assert retry.params == {"asset_id": asset.id, "base_url": "https://example.test/"}
    assert retry.depends_on == [dep.id]
    assert retry.investigation_id == investigation.id
    assert [event.event_type for event in retry.events] == ["created"]

    link = original.events[-1]
    assert link.event_type == "retry_created"
    assert link.detail == {"retry_task_id": retry.id, "retry_of": original.id}


def test_create_retry_task_accepts_a_cancelled_original(
    session: Session, investigation: Investigation
) -> None:
    original = create_task(investigation.id, session, kind="report", title="write-up")
    complete_task(original.id, session, final_status="cancelled")

    retry = create_retry_task(original.id, session)

    assert retry.status == PENDING
    assert retry.kind == "report"


@pytest.mark.parametrize("final_status", ["pending", "running", "completed"])
def test_create_retry_task_refuses_a_non_retryable_original(
    session: Session, investigation: Investigation, final_status: str
) -> None:
    original = create_task(investigation.id, session, kind="recon", title="x")
    if final_status == "running":
        start_task(original.id, session)
    elif final_status == "completed":
        start_task(original.id, session)
        complete_task(original.id, session, final_status="completed")

    with pytest.raises(ValueError, match="only a failed or cancelled task"):
        create_retry_task(original.id, session)

    assert session.query(Task).count() == 1


def test_create_retry_task_refuses_a_second_retry(
    session: Session, investigation: Investigation
) -> None:
    original = create_task(investigation.id, session, kind="recon", title="x")
    start_task(original.id, session)
    complete_task(original.id, session, final_status="failed")

    first = create_retry_task(original.id, session)

    with pytest.raises(ValueError, match="already has a retry"):
        create_retry_task(original.id, session)

    assert session.query(Task).count() == 2
    assert first.status == PENDING


def test_retry_creation_rolls_back_task_when_audit_link_fails(
    session: Session, investigation: Investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    import verification.task_recovery as recovery

    original = create_task(investigation.id, session, kind="report", title="retry atomically")
    start_task(original.id, session)
    complete_task(original.id, session, final_status="failed")
    task_count = session.query(Task).count()

    def fail_retry_audit(*_args, **_kwargs):
        raise RuntimeError("audit link failed")

    monkeypatch.setattr(recovery, "append_task_event", fail_retry_audit)
    with pytest.raises(RuntimeError, match="audit link failed"):
        create_retry_task(original.id, session)

    assert session.query(Task).count() == task_count
    assert not any(event.event_type == "retry_created" for event in original.events)

def test_create_retry_task_rejects_a_missing_task(session: Session) -> None:
    with pytest.raises(LookupError, match="Task 4242 does not exist"):
        create_retry_task(4242, session)


# --- no commit / structural guards ------------------------------------------


def test_recovery_functions_never_commit(
    session: Session, investigation: Investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse() -> None:
        raise AssertionError("the recovery library must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    crashed = create_task(investigation.id, session, kind="recon", title="crashed")
    start_task(crashed.id, session)
    mark_task_failed_after_crash(crashed.id, session, reason="worker died")
    retry = create_retry_task(crashed.id, session)

    assert retry.status == PENDING

    session.rollback()
    assert session.query(Task).count() == 0
    assert session.query(Investigation).count() == 0


def test_recovery_module_imports_only_the_session_and_task_layers() -> None:
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
        "re",
        "sqlalchemy",
        "sqlalchemy.exc",
        "sqlalchemy.orm",
        "data.models",
        "verification.investigation_tasks",
    }
    assert model_names == {"Investigation", "Task", "TaskEvent"}


def test_recovery_module_has_no_commit_or_side_effect_path() -> None:
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
        "while True",
        "run_task",
        "plan_next_tasks",
    ):
        assert forbidden not in source, forbidden

    # The task layer is the only writer of task status/timestamps; recovery
    # reuses it rather than assigning them itself.
    assert "task.status =" not in source
    assert "task.started_at =" not in source
    assert "task.ended_at =" not in source
    assert "hypothesis.status" not in source


