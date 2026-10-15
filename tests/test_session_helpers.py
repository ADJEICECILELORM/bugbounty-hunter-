"""Tests for orchestration.session_helpers (the thin Investigation+Task glue).

``orchestration.session_helpers.run_under_investigation`` is the seam that lets a
real operator path own an ``Investigation`` and a ``Task`` without re-implementing
the lifecycle or task layers. The tests assert the happy path (investigation
started + task completed), the failure path (task failed + re-raised), the
dispatch path (a ``DISPATCH_TARGETS`` kind goes through ``run_task``), every
refusal, and - behaviorally and in the source - that the helper never commits and
never promotes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

import orchestration.session_helpers as helpers
import orchestration.task_runner as runner
from data.db import init_db
from data.models import Asset, Investigation, Observation, Program, Task
from verification.investigation_lifecycle import start_investigation

REPO_ROOT = Path(__file__).resolve().parent.parent
HELPER_PATH = REPO_ROOT / "orchestration" / "session_helpers.py"


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


@pytest.fixture()
def program_id(session: Session) -> int:
    program = Program(
        name="Example Program",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    session.add(program)
    session.flush()
    return program.id


def test_starts_investigation_and_completes_work(
    session: Session, program_id: int
) -> None:
    calls: list[int] = []

    def work(task: Task) -> str:
        calls.append(task.id)
        return "did the thing"

    task = helpers.run_under_investigation(
        session,
        program_id=program_id,
        kind="report",
        title="write report",
        work=work,
    )

    assert task.status == "completed"
    assert task.result_summary == "did the thing"
    assert calls == [task.id]
    investigation = session.get(Investigation, task.investigation_id)
    assert investigation.status == "running"
    assert [event.event_type for event in task.events] == [
        "created",
        "started",
        "completed",
    ]


def test_marks_task_failed_and_reraises(
    session: Session, program_id: int
) -> None:
    def work(task: Task) -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        helpers.run_under_investigation(
            session, program_id=program_id, kind="report", title="x", work=work
        )

    task = session.query(Task).one()
    assert task.status == "failed"
    assert "RuntimeError: boom" in (task.result_summary or "")


def test_reuses_an_existing_investigation(
    session: Session, program_id: int
) -> None:
    investigation = start_investigation(program_id, session)

    task = helpers.run_under_investigation(
        session,
        investigation_id=investigation.id,
        kind="report",
        title="x",
        work=lambda task: None,
    )

    assert task.investigation_id == investigation.id
    assert session.query(Investigation).count() == 1


def test_never_commits(session: Session, program_id: int, monkeypatch) -> None:
    def refuse() -> None:
        raise AssertionError("the helper must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    task = helpers.run_under_investigation(
        session,
        program_id=program_id,
        kind="report",
        title="x",
        work=lambda task: "ok",
    )
    assert task.status == "completed"

    session.rollback()
    assert session.query(Investigation).count() == 0
    assert session.query(Task).count() == 0


def test_dispatchable_kind_runs_through_run_task(
    session: Session, program_id: int, monkeypatch
) -> None:
    investigation = start_investigation(program_id, session)
    asset = Asset(investigation_id=investigation.id, hostname="example.test")
    session.add(asset)
    session.flush()

    def fake_collect(
        base_url, authorize, *, session, asset_id, allow_private_network=False, **kwargs
    ):
        observation = Observation(
            asset_id=asset_id,
            observation_type="endpoint_inventory",
            data={"url": base_url},
        )
        session.add(observation)
        session.flush()
        return [observation]

    monkeypatch.setattr(runner, "collect_seed_inventory", fake_collect)

    task = helpers.run_under_investigation(
        session,
        investigation_id=investigation.id,
        kind="inventory",
        title="collect",
        params={"asset_id": asset.id, "base_url": "https://example.test/"},
        authorize=lambda url: True,
    )

    assert task.status == "completed"
    assert session.query(Observation).count() == 1
    assert [event.event_type for event in task.events] == [
        "created",
        "started",
        "dispatched",
        "completed",
    ]


def test_dispatchable_kind_rejects_a_work_callable(
    session: Session, program_id: int
) -> None:
    with pytest.raises(ValueError, match="work callable"):
        helpers.run_under_investigation(
            session,
            program_id=program_id,
            kind="inventory",
            title="x",
            work=lambda task: None,
        )


def test_nondispatchable_kind_requires_work(
    session: Session, program_id: int
) -> None:
    with pytest.raises(ValueError, match="pass a work callable"):
        helpers.run_under_investigation(
            session, program_id=program_id, kind="report", title="x"
        )


def test_requires_program_or_investigation(session: Session) -> None:
    with pytest.raises(ValueError, match="either program_id or investigation_id"):
        helpers.run_under_investigation(
            session, kind="report", title="x", work=lambda task: None
        )


def test_missing_investigation_raises_lookup(session: Session) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        helpers.run_under_investigation(
            session,
            investigation_id=4242,
            kind="report",
            title="x",
            work=lambda task: None,
        )


def test_non_running_investigation_raises(
    session: Session, program_id: int
) -> None:
    investigation = Investigation(program_id=program_id, status="completed")
    session.add(investigation)
    session.flush()

    with pytest.raises(ValueError, match="not 'running'"):
        helpers.run_under_investigation(
            session,
            investigation_id=investigation.id,
            kind="report",
            title="x",
            work=lambda task: None,
        )


def test_helper_source_never_commits_or_promotes() -> None:
    source = HELPER_PATH.read_text(encoding="utf-8")

    for forbidden in (
        ".commit(",
        "finding_promotion",
        "promote_to_finding",
        "import requests",
        "from gateway.lab_mode",
        "threading",
        "asyncio",
        "while True",
    ):
        assert forbidden not in source, forbidden

    assert "hypothesis.status" not in source
    assert re.search(r"\btask\.(status|started_at|ended_at)\s*=(?!=)", source) is None
    assert re.search(r"\binvestigation\.status\s*=(?!=)", source) is None
