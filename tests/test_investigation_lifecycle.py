"""Tests for the persistent investigation lifecycle (V4 smallest slice).

``start_investigation`` and ``close_investigation`` are the only two functions in
``verification/investigation_lifecycle.py``. They open and close a single
``Investigation`` row and nothing else: both flush and never commit, and neither
imports the gateway or the promotion gate. The tests assert the row shape, the
two rejections, and - both at runtime and in the source - that the session is
never committed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Investigation, Program
from verification.investigation_lifecycle import (
    CLOSED_STATUSES,
    RUNNING,
    close_investigation,
    start_investigation,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "verification" / "investigation_lifecycle.py"
STATUS_WRITER = "investigation_lifecycle.py"


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


def seed_program(session: Session) -> Program:
    program = Program(
        name="Example Program",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    session.add(program)
    session.flush()
    return program


def test_start_investigation_creates_a_running_row_with_started_at(
    session: Session,
) -> None:
    program = seed_program(session)

    investigation = start_investigation(program.id, session)

    assert investigation.id is not None
    assert investigation.status == RUNNING
    assert investigation.started_at is not None
    assert investigation.ended_at is None

    loaded = session.get(Investigation, investigation.id)
    assert loaded is investigation
    assert loaded.program_id == program.id


def test_start_investigation_rejects_an_unknown_program(session: Session) -> None:
    with pytest.raises(LookupError, match="Program 4242 does not exist"):
        start_investigation(4242, session)


def test_close_investigation_sets_final_status_and_ended_at(
    session: Session,
) -> None:
    program = seed_program(session)
    investigation = start_investigation(program.id, session)
    started_at = investigation.started_at

    closed = close_investigation(
        investigation.id, session, final_status="completed"
    )

    assert closed is investigation
    assert investigation.status == "completed"
    assert investigation.ended_at is not None
    assert investigation.started_at == started_at


def test_close_investigation_accepts_every_closed_status(session: Session) -> None:
    program = seed_program(session)

    for final_status in sorted(CLOSED_STATUSES):
        investigation = start_investigation(program.id, session)
        close_investigation(investigation.id, session, final_status=final_status)
        assert investigation.status == final_status
        assert investigation.ended_at is not None


def test_close_investigation_rejects_an_invalid_final_status(
    session: Session,
) -> None:
    program = seed_program(session)
    investigation = start_investigation(program.id, session)

    with pytest.raises(ValueError, match="final_status"):
        close_investigation(investigation.id, session, final_status="paused")

    # Nothing changed: still running and still open.
    assert investigation.status == RUNNING
    assert investigation.ended_at is None


def test_close_investigation_raises_on_a_missing_id(session: Session) -> None:
    with pytest.raises(LookupError, match="Investigation 4242 does not exist"):
        close_investigation(4242, session, final_status="completed")


def test_neither_function_commits_the_session(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    program = seed_program(session)

    def refuse() -> None:
        raise AssertionError("the lifecycle must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    investigation = start_investigation(program.id, session)
    close_investigation(investigation.id, session, final_status="completed")

    # The row is visible because it was flushed ...
    assert session.get(Investigation, investigation.id) is investigation

    # ... and it disappears on rollback, because nothing was ever committed.
    session.rollback()
    assert session.get(Investigation, investigation.id) is None


# --- structural guards -----------------------------------------------------


def test_the_lifecycle_module_has_no_commit_or_side_effect_path() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    for forbidden in (
        ".commit(",  # the caller owns the transaction, never this module
        "import requests",
        "llm_client",
        "generate_completion",
        "finding_promotion",
        "probe_endpoint",
        "check_verdict",
    ):
        assert forbidden not in source, forbidden


def test_the_lifecycle_module_does_not_touch_hypotheses_or_findings() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    # The docstring may name them to say the module leaves them alone, but it
    # must never import or construct a Hypothesis or a Finding.
    assert "from data.models import Hypothesis" not in source
    assert "from data.models import Finding" not in source
    assert "Hypothesis(" not in source
    assert "Finding(" not in source


def test_only_the_lifecycle_module_writes_an_investigation_status() -> None:
    writers = [
        path.name
        for path in python_sources("verification", "intelligence", "gateway", "data")
        if re.search(r"investigation\.status\s*=(?!=)", path.read_text(encoding="utf-8"))
    ]

    assert writers == [STATUS_WRITER], (
        "an investigation status may only be written by the lifecycle module"
    )
