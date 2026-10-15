"""Tests for the operator inventory-collection script (V6 wiring).

``scripts.collect_inventory.run_collect_inventory`` is the first real operator
path that owns an ``Investigation``, an ``Asset``, and a ``Task``: it ensures an
asset for the target host and runs the existing
``verification.endpoint_inventory_collector.collect_seed_inventory`` as an
``inventory`` task through the dispatcher. These tests use in-memory SQLite and a
fake collector (no network), and assert the durable happy path, the failed-task
path, that the core function never commits, asset reuse, and - in the source -
that the script never promotes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

import orchestration.task_runner as runner
from data.db import init_db
from data.models import Asset, Investigation, Observation, Program, Task
from scripts import collect_inventory
from verification.investigation_lifecycle import start_investigation

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "collect_inventory.py"


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


def _program(session: Session) -> Program:
    program = Program(
        name="Example Program",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    session.add(program)
    session.flush()
    return program


def _fake_collect():
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

    return fake_collect


def test_full_path_leaves_durable_investigation_asset_task(
    session: Session, monkeypatch
) -> None:
    program = _program(session)
    investigation = start_investigation(program.id, session)
    monkeypatch.setattr(runner, "collect_seed_inventory", _fake_collect())

    investigation, asset, task = collect_inventory.run_collect_inventory(
        session,
        investigation=investigation,
        base_url="https://example.test/",
        authorize=lambda url: True,
    )

    assert task.status == "completed"
    assert task.kind == "inventory"
    session.commit()

    engine = session.get_bind()
    with Session(engine) as fresh:
        stored_investigation = fresh.get(Investigation, investigation.id)
        assert stored_investigation is not None
        assert stored_investigation.status == "running"
        stored_asset = fresh.get(Asset, asset.id)
        assert stored_asset is not None
        assert stored_asset.hostname == "example.test"
        stored_task = fresh.get(Task, task.id)
        assert stored_task is not None
        assert stored_task.status == "completed"
        assert fresh.query(Observation).count() == 1


def test_failed_collect_marks_task_failed_and_reraises(
    session: Session, monkeypatch
) -> None:
    program = _program(session)
    investigation = start_investigation(program.id, session)

    def boom(base_url, authorize, *, session, asset_id, allow_private_network=False, **kwargs):
        raise RuntimeError("target down")

    monkeypatch.setattr(runner, "collect_seed_inventory", boom)

    with pytest.raises(RuntimeError, match="target down"):
        collect_inventory.run_collect_inventory(
            session,
            investigation=investigation,
            base_url="https://example.test/",
            authorize=lambda url: True,
        )

    task = session.query(Task).one()
    assert task.status == "failed"
    assert "RuntimeError: target down" in (task.result_summary or "")


def test_core_never_commits(session: Session, monkeypatch) -> None:
    program = _program(session)
    investigation = start_investigation(program.id, session)
    monkeypatch.setattr(runner, "collect_seed_inventory", _fake_collect())

    def refuse() -> None:
        raise AssertionError("the script core must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    _, _, task = collect_inventory.run_collect_inventory(
        session,
        investigation=investigation,
        base_url="https://example.test/",
        authorize=lambda url: True,
    )
    assert task.status == "completed"

    session.rollback()
    assert session.query(Investigation).count() == 0
    assert session.query(Task).count() == 0


def test_reuses_an_existing_asset(session: Session, monkeypatch) -> None:
    program = _program(session)
    investigation = start_investigation(program.id, session)
    existing = Asset(investigation_id=investigation.id, hostname="example.test")
    session.add(existing)
    session.flush()
    monkeypatch.setattr(runner, "collect_seed_inventory", _fake_collect())

    _, asset, _ = collect_inventory.run_collect_inventory(
        session,
        investigation=investigation,
        base_url="https://example.test/",
        authorize=lambda url: True,
    )

    assert asset.id == existing.id
    assert session.query(Asset).count() == 1


def test_script_source_never_promotes() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    for forbidden in (
        "finding_promotion",
        "promote_to_finding",
        "Hypothesis(",
        "Finding(",
        "Verdict(",
    ):
        assert forbidden not in source, forbidden

    assert "hypothesis.status" not in source
