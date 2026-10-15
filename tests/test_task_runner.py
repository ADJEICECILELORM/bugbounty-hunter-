"""Tests for the operator-invoked task dispatcher (V4 Task B).

``orchestration.task_runner.run_task`` is the only place a task turns into work,
and it adds no work of its own: each kind maps to one existing, already-tested
function. The tests mock those functions and assert the dispatch/routing, the
dependency gate, the failure recording, and - in the source - that orchestration
never assigns ``Hypothesis.status``, never commits, and never reaches the
promotion gate.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

import orchestration.task_runner as runner
from data.db import init_db
from data.models import Asset, Hypothesis, Observation, Program
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import (
    complete_task,
    create_task,
    start_task,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ORCHESTRATION_DIR = REPO_ROOT / "orchestration"


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


def seed_asset(session: Session, investigation, hostname: str = "example.test"):
    asset = Asset(investigation_id=investigation.id, hostname=hostname)
    session.add(asset)
    session.flush()
    return asset


def seed_hypothesis(session: Session, asset):
    hypothesis = Hypothesis(
        asset_id=asset.id, category="authz", description="x", status="unverified"
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis


def make_task(session, investigation, *, kind, title="t", params=None, depends_on=None):
    return create_task(
        investigation.id,
        session,
        kind=kind,
        title=title,
        params=params,
        depends_on=depends_on,
    )


def test_inventory_task_dispatches_and_completes(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session,
        investigation,
        kind="inventory",
        params={"asset_id": asset.id, "base_url": "https://example.test/"},
    )

    def fake_collect(base_url, authorize, *, session, asset_id, allow_private_network=False, **kwargs):
        observation = Observation(
            asset_id=asset_id, observation_type="endpoint_inventory", data={"url": base_url}
        )
        session.add(observation)
        session.flush()
        return [observation]

    monkeypatch.setattr(runner, "collect_seed_inventory", fake_collect)
    authorize = lambda url: True  # noqa: E731

    runner.run_task(task.id, session, authorize=authorize)

    assert task.status == "completed"
    assert task.result_summary is not None
    assert [event.event_type for event in task.events] == [
        "created",
        "started",
        "dispatched",
        "completed",
    ]


def test_hypothesis_generation_task_dispatches(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session, investigation, kind="hypothesis_generation", params={"asset_id": asset.id}
    )

    def fake_generate(asset_id, session):
        hypothesis = Hypothesis(
            asset_id=asset_id, category="authz", description="from runner", status="unverified"
        )
        session.add(hypothesis)
        session.flush()
        return [hypothesis]

    monkeypatch.setattr(runner, "generate_hypotheses", fake_generate)

    runner.run_task(task.id, session)

    assert task.status == "completed"


def test_verification_task_dispatches_with_operator_inputs(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    hypothesis = seed_hypothesis(session, asset)
    task = make_task(
        session, investigation, kind="verification", params={"hypothesis_id": hypothesis.id}
    )

    class FakeVerdict:
        id = 1

    class FakeOutcome:
        verdict = FakeVerdict()

    class FakeResult:
        control_outcomes = ()
        primary_outcomes = (FakeOutcome(),)
        outcomes = primary_outcomes

    captured: dict[str, Any] = {}

    def fake_run(hypothesis_id, plan, *, allow_private_network, authorize, session, **kwargs):
        captured.update(
            hypothesis_id=hypothesis_id,
            plan=plan,
            allow_private_network=allow_private_network,
            authorize=authorize,
        )
        return FakeResult()

    monkeypatch.setattr(runner, "run_hypothesis_verification", fake_run)
    authorize = lambda url: True  # noqa: E731
    plan = object()

    runner.run_task(task.id, session, authorize=authorize, verification_plan=plan)

    assert task.status == "completed"
    assert captured["hypothesis_id"] == hypothesis.id
    assert captured["plan"] is plan
    assert captured["authorize"] is authorize
    assert captured["allow_private_network"] is False


def test_unmet_dependency_refuses_before_running(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = make_task(session, investigation, kind="recon", title="first")
    second = make_task(session, investigation, kind="recon", title="second", depends_on=[first.id])

    called: list[Any] = []
    monkeypatch.setattr(runner, "generate_hypotheses", lambda *a, **k: called.append(1))

    with pytest.raises(runner.TaskNotRunnable, match="unfinished"):
        runner.run_task(second.id, session)

    assert second.status == "pending"
    assert [event.event_type for event in second.events] == ["created"]
    assert called == []


def test_met_dependency_runs(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    first = make_task(
        session, investigation, kind="hypothesis_generation", params={"asset_id": asset.id}
    )
    start_task(first.id, session)
    complete_task(first.id, session, final_status="completed")

    second = make_task(
        session,
        investigation,
        kind="hypothesis_generation",
        params={"asset_id": asset.id},
        depends_on=[first.id],
    )
    monkeypatch.setattr(runner, "generate_hypotheses", lambda asset_id, session: [])

    runner.run_task(second.id, session)

    assert second.status == "completed"


def test_exception_is_recorded_and_reraised(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session, investigation, kind="hypothesis_generation", params={"asset_id": asset.id}
    )

    def boom(asset_id, session):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(runner, "generate_hypotheses", boom)

    with pytest.raises(RuntimeError, match="model exploded"):
        runner.run_task(task.id, session)

    assert task.status == "failed"
    assert "RuntimeError" in (task.result_summary or "")
    types = [event.event_type for event in task.events]
    assert types == ["created", "started", "dispatched", "dispatch_failed", "failed"]
    assert task.events[-2].detail["error_type"] == "RuntimeError"


def test_failure_leaves_no_partial_evidence(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session,
        investigation,
        kind="inventory",
        params={"asset_id": asset.id, "base_url": "https://example.test/"},
    )

    def collect_then_boom(base_url, authorize, *, session, asset_id, allow_private_network=False, **kwargs):
        session.add(
            Observation(
                asset_id=asset_id, observation_type="endpoint_inventory", data={"url": base_url}
            )
        )
        session.flush()
        raise RuntimeError("network down")

    monkeypatch.setattr(runner, "collect_seed_inventory", collect_then_boom)

    with pytest.raises(RuntimeError):
        runner.run_task(task.id, session, authorize=lambda u: True)

    assert session.query(Observation).count() == 0
    assert task.status == "failed"


def test_missing_authorize_refuses_before_starting(
    session: Session, investigation
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session,
        investigation,
        kind="inventory",
        params={"asset_id": asset.id, "base_url": "https://example.test/"},
    )

    with pytest.raises(runner.TaskNotRunnable, match="authorize"):
        runner.run_task(task.id, session)

    assert task.status == "pending"
    assert [event.event_type for event in task.events] == ["created"]


def test_missing_verification_plan_refuses(session: Session, investigation) -> None:
    asset = seed_asset(session, investigation)
    hypothesis = seed_hypothesis(session, asset)
    task = make_task(
        session, investigation, kind="verification", params={"hypothesis_id": hypothesis.id}
    )

    with pytest.raises(runner.TaskNotRunnable, match="verification_plan"):
        runner.run_task(task.id, session, authorize=lambda u: True)

    assert task.status == "pending"


def test_non_dispatchable_kind_refuses(session: Session, investigation) -> None:
    task = make_task(session, investigation, kind="recon")

    with pytest.raises(runner.TaskNotRunnable, match="no dispatcher"):
        runner.run_task(task.id, session)

    assert task.status == "pending"


def test_run_task_rejects_a_missing_task(session: Session) -> None:
    with pytest.raises(LookupError, match="Task 4242 does not exist"):
        runner.run_task(4242, session)


def test_run_task_never_commits(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session, investigation, kind="hypothesis_generation", params={"asset_id": asset.id}
    )

    def refuse():
        raise AssertionError("must not commit")

    monkeypatch.setattr(session, "commit", refuse)
    monkeypatch.setattr(runner, "generate_hypotheses", lambda asset_id, session: [])

    runner.run_task(task.id, session)

    assert task.status == "completed"


def test_orchestration_never_assigns_hypothesis_status_or_promotes() -> None:
    sources = [path.read_text(encoding="utf-8") for path in ORCHESTRATION_DIR.glob("*.py")]
    assert sources, "expected orchestration sources to scan"

    for source in sources:
        assert re.search(r"hypothesis\.status\s*=(?!=)", source) is None
        assert "finding_promotion" not in source
        assert "promote_to_finding" not in source


def test_orchestration_never_commits_or_writes_statuses_directly() -> None:
    sources = [path.read_text(encoding="utf-8") for path in ORCHESTRATION_DIR.glob("*.py")]
    assert sources, "expected orchestration sources to scan"

    for source in sources:
        assert ".commit(" not in source
        assert re.search(r"\btask\.(status|started_at|ended_at)\s*=(?!=)", source) is None
        assert re.search(r"investigation\.status\s*=(?!=)", source) is None
        assert "from gateway.lab_mode" not in source


