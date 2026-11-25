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
from sqlalchemy import select
from sqlalchemy.orm import Session

import orchestration.task_runner as runner
from data.db import init_db
from data.models import Asset, Hypothesis, Observation, Program, TaskObservation
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
        authorized_scope=["example.test", "*.example.test"],
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


def test_inventory_task_records_provenance_links(
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
            asset_id=asset_id,
            observation_type="endpoint_inventory",
            data={"url": base_url, "status_code": 200},
        )
        session.add(observation)
        session.flush()
        return [observation]

    monkeypatch.setattr(runner, "collect_seed_inventory", fake_collect)
    runner.run_task(task.id, session, authorize=lambda url: True)

    links = session.scalars(
        select(TaskObservation).where(TaskObservation.task_id == task.id)
    ).all()
    assert len(links) == 1
    assert links[0].role == "output"
    assert session.get(Observation, links[0].observation_id) is not None


def test_inventory_task_refuses_scope_removed_since_authorizer_creation(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session,
        investigation,
        kind="inventory",
        params={"asset_id": asset.id, "base_url": "https://example.test/"},
    )
    called = []
    monkeypatch.setattr(
        runner,
        "collect_seed_inventory",
        lambda *args, **kwargs: called.append(True),
    )
    # This callback represents a CLI snapshot built before an operator narrows
    # the program scope. The dispatcher must also consult the stored current scope.
    investigation.program.authorized_scope = ["other.example.test"]
    session.flush()

    with pytest.raises(runner.TaskNotRunnable, match="no longer authorized"):
        runner.run_task(task.id, session, authorize=lambda _url: True)

    assert called == []
    assert task.status == "pending"
    assert [event.event_type for event in task.events] == ["created"]


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


def test_hypothesis_generation_records_input_observation_links(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation)
    observation = Observation(
        asset_id=asset.id,
        observation_type="dns_record",
        data={"record_type": "A", "value": "192.0.2.10"},
    )
    session.add(observation)
    session.flush()
    task = make_task(
        session, investigation, kind="hypothesis_generation", params={"asset_id": asset.id}
    )
    monkeypatch.setattr(runner, "generate_hypotheses", lambda _asset_id, _session: [])

    runner.run_task(task.id, session)

    link = session.scalar(
        select(TaskObservation).where(TaskObservation.task_id == task.id)
    )
    assert link is not None
    assert (link.observation_id, link.role) == (observation.id, "input")


def test_task_observation_link_rejects_cross_investigation_evidence(
    session: Session, investigation
) -> None:
    asset = seed_asset(session, investigation)
    task = make_task(
        session,
        investigation,
        kind="research_brief",
        params={"asset_id": asset.id},
    )
    other_investigation = start_investigation(investigation.program_id, session)
    other_asset = seed_asset(
        session, other_investigation, hostname="other.example.test"
    )
    observation = Observation(
        asset_id=other_asset.id,
        observation_type="dns_record",
        data={"record_type": "A", "value": "192.0.2.1"},
    )
    session.add(observation)
    session.flush()

    with pytest.raises(ValueError, match="another investigation"):
        runner.record_task_observation_links(
            task,
            session,
            observation_ids=[observation.id],
            role="input",
        )
    assert session.scalar(
        select(TaskObservation.id).where(TaskObservation.task_id == task.id)
    ) is None


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
        def __init__(self, observation):
            self.verdict = FakeVerdict()
            self.observation = observation

    captured: dict[str, Any] = {}

    def fake_run(hypothesis_id, plan, *, allow_private_network, authorize, session, **kwargs):
        observation = Observation(
            asset_id=hypothesis.asset_id,
            hypothesis_id=hypothesis_id,
            observation_type="diff_check",
            data={"probe_a": {}, "probe_b": {}},
        )
        session.add(observation)
        session.flush()
        outcome = FakeOutcome(observation)

        class FakeResult:
            control_outcomes = ()
            primary_outcomes = (outcome,)
            outcomes = primary_outcomes

        captured.update(
            hypothesis_id=hypothesis_id,
            plan=plan,
            allow_private_network=allow_private_network,
            authorize=authorize,
        )
        return FakeResult()

    monkeypatch.setattr(runner, "run_hypothesis_verification", fake_run)
    authorize = lambda url: True  # noqa: E731
    plan = type("BoundPlan", (), {"hypothesis_id": hypothesis.id})()

    runner.run_task(
        task.id,
        session,
        authorize=authorize,
        allow_private_network=True,
        verification_plan=plan,
        approve_verification=True,
    )

    assert task.status == "completed"
    assert captured["hypothesis_id"] == hypothesis.id
    assert captured["plan"] is plan
    assert captured["authorize"] is not authorize
    assert captured["authorize"]("https://example.test/") is True
    assert captured["authorize"]("https://outside.invalid/") is False
    assert captured["allow_private_network"] is True
    link = session.scalar(
        select(TaskObservation).where(TaskObservation.task_id == task.id)
    )
    assert link is not None
    assert (link.observation_id, link.role) == (
        session.scalar(select(Observation.id).where(Observation.hypothesis_id == hypothesis.id)),
        "output",
    )


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


def test_verification_plan_alone_is_not_an_execution_approval(
    session: Session,
    investigation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = seed_asset(session, investigation)
    hypothesis = seed_hypothesis(session, asset)
    task = make_task(
        session, investigation, kind="verification", params={"hypothesis_id": hypothesis.id}
    )
    called: list[bool] = []
    monkeypatch.setattr(runner, "run_hypothesis_verification", lambda *a, **k: called.append(True))

    with pytest.raises(runner.TaskNotRunnable, match="explicit approve_verification"):
        runner.run_task(
            task.id,
            session,
            authorize=lambda _url: True,
            verification_plan=type(
                "BoundPlan", (), {"hypothesis_id": hypothesis.id}
            )(),
        )

    assert task.status == "pending"
    assert called == []


def test_non_dispatchable_kind_refuses(session: Session, investigation) -> None:
    task = make_task(session, investigation, kind="hypothesis_review")

    with pytest.raises(runner.TaskNotRunnable, match="no dispatcher"):
        runner.run_task(task.id, session)

    assert task.status == "pending"


def test_recon_task_dispatches_only_after_operator_authorization(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    task = make_task(session, investigation, kind="recon")
    calls: list[str] = []

    def fake_discover(hostname, policy, rate_limiter):
        calls.append(hostname)
        return [
            {"type": "dns_record", "record_type": "A", "value": "203.0.113.10"}
        ]

    monkeypatch.setattr(runner, "passive_discover", fake_discover)

    runner.run_task(task.id, session, authorize=lambda _url: True)

    assert calls == [asset.hostname]
    assert task.status == "completed"
    observation = session.query(Observation).filter_by(asset_id=asset.id).one()
    link = session.scalar(
        select(TaskObservation).where(TaskObservation.task_id == task.id)
    )
    assert link is not None
    assert (link.observation_id, link.role) == (observation.id, "output")


def test_recon_skips_targets_rejected_by_operator_scope_before_dns(
    session: Session, investigation, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_asset(session, investigation)
    task = make_task(session, investigation, kind="recon")
    calls: list[str] = []
    monkeypatch.setattr(
        runner,
        "passive_discover",
        lambda *args: calls.append("called") or [],
    )

    with pytest.raises(runner.TaskNotRunnable, match="no asset currently authorized"):
        runner.run_task(task.id, session, authorize=lambda _url: False)

    assert calls == []
    assert task.status == "pending"


def test_research_brief_task_dispatch_is_idempotent_for_repeated_evidence(
    session: Session, investigation
) -> None:
    asset = seed_asset(session, investigation, hostname="api.example.test")
    observation = Observation(
        asset_id=asset.id,
        observation_type="endpoint_inventory",
        data={"url": "https://api.example.test/account", "status_code": 200},
    )
    session.add(observation)
    session.flush()
    first = make_task(
        session,
        investigation,
        kind="research_brief",
        params={"asset_id": asset.id},
    )
    second = make_task(
        session,
        investigation,
        kind="research_brief",
        title="Repeat offline brief",
        params={"asset_id": asset.id},
    )

    runner.run_task(first.id, session)
    runner.run_task(second.id, session)

    from data.models import Hypothesis, HypothesisSupportingObservation

    assert first.status == second.status == "completed"
    assert session.query(Hypothesis).filter_by(asset_id=asset.id).count() == 1
    assert (
        session.query(HypothesisSupportingObservation)
        .filter_by(observation_id=observation.id)
        .count()
        == 1
    )
    for task in (first, second):
        links = session.scalars(
            select(TaskObservation).where(TaskObservation.task_id == task.id)
        ).all()
        assert [(link.observation_id, link.role) for link in links] == [
            (observation.id, "input")
        ]


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


def test_only_explicit_task_runner_mode_commits_before_dispatch() -> None:
    paths = list(ORCHESTRATION_DIR.glob("*.py"))
    assert paths, "expected orchestration sources to scan"

    committers = {
        path.name
        for path in paths
        if ".commit(" in path.read_text(encoding="utf-8")
    }
    assert committers == {"task_runner.py"}
    runner_source = (ORCHESTRATION_DIR / "task_runner.py").read_text(encoding="utf-8")
    assert "if commit_before_dispatch:" in runner_source
    assert "session.commit()" in runner_source

    for source in (path.read_text(encoding="utf-8") for path in paths):
        assert re.search(r"\btask\.(status|started_at|ended_at)\s*=(?!=)", source) is None
        assert re.search(r"investigation\.status\s*=(?!=)", source) is None
        assert "from gateway.lab_mode" not in source
