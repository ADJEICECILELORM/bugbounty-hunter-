"""Temporary-database integration coverage for the supervised pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

import orchestration.task_runner as runner
from data.db import create_database_engine, initialize_fresh_database
from data.models import Asset, Hypothesis, Investigation, Observation, Program, Task
from orchestration.supervised_cycle import run_supervised_cycle
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import complete_task, create_task, start_task
from verification.run_hypothesis_verification import (
    RequestPair,
    VerificationTestPlan,
)
from verification.task_recovery import create_retry_task, mark_task_failed_after_crash
from verification.verdict_checker import VerdictClaim


@pytest.fixture()
def session(tmp_path: Path):
    engine = create_database_engine(
        f"sqlite+pysqlite:///{tmp_path / 'supervised-pipeline.db'}"
    )
    initialize_fresh_database(engine)
    with Session(engine) as active_session:
        yield active_session
    engine.dispose()


def _investigation(session: Session, *, max_tasks: int | None = None):
    program = Program(
        name="Pipeline test",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=5,
    )
    session.add(program)
    session.flush()
    investigation = start_investigation(program.id, session)
    investigation.max_tasks = max_tasks
    session.flush()
    return investigation


def _asset(session: Session, investigation: Investigation) -> Asset:
    asset = Asset(investigation_id=investigation.id, hostname="api.example.test")
    session.add(asset)
    session.flush()
    return asset


def _plan(hypothesis_id: int) -> VerificationTestPlan:
    return VerificationTestPlan(
        pairs=(
            RequestPair(
                name="control",
                url_a="https://api.example.test/a",
                url_b="https://api.example.test/b",
                claim=VerdictClaim(
                    type="cross_account_same_bytes", control_expected_match=False
                ),
            ),
            RequestPair(
                name="claim",
                url_a="https://api.example.test/private",
                url_b="https://api.example.test/private",
                claim=VerdictClaim(type="cross_account_same_bytes"),
                extra_headers_a={"Authorization": "transient-a"},
                extra_headers_b={"Authorization": "transient-b"},
            ),
        ),
        hypothesis_id=hypothesis_id,
    )


def test_pipeline_reaches_human_gated_verification_without_real_network_or_llm(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    session.add(
        Observation(
            asset_id=asset.id,
            observation_type="endpoint_inventory",
            data={"url": "https://api.example.test/private", "status_code": 200},
        )
    )
    recon = create_task(
        investigation.id, session, kind="recon", title="Passive DNS discovery"
    )
    passive_calls: list[str] = []

    def fake_passive(hostname, policy, limiter):
        passive_calls.append(hostname)
        return [{"type": "dns_record", "record_type": "A", "value": "192.0.2.9"}]

    monkeypatch.setattr(runner, "passive_discover", fake_passive)

    first = run_supervised_cycle(
        investigation.id,
        session,
        execute=True,
        authorize=lambda _url: True,
    )
    assert [result.ok for result in first.executed] == [True, True]
    assert passive_calls == [asset.hostname]
    assert session.query(Observation).filter_by(observation_type="dns_record").count() == 1
    assert session.query(Task).count() == 4  # recon plus one non-duplicated planned chain
    brief_hypothesis = session.query(Hypothesis).filter_by(
        category="access_control_review"
    ).one()

    def fake_generate(asset_id, active_session):
        candidate = Hypothesis(
            asset_id=asset_id,
            category="idor",
            description="Review the private endpoint access boundary",
            status="unverified",
        )
        active_session.add(candidate)
        active_session.flush()
        return [candidate]

    monkeypatch.setattr(runner, "generate_hypotheses", fake_generate)
    generated = run_supervised_cycle(investigation.id, session, execute=True)
    assert [result.kind for result in generated.executed] == ["hypothesis_generation"]
    assert session.query(Task).count() == 4

    review = session.query(Task).filter_by(kind="hypothesis_review").one()
    start_task(review.id, session)
    complete_task(review.id, session, final_status="completed")
    hypothesis = session.query(Hypothesis).filter_by(category="idor").one()
    verification = create_task(
        investigation.id,
        session,
        kind="verification",
        title="Operator-approved verification",
        params={"hypothesis_id": hypothesis.id},
    )
    calls: list[int] = []

    def fake_verify(hypothesis_id, plan, **kwargs):
        calls.append(hypothesis_id)
        assert plan is supplied_plan
        assert kwargs["allow_private_network"] is True
        return SimpleNamespace(
            outcomes=(
                SimpleNamespace(verdict=SimpleNamespace(id=1), observation=None),
                SimpleNamespace(verdict=SimpleNamespace(id=2), observation=None),
            ),
            control_outcomes=(
                SimpleNamespace(verdict=SimpleNamespace(id=1), observation=None),
            ),
            primary_outcomes=(
                SimpleNamespace(verdict=SimpleNamespace(id=2), observation=None),
            ),
        )

    supplied_plan = _plan(hypothesis.id)
    monkeypatch.setattr(runner, "run_hypothesis_verification", fake_verify)
    refused = run_supervised_cycle(investigation.id, session, execute=True)
    assert [item.reason for item in refused.skipped] == ["verification_plan_required"]
    assert verification.status == "pending"
    assert calls == []

    approved = run_supervised_cycle(
        investigation.id,
        session,
        execute=True,
        authorize=lambda _url: True,
        allow_private_network=True,
        verification_plan=supplied_plan,
        approve_verification=True,
    )
    assert approved.executed[0].ok is True
    assert verification.status == "completed"
    assert calls == [hypothesis.id]
    assert brief_hypothesis.status == hypothesis.status == "unverified"


def test_failed_task_requires_explicit_retry_and_recovery(session: Session, monkeypatch):
    investigation = _investigation(session)
    _asset(session, investigation)
    task = create_task(
        investigation.id, session, kind="recon", title="Retryable passive recon"
    )
    calls = 0

    def flaky_passive(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("controlled fixture failure")
        return []

    monkeypatch.setattr(runner, "passive_discover", flaky_passive)
    failed = run_supervised_cycle(
        investigation.id,
        session,
        execute=True,
        authorize=lambda _url: True,
    )
    assert failed.executed[0].ok is False
    assert task.status == "failed"
    repeated = run_supervised_cycle(
        investigation.id,
        session,
        execute=True,
        authorize=lambda _url: True,
    )
    assert repeated.proposed == []
    assert calls == 1

    retry = create_retry_task(task.id, session)
    recovered = run_supervised_cycle(
        investigation.id,
        session,
        execute=True,
        authorize=lambda _url: True,
    )
    assert recovered.executed[0].task_id == retry.id
    assert recovered.executed[0].ok is True
    assert retry.status == "completed"
    assert calls == 2


def test_budget_exhaustion_defers_the_complete_asset_plan(session: Session) -> None:
    investigation = _investigation(session, max_tasks=2)
    asset = _asset(session, investigation)
    session.add(
        Observation(
            asset_id=asset.id,
            observation_type="endpoint_inventory",
            data={"url": "https://api.example.test/private", "status_code": 200},
        )
    )
    session.flush()

    report = run_supervised_cycle(investigation.id, session, execute=True)

    assert report.proposed == []
    assert report.executed == []
    assert [item.reason for item in report.skipped] == ["budget", "empty"]
    assert session.query(Task).count() == 0


def test_stuck_task_blocks_then_recovers_after_operator_action(session: Session):
    investigation = _investigation(session)
    task = create_task(
        investigation.id, session, kind="recon", title="Interrupted recon"
    )
    start_task(task.id, session)
    task.started_at = datetime.now(UTC) - timedelta(hours=2)
    session.flush()

    blocked = run_supervised_cycle(
        investigation.id, session, execute=True, threshold_seconds=30
    )
    assert [item.reason for item in blocked.skipped] == ["stuck"]
    assert task.status == "running"

    mark_task_failed_after_crash(task.id, session, reason="operator confirmed process exit")
    retry = create_retry_task(task.id, session)
    completed = run_supervised_cycle(investigation.id, session, execute=True)
    # No authorizer is supplied, so the retry remains pending and the dispatcher
    # refuses before any network path. Recovery is still an explicit step.
    assert completed.executed[0].ok is False
    assert retry.status == "pending"
