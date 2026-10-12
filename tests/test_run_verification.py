import ipaddress

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Hypothesis, Investigation, Observation, Program
from gateway.dns_pin import PinnedTarget, TargetRejected
from verification import diff_check
from verification.http_probe import ProbeResult
from verification.run_verification import VerificationRunResult, run_verification


def _create_hypothesis(session: Session, *, status: str = "unverified") -> Hypothesis:
    program = Program(
        name="Example Program",
        authorized_scope=["api.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="api.example.test")
    hypothesis = Hypothesis(
        asset=asset,
        category="access_control",
        description="Check whether response behavior differs by account.",
        status=status,
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis


def _probe(url: str, *, status: int, body_hash: str) -> ProbeResult:
    return ProbeResult(
        url=url,
        status_code=status,
        headers={"content-type": "application/json"},
        response_time_ms=4.0,
        content_length=12,
        body_sha256=body_hash,
    )


def _patch_probe_results(
    monkeypatch: pytest.MonkeyPatch,
    results: list[ProbeResult],
) -> list[str]:
    calls: list[str] = []
    result_iter = iter(results)

    def fake_probe(url: str, **_kwargs: object) -> ProbeResult:
        calls.append(url)
        return next(result_iter)

    monkeypatch.setattr(diff_check, "probe_endpoint", fake_probe)
    return calls


def test_full_happy_path_persists_evidence_without_changing_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    url_a = "https://api.example.test/account"
    url_b = "https://api.example.test/account"
    _patch_probe_results(
        monkeypatch,
        [
            _probe(url_a, status=200, body_hash="a" * 64),
            _probe(url_b, status=200, body_hash="b" * 64),
        ],
    )

    with Session(engine) as session:
        hypothesis = _create_hypothesis(session)
        result = run_verification(
            hypothesis.id,
            url_a,
            url_b,
            authorize=lambda _: True,
            session=session,
        )

        stored = session.scalar(
            select(Observation).where(Observation.id == result.observation.id)
        )
        assert isinstance(result, VerificationRunResult)
        assert result.hypothesis_id == hypothesis.id
        assert result.diff.body_match is False
        assert stored is not None
        assert stored.observation_type == "diff_check"
        assert stored.hypothesis_id == hypothesis.id
        assert stored.asset_id == hypothesis.asset_id
        assert hypothesis.status == "unverified"
        assert session.in_transaction()

    engine.dispose()


def test_missing_hypothesis_fails_before_any_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe_calls: list[bool] = []
    monkeypatch.setattr(
        diff_check,
        "probe_endpoint",
        lambda *_args, **_kwargs: probe_calls.append(True),
    )

    with Session(engine) as session:
        with pytest.raises(ValueError, match="Hypothesis with id 999 does not exist"):
            run_verification(
                999,
                "https://api.example.test/a",
                "https://api.example.test/b",
                authorize=lambda _: True,
                session=session,
            )

        assert probe_calls == []
        assert session.scalar(select(func.count()).select_from(Observation)) == 0

    engine.dispose()


def test_probe_failure_propagates_without_storing_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    calls = 0

    def fail_on_second_probe(url: str, **_kwargs: object) -> ProbeResult:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TargetRejected("second target is outside scope")
        return _probe(url, status=200, body_hash="a" * 64)

    monkeypatch.setattr(diff_check, "probe_endpoint", fail_on_second_probe)

    with Session(engine) as session:
        hypothesis = _create_hypothesis(session)
        with pytest.raises(TargetRejected, match="outside scope"):
            run_verification(
                hypothesis.id,
                "https://api.example.test/a",
                "https://outside.example/b",
                authorize=lambda _: True,
                session=session,
            )

        assert calls == 2
        assert session.scalar(select(func.count()).select_from(Observation)) == 0
        assert hypothesis.status == "unverified"

    engine.dispose()


def test_hypothesis_status_never_changes_for_any_diff_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    urls = [
        "https://api.example.test/a1",
        "https://api.example.test/b1",
        "https://api.example.test/a2",
        "https://api.example.test/b2",
        "https://api.example.test/a3",
        "https://api.example.test/b3",
    ]
    _patch_probe_results(
        monkeypatch,
        [
            _probe(urls[0], status=200, body_hash="a" * 64),
            _probe(urls[1], status=403, body_hash="b" * 64),
            _probe(urls[2], status=200, body_hash="c" * 64),
            _probe(urls[3], status=200, body_hash="d" * 64),
            _probe(urls[4], status=200, body_hash="e" * 64),
            _probe(urls[5], status=200, body_hash="e" * 64),
        ],
    )

    with Session(engine) as session:
        hypothesis = _create_hypothesis(session)
        outcomes = []
        for index in range(0, len(urls), 2):
            result = run_verification(
                hypothesis.id,
                urls[index],
                urls[index + 1],
                authorize=lambda _: True,
                session=session,
            )
            outcomes.append((result.diff.status_match, result.diff.body_match))
            assert hypothesis.status == "unverified"

        assert outcomes == [(False, False), (True, False), (True, True)]
        assert session.scalar(select(func.count()).select_from(Observation)) == 3

    engine.dispose()