import ipaddress

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Hypothesis, Investigation, Observation, Program
from gateway.lab_mode import LabPinnedTarget
from verification import lab_verification
from verification.http_probe import ProbeResult


def _create_hypothesis(session: Session) -> Hypothesis:
    program = Program(
        name="Local Juice Shop Lab",
        authorized_scope=["127.0.0.1"],
        excluded_scope=[],
        rate_limit=10,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="127.0.0.1")
    hypothesis = Hypothesis(
        asset=asset,
        category="access_control",
        description="Compare lab responses for two test accounts.",
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis


def test_explicit_lab_runner_pins_both_requests_and_stores_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    pinned_calls: list[tuple[str, bool]] = []
    probe_calls: list[str] = []
    probe_opt_ins: list[bool] = []

    def fake_pin_lab_url(
        url: str,
        *,
        allow_private_network: bool,
        authorize: object,
        resolver: object,
    ) -> LabPinnedTarget:
        assert callable(authorize) and authorize(url)
        pinned_calls.append((url, allow_private_network))
        return LabPinnedTarget(
            url=url,
            hostname="127.0.0.1",
            port=3000,
            addresses=(ipaddress.ip_address("127.0.0.1"),),
        )

    def fake_probe(
        target: LabPinnedTarget,
        *,
        allow_private_network: bool,
        **_kwargs: object,
    ) -> ProbeResult:
        probe_calls.append(target.url)
        probe_opt_ins.append(allow_private_network)
        status = 200 if len(probe_calls) == 1 else 403
        body_hash = str(len(probe_calls)) * 64
        return ProbeResult(
            url=target.url,
            status_code=status,
            headers={"content-type": "application/json"},
            response_time_ms=2.0,
            content_length=12,
            body_sha256=body_hash,
        )

    monkeypatch.setattr(lab_verification, "pin_lab_url", fake_pin_lab_url)
    monkeypatch.setattr(lab_verification, "probe_lab_target", fake_probe)

    with Session(engine) as session:
        hypothesis = _create_hypothesis(session)
        authorize = lambda _: True
        result = lab_verification.run_lab_verification(
            hypothesis.id,
            "http://127.0.0.1:3000/rest/basket/1",
            "http://127.0.0.1:3000/rest/basket/1",
            allow_private_network=True,
            authorize=authorize,
            session=session,
        )

        assert result.hypothesis_id == hypothesis.id
        assert result.diff.status_match is False
        assert pinned_calls == [
            ("http://127.0.0.1:3000/rest/basket/1", True),
            ("http://127.0.0.1:3000/rest/basket/1", True),
        ]
        assert probe_calls == [
            "http://127.0.0.1:3000/rest/basket/1",
            "http://127.0.0.1:3000/rest/basket/1",
        ]
        assert probe_opt_ins == [True, True]
        stored = session.scalar(
            select(Observation).where(Observation.id == result.observation.id)
        )
        assert stored is not None
        assert stored.hypothesis_id == hypothesis.id
        assert stored.asset_id == hypothesis.asset_id
        assert hypothesis.status == "unverified"
        assert session.in_transaction()

    engine.dispose()