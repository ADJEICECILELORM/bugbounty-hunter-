"""Tests for the gated verification runner.

The transports are faked so the tests are offline, but everything else is real:
real models, a real session, the real diff and verdict code. The scenario mirrors
the Part 1 lab run - one control pair and one claim pair - so the runner is
exercised against the shape the project has actually stored.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

import verification.run_hypothesis_verification as runner
from data.db import init_db
from data.models import Asset, Hypothesis, Investigation, Observation, Program, Verdict
from gateway.dns_pin import TargetRejected
from gateway.lab_mode import LabModeNotExplicitlyEnabled
from verification.http_probe import ProbeResult
from verification.run_hypothesis_verification import (
    InvalidTestPlan,
    RequestPair,
    SetupControlError,
    VerificationTestPlan,
)
from verification.verdict_checker import (
    CONTROL_DISCRIMINATED,
    CROSS_ACCOUNT_SAME_BYTES,
    INCONCLUSIVE,
    REFUTED,
    SUPPORTED,
    VerdictClaim,
)
from verification.verdict_integrity import digest_for, evidence_digest, verify_verdict

BASKET_A = "http://127.0.0.1:3000/rest/basket/6"
BASKET_B = "http://127.0.0.1:3000/rest/basket/7"
SHA_MATCH_A = "62224ea89597345427001c549b8510aaea3a49d13c98715f67f64710db4738c9"
SHA_OTHER = "77200416dba5b985bf6a26926536c18681c40d4d7cb02915fa5a288bb5eaea56"
TOKEN_A = "Bearer lab-token-a"
TOKEN_B = "Bearer lab-token-b"

CLAIM = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES)
CONTROL = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False)


def probe(
    url: str,
    *,
    status_code: int = 200,
    content_length: int = 747,
    body_sha256: str = SHA_MATCH_A,
) -> ProbeResult:
    return ProbeResult(
        url=url,
        status_code=status_code,
        headers={"content-type": "application/json"},
        response_time_ms=1.0,
        content_length=content_length,
        body_sha256=body_sha256,
    )


def part_one_responses() -> dict[tuple[str, str], ProbeResult]:
    """What the Part 1 lab run saw, keyed by (url, authorization header)."""
    return {
        (BASKET_A, ""): probe(BASKET_A),
        (BASKET_B, ""): probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        (BASKET_A, TOKEN_A): probe(BASKET_A),
        (BASKET_A, TOKEN_B): probe(BASKET_A),
    }


def part_one_plan() -> VerificationTestPlan:
    return VerificationTestPlan(
        pairs=(
            RequestPair(
                name="control-two-different-baskets",
                url_a=BASKET_A,
                url_b=BASKET_B,
                claim=CONTROL,
            ),
            RequestPair(
                name="claim-same-basket-two-identities",
                url_a=BASKET_A,
                url_b=BASKET_A,
                claim=CLAIM,
                extra_headers_a={"Authorization": TOKEN_A},
                extra_headers_b={"Authorization": TOKEN_B},
            ),
        )
    )


class FakeTransport:
    """Records every pin/probe call and replays canned probe results."""

    def __init__(self, responses: dict[tuple[str, str], ProbeResult]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, Any]] = []

    def pin(self, url: str, **kwargs: Any) -> Any:
        self.calls.append(("pin", url))
        return SimpleNamespace(url=url, is_lab_target=True)

    def probe(self, target: Any, **kwargs: Any) -> ProbeResult:
        headers = kwargs.get("extra_headers") or {}
        key = (target.url, headers.get("Authorization", ""))
        self.calls.append(("probe", key))
        if key not in self.responses:
            raise AssertionError(f"unexpected probe of {key}")
        return self.responses[key]

    @property
    def probes(self) -> list[tuple[str, str]]:
        return [argument for call, argument in self.calls if call == "probe"]


def install_transport(
    monkeypatch: pytest.MonkeyPatch,
    responses: dict[tuple[str, str], ProbeResult],
) -> FakeTransport:
    transport = FakeTransport(responses)
    monkeypatch.setattr(runner, "pin_lab_url", transport.pin)
    monkeypatch.setattr(runner, "probe_lab_target", transport.probe)
    return transport


def seed_hypothesis(session: Session, status: str = "unverified") -> Hypothesis:
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
        description="Basket 6 may be readable by another account",
        status=status,
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


def authorize(url: str) -> bool:
    return url.startswith("http://127.0.0.1:3000/")


# --- the Part 1 scenario, end to end ---------------------------------------


def run_plan(
    session: Session,
    hypothesis_id: int,
    plan: VerificationTestPlan,
    *,
    allow_private_network: bool = True,
) -> Any:
    return runner.run_hypothesis_verification(
        hypothesis_id,
        plan,
        allow_private_network=allow_private_network,
        authorize=authorize,
        session=session,
        timeout_seconds=5.0,
    )


def test_part_one_scenario_stores_evidence_and_verdicts(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    transport = install_transport(monkeypatch, part_one_responses())

    result = run_plan(session, hypothesis.id, part_one_plan())

    assert len(result.control_outcomes) == 1
    assert len(result.primary_outcomes) == 1
    control = result.control_outcomes[0]
    claim = result.primary_outcomes[0]

    assert control.result.reasons == (CONTROL_DISCRIMINATED,)
    assert control.verdict.is_control is True
    assert claim.result.verdict == SUPPORTED
    assert claim.verdict.is_control is False
    assert claim.verdict.verdict == SUPPORTED

    assert len(session.scalars(select(Observation)).all()) == 2
    assert len(session.scalars(select(Verdict)).all()) == 2
    for outcome in result.outcomes:
        assert outcome.observation.observation_type == "diff_check"
        assert outcome.observation.hypothesis_id == hypothesis.id
        assert outcome.verdict.observation_id == outcome.observation.id


def test_controls_are_probed_before_any_claim_pair(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    transport = install_transport(monkeypatch, part_one_responses())

    run_plan(session, hypothesis.id, part_one_plan())

    assert transport.probes == [
        (BASKET_A, ""),
        (BASKET_B, ""),
        (BASKET_A, TOKEN_A),
        (BASKET_A, TOKEN_B),
    ]
    assert transport.calls[0] == ("pin", BASKET_A)


def test_the_stored_evidence_is_exactly_what_the_verdict_judged(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    install_transport(monkeypatch, part_one_responses())

    result = run_plan(session, hypothesis.id, part_one_plan())

    for outcome in result.outcomes:
        judged = outcome.observation.data
        assert judged["probe_a"]["body_sha256"] == SHA_MATCH_A
        assert judged["status_match"] is True
        assert judged["probe_b"]["url"] == outcome.pair.url_b


def test_verification_never_writes_a_status(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    install_transport(monkeypatch, part_one_responses())

    run_plan(session, hypothesis.id, part_one_plan())

    session.expire_all()
    assert session.get(Hypothesis, hypothesis.id).status == "unverified"


def test_runner_leaves_the_transaction_to_the_caller(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing survives a rollback, which is only true if nothing committed."""
    hypothesis = seed_hypothesis(session)
    install_transport(monkeypatch, part_one_responses())
    run_plan(session, hypothesis.id, part_one_plan())

    session.rollback()

    assert session.scalars(select(Observation)).all() == []
    assert session.scalars(select(Verdict)).all() == []
    assert session.scalars(select(Hypothesis)).all() == []


def test_request_credentials_are_never_stored(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    install_transport(monkeypatch, part_one_responses())

    run_plan(session, hypothesis.id, part_one_plan())

    for observation in session.scalars(select(Observation)).all():
        serialized = str(observation.data)
        assert "lab-token" not in serialized
        assert "Authorization" not in serialized


# --- failed setup controls and claims --------------------------------------


def test_control_that_matches_aborts_before_any_evidence_is_written(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    responses = part_one_responses()
    responses[(BASKET_B, "")] = probe(BASKET_B)  # identical to BASKET_A
    transport = install_transport(monkeypatch, responses)

    with pytest.raises(SetupControlError) as error:
        run_plan(session, hypothesis.id, part_one_plan())

    assert "did not discriminate" in str(error.value)
    assert session.scalars(select(Observation)).all() == []
    assert session.scalars(select(Verdict)).all() == []
    assert transport.probes == [(BASKET_A, ""), (BASKET_B, "")]


def test_thin_control_data_aborts_the_run(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    responses = part_one_responses()
    responses[(BASKET_A, "")] = probe(
        BASKET_A, content_length=0, body_sha256="0" * 64
    )
    responses[(BASKET_B, "")] = probe(
        BASKET_B, content_length=0, body_sha256="0" * 64
    )
    install_transport(monkeypatch, responses)

    with pytest.raises(SetupControlError):
        run_plan(session, hypothesis.id, part_one_plan())

    assert session.scalars(select(Verdict)).all() == []


def test_a_refuted_claim_is_recorded_as_a_verdict(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refuted claim still gets a verdict; it simply cannot support a finding."""
    hypothesis = seed_hypothesis(session)
    responses = part_one_responses()
    # The same URL served a different body to the second identity.
    responses[(BASKET_A, TOKEN_B)] = probe(
        BASKET_A, content_length=154, body_sha256=SHA_OTHER
    )
    install_transport(monkeypatch, responses)

    result = run_plan(session, hypothesis.id, part_one_plan())

    claim = result.primary_outcomes[0]
    assert claim.verdict.verdict == REFUTED
    assert claim.verdict.verdict != SUPPORTED


def test_a_probe_that_reports_back_some_other_url_cannot_support_the_claim(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The recorded URL is authoritative, so a mismatch is inconclusive."""
    hypothesis = seed_hypothesis(session)
    responses = part_one_responses()
    responses[(BASKET_A, TOKEN_B)] = probe(BASKET_B)
    install_transport(monkeypatch, responses)

    result = run_plan(session, hypothesis.id, part_one_plan())

    assert result.primary_outcomes[0].verdict.verdict == INCONCLUSIVE


def test_an_unknown_hypothesis_is_a_lookup_error(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_transport(monkeypatch, part_one_responses())

    with pytest.raises(LookupError):
        run_plan(session, 999, part_one_plan())


def test_every_stored_verdict_verifies_against_its_evidence(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    install_transport(monkeypatch, part_one_responses())

    result = run_plan(session, hypothesis.id, part_one_plan())

    for outcome in result.outcomes:
        check = verify_verdict(
            outcome.verdict, outcome.observation, hypothesis_id=hypothesis.id
        )
        assert check.ok is True, check.reason
        assert outcome.verdict.integrity_digest == digest_for(
            outcome.verdict, outcome.observation
        )
        assert evidence_digest(outcome.observation)

    for stored in session.scalars(select(Verdict)).all():
        observation = session.get(Observation, stored.observation_id)
        assert (
            verify_verdict(stored, observation, hypothesis_id=hypothesis.id).ok is True
        )


def test_rollback_after_a_run_leaves_no_orphaned_rows(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner flushes and never commits, so a rolled-back run writes nothing."""
    hypothesis = seed_hypothesis(session)
    session.commit()
    install_transport(monkeypatch, part_one_responses())

    run_plan(session, hypothesis.id, part_one_plan())
    assert len(session.scalars(select(Observation)).all()) == 2
    assert len(session.scalars(select(Verdict)).all()) == 2

    session.rollback()

    assert session.scalars(select(Observation)).all() == []
    assert session.scalars(select(Verdict)).all() == []
    assert session.get(Hypothesis, hypothesis.id) is not None, (
        "the caller's committed work is untouched"
    )


def test_a_target_outside_scope_aborts_before_any_request(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every target is pinned up front, so an out-of-scope one costs no request."""
    hypothesis = seed_hypothesis(session)
    transport = FakeTransport({})
    # Only the probe is faked: the real authorization and pinning must run.
    monkeypatch.setattr(runner, "probe_lab_target", transport.probe)
    out_of_scope = "http://evil.example/rest/basket/6"
    plan = VerificationTestPlan(
        pairs=(
            control_pair(),
            RequestPair(
                name="claim-out-of-scope",
                url_a=out_of_scope,
                url_b=out_of_scope,
                claim=CLAIM,
                extra_headers_a={"Authorization": TOKEN_A},
                extra_headers_b={"Authorization": TOKEN_B},
            ),
        )
    )

    with pytest.raises(TargetRejected):
        run_plan(session, hypothesis.id, plan)

    assert transport.calls == [], "no request may be sent"
    assert session.scalars(select(Observation)).all() == []
    assert session.scalars(select(Verdict)).all() == []


# --- plan validation happens before any request ----------------------------


def control_pair(name: str = "control", url_a: str = BASKET_A, url_b: str = BASKET_B) -> RequestPair:
    return RequestPair(name=name, url_a=url_a, url_b=url_b, claim=CONTROL)


def claim_pair(
    name: str = "claim",
    *,
    url_a: str = BASKET_A,
    url_b: str = BASKET_A,
    headers_a: dict[str, str] | None = None,
    headers_b: dict[str, str] | None = None,
) -> RequestPair:
    return RequestPair(
        name=name,
        url_a=url_a,
        url_b=url_b,
        claim=CLAIM,
        extra_headers_a=headers_a if headers_a is not None else {"Authorization": TOKEN_A},
        extra_headers_b=headers_b if headers_b is not None else {"Authorization": TOKEN_B},
    )


INVALID_PLANS = {
    "no-control-pair": VerificationTestPlan(pairs=(claim_pair(),)),
    "no-claim-pair": VerificationTestPlan(pairs=(control_pair(),)),
    "single-pair": VerificationTestPlan(pairs=(claim_pair(),)),
    "control-compares-one-url": VerificationTestPlan(
        pairs=(control_pair(url_b=BASKET_A), claim_pair())
    ),
    "claim-compares-two-urls": VerificationTestPlan(
        pairs=(control_pair(), claim_pair(url_b=BASKET_B))
    ),
    "claim-without-headers": VerificationTestPlan(
        pairs=(control_pair(), claim_pair(headers_a={}, headers_b={}))
    ),
    "claim-with-one-side-only": VerificationTestPlan(
        pairs=(control_pair(), claim_pair(headers_b={}))
    ),
    "claim-with-identical-identities": VerificationTestPlan(
        pairs=(
            control_pair(),
            claim_pair(headers_a={"Authorization": TOKEN_A}, headers_b={"Authorization": TOKEN_A}),
        )
    ),
    "duplicate-pair-names": VerificationTestPlan(
        pairs=(control_pair("same-name"), claim_pair("same-name"))
    ),
    "empty-pair-name": VerificationTestPlan(pairs=(control_pair(""), claim_pair())),
    "unsupported-claim-type": VerificationTestPlan(
        pairs=(
            control_pair(),
            RequestPair(
                name="open-redirect",
                url_a=BASKET_A,
                url_b=BASKET_A,
                claim=VerdictClaim("open_redirect"),
                extra_headers_a={"Authorization": TOKEN_A},
                extra_headers_b={"Authorization": TOKEN_B},
            ),
        )
    ),
    "entry-is-not-a-pair": VerificationTestPlan(pairs=(control_pair(), object())),
}


@pytest.mark.parametrize(
    "plan",
    [pytest.param(plan, id=name) for name, plan in INVALID_PLANS.items()],
)
def test_invalid_plans_are_refused_before_any_request(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
    plan: VerificationTestPlan,
) -> None:
    hypothesis = seed_hypothesis(session)
    transport = install_transport(monkeypatch, part_one_responses())

    with pytest.raises(InvalidTestPlan):
        run_plan(session, hypothesis.id, plan)

    assert transport.calls == []
    assert session.scalars(select(Observation)).all() == []


def test_missing_lab_opt_in_is_refused_before_any_request(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    hypothesis = seed_hypothesis(session)
    transport = install_transport(monkeypatch, part_one_responses())

    with pytest.raises(LabModeNotExplicitlyEnabled):
        run_plan(session, hypothesis.id, part_one_plan(), allow_private_network=False)

    assert transport.calls == []


def test_plan_shape_is_validated_before_the_hypothesis_is_looked_up(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_transport(monkeypatch, part_one_responses())

    with pytest.raises(InvalidTestPlan):
        run_plan(session, 999, INVALID_PLANS["no-control-pair"])


def test_validation_helper_accepts_the_part_one_plan() -> None:
    runner.validate_test_plan(part_one_plan(), allow_private_network=True)


# --- the module's only transport is the guarded lab one --------------------


def test_source_uses_only_the_guarded_lab_transport() -> None:
    from pathlib import Path

    source = Path(runner.__file__).read_text(encoding="utf-8")

    for forbidden in (
        "probe_endpoint",  # the public gateway path
        "compare_requests",  # the un-gated diff helper
        "import requests",  # a raw HTTP client
        "run_verification",  # the non-lab runner
        ".commit(",  # transactions belong to the caller
        ".status =",  # only the promotion gate may write a status
        "promote_to_finding(",  # verification cannot promote, only name the gate
    ):
        assert forbidden not in source, forbidden
