"""Tests for the human promotion gate - the only status writer in the project."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import (
    Asset,
    Finding,
    Hypothesis,
    Investigation,
    Observation,
    Program,
    PromotionAudit,
    Verdict,
)
from verification.diff_check import DiffResult, build_diff_result
from verification.evidence import diff_data, store_diff_evidence, store_verdict
from verification.finding_promotion import (
    PROMOTION_ACTION,
    VERIFIED_STATUS,
    PromotionRefused,
    promote_to_finding,
)
from verification.http_probe import ProbeResult
from verification.verdict_checker import (
    CROSS_ACCOUNT_SAME_BYTES,
    SUPPORTED,
    VerdictClaim,
    VerdictResult,
    check_verdict,
)

BASKET_A = "http://127.0.0.1:3000/rest/basket/6"
BASKET_B = "http://127.0.0.1:3000/rest/basket/7"
SHA_MATCH_A = "62224ea89597345427001c549b8510aaea3a49d13c98715f67f64710db4738c9"
SHA_OTHER = "77200416dba5b985bf6a26926536c18681c40d4d7cb02915fa5a288bb5eaea56"

CLAIM = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES)
CONTROL = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False)

REPO_ROOT = Path(__file__).resolve().parent.parent
STATUS_WRITER = "finding_promotion.py"


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


def record_pair(
    session: Session,
    hypothesis: Hypothesis,
    url_a: str,
    url_b: str,
    probe_a: ProbeResult,
    probe_b: ProbeResult,
    claim: VerdictClaim,
) -> tuple[Observation, Verdict, VerdictResult]:
    diff: DiffResult = build_diff_result(url_a, url_b, probe_a, probe_b)
    observation = store_diff_evidence(hypothesis.id, diff, session)
    result = check_verdict(diff_data(diff), claim)
    verdict = store_verdict(hypothesis.id, observation, result, session)
    return observation, verdict, result


def seed_supported_evidence(session: Session, hypothesis: Hypothesis) -> tuple[Any, ...]:
    """The Part 1 shape: one matching claim pair and one differing control pair."""
    supported = record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_A,
        probe(BASKET_A),
        probe(BASKET_A),
        CLAIM,
    )
    control = record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_B,
        probe(BASKET_A),
        probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        CONTROL,
    )
    assert supported[2].verdict == SUPPORTED
    return supported + control


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


# --- the happy path --------------------------------------------------------


def test_promotion_creates_a_finding_and_records_the_approval(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    supported_observation, supported_verdict, *_ = seed_supported_evidence(
        session, hypothesis
    )

    finding = promote_to_finding(
        hypothesis.id, session, approved_by="  Ada Reviewer  "
    )

    assert finding.id is not None
    assert finding.hypothesis_id == hypothesis.id
    assert finding.approved_by == "Ada Reviewer", "the approver name is trimmed"
    assert finding.category == "access_control"
    assert finding.title == "access_control: 127.0.0.1/rest/basket/6"
    assert session.get(Hypothesis, hypothesis.id).status == VERIFIED_STATUS

    audits = session.scalars(select(PromotionAudit)).all()
    assert len(audits) == 1
    audit = audits[0]
    assert audit.action == PROMOTION_ACTION
    assert audit.actor == "Ada Reviewer"
    assert audit.hypothesis_id == hypothesis.id
    assert audit.finding_id == finding.id
    assert audit.evidence_ids == [supported_observation.id]
    assert audit.verdict_ids == [supported_verdict.id], "controls are never cited"


def test_custom_titles_are_trimmed_and_truncated(session: Session) -> None:
    first = seed_hypothesis(session)
    seed_supported_evidence(session, first)
    second = seed_hypothesis(session)
    seed_supported_evidence(session, second)

    trimmed = promote_to_finding(first.id, session, approved_by="Ada", title="  Hi  ")
    long_title = promote_to_finding(
        second.id, session, approved_by="Ada", title="x" * 400
    )

    assert trimmed.title == "Hi"
    assert len(long_title.title) == 255


# --- refusals --------------------------------------------------------------


def test_promotion_requires_a_named_approver(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)

    for approver in ("", "   ", None, 42):
        with pytest.raises(PromotionRefused):
            promote_to_finding(hypothesis.id, session, approved_by=approver)

    assert session.scalars(select(Finding)).all() == []
    assert session.get(Hypothesis, hypothesis.id).status == "unverified"


def test_a_double_promotion_is_refused(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)
    promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "unverified" in str(error.value)
    assert len(session.scalars(select(Finding)).all()) == 1
    assert len(session.scalars(select(PromotionAudit)).all()) == 1


def test_promotion_is_refused_without_a_supported_verdict(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_B,
        probe(BASKET_A),
        probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        CONTROL,
    )

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "no supported verdict" in str(error.value)
    assert session.scalars(select(Finding)).all() == []
    assert session.get(Hypothesis, hypothesis.id).status == "unverified"


def test_promotion_is_refused_when_a_verdict_refutes_the_claim(
    session: Session,
) -> None:
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)
    refuted = record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_A,
        probe(BASKET_A),
        probe(BASKET_A, content_length=154, body_sha256=SHA_OTHER),
        CLAIM,
    )
    assert refuted[2].verdict == "refuted"

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "contradictory" in str(error.value)
    assert session.scalars(select(Finding)).all() == []


def test_promotion_is_refused_when_the_status_is_unexpected(session: Session) -> None:
    hypothesis = seed_hypothesis(session, status="confirmed")
    seed_supported_evidence(session, hypothesis)

    with pytest.raises(PromotionRefused):
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert session.get(Hypothesis, hypothesis.id).status == "confirmed"


def test_an_unknown_hypothesis_is_a_lookup_error(session: Session) -> None:
    with pytest.raises(LookupError):
        promote_to_finding(999, session, approved_by="Ada Reviewer")


def test_promotion_is_refused_when_the_evidence_row_is_gone(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, *_ = seed_supported_evidence(session, hypothesis)
    session.delete(observation)
    session.flush()

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "does not exist" in str(error.value)
    assert session.scalars(select(Finding)).all() == []


def test_promotion_is_refused_when_evidence_belongs_to_another_hypothesis(
    session: Session,
) -> None:
    source = seed_hypothesis(session)
    target = seed_hypothesis(session)
    foreign_observation, *_ = seed_supported_evidence(session, source)
    seed_supported_evidence(session, target)
    session.add(
        Verdict(
            hypothesis_id=target.id,
            observation_id=foreign_observation.id,
            claim_type=CROSS_ACCOUNT_SAME_BYTES,
            is_control=False,
            verdict=SUPPORTED,
            rationale="hand-written row pointing at another hypothesis",
            integrity_digest="0" * 64,
        )
    )
    session.flush()

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(target.id, session, approved_by="Ada Reviewer")

    assert "belonging to hypothesis" in str(error.value)
    assert session.scalars(select(Finding)).all() == []


def test_promotion_is_refused_for_evidence_that_is_not_a_diff_check(
    session: Session,
) -> None:
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)
    other_evidence = Observation(
        asset_id=hypothesis.asset_id,
        hypothesis_id=hypothesis.id,
        observation_type="http_headers",
        data={},
    )
    session.add(other_evidence)
    session.flush()
    session.add(
        Verdict(
            hypothesis_id=hypothesis.id,
            observation_id=other_evidence.id,
            claim_type=CROSS_ACCOUNT_SAME_BYTES,
            is_control=False,
            verdict=SUPPORTED,
            rationale="hand-written row over non-comparison evidence",
            integrity_digest="0" * 64,
        )
    )
    session.flush()

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "not a diff_check" in str(error.value)


def test_promotion_is_refused_for_inventory_context_evidence(session: Session) -> None:
    """Inventory rows are summarizer context: nothing built on them is promotable."""
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)
    inventory_evidence = Observation(
        asset_id=hypothesis.asset_id,
        hypothesis_id=hypothesis.id,
        observation_type="endpoint_inventory",
        data={"url": BASKET_A, "status_code": 200, "content_length": 747},
    )
    session.add(inventory_evidence)
    session.flush()
    session.add(
        Verdict(
            hypothesis_id=hypothesis.id,
            observation_id=inventory_evidence.id,
            claim_type=CROSS_ACCOUNT_SAME_BYTES,
            is_control=False,
            verdict=SUPPORTED,
            rationale="hand-written row over inventory context",
            integrity_digest="0" * 64,
        )
    )
    session.flush()

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "not a diff_check" in str(error.value)
    assert session.scalars(select(Finding)).all() == []


def test_promotion_is_refused_when_a_supporting_verdict_was_edited(
    session: Session,
) -> None:
    hypothesis = seed_hypothesis(session)
    _, supported_verdict, _ = seed_supported_evidence(session, hypothesis)[:3]

    supported_verdict.rationale = "edited after the review"

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "integrity" in str(error.value)
    assert session.scalars(select(Finding)).all() == []
    assert session.get(Hypothesis, hypothesis.id).status == "unverified"


def test_promotion_is_refused_when_the_bound_evidence_was_edited(
    session: Session,
) -> None:
    hypothesis = seed_hypothesis(session)
    supported_observation, _, _ = seed_supported_evidence(session, hypothesis)[:3]

    supported_observation.data["probe_b"] = dict(
        supported_observation.data["probe_b"], content_length=154
    )

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "integrity" in str(error.value)
    assert session.scalars(select(Finding)).all() == []


def test_promotion_is_refused_when_a_control_verdict_was_edited(
    session: Session,
) -> None:
    """An edited control row means the judgements for this hypothesis are untrusted."""
    hypothesis = seed_hypothesis(session)
    evidence = seed_supported_evidence(session, hypothesis)
    control_verdict = evidence[4]

    control_verdict.verdict = "supported"

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "integrity" in str(error.value)


def test_a_supported_row_that_no_digest_binds_is_refused(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)
    diff = build_diff_result(BASKET_A, BASKET_A, probe(BASKET_A), probe(BASKET_A))
    observation = Observation(
        asset_id=hypothesis.asset_id,
        hypothesis_id=hypothesis.id,
        observation_type="diff_check",
        data=diff_data(diff),
    )
    session.add(observation)
    session.flush()
    session.add(
        Verdict(
            hypothesis_id=hypothesis.id,
            observation_id=observation.id,
            claim_type=CROSS_ACCOUNT_SAME_BYTES,
            is_control=False,
            verdict=SUPPORTED,
            rationale="hand-written, with a well-formed but unrelated digest",
            integrity_digest="0" * 64,
        )
    )
    session.flush()

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "integrity" in str(error.value)
    assert session.scalars(select(Finding)).all() == []


def test_promotion_is_refused_when_a_verdict_is_rebound_to_other_evidence(
    session: Session,
) -> None:
    """A digest computed for one observation must not bind the verdict to another."""
    hypothesis = seed_hypothesis(session)
    _, original_verdict, _ = seed_supported_evidence(session, hypothesis)[:3]

    other_observation, _, _ = record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_A,
        probe(BASKET_A, body_sha256=SHA_OTHER),
        probe(BASKET_A, body_sha256=SHA_OTHER),
        CLAIM,
    )

    original_verdict.observation_id = other_observation.id

    with pytest.raises(PromotionRefused) as error:
        promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    assert "integrity" in str(error.value)
    assert session.scalars(select(Finding)).all() == []
    assert session.get(Hypothesis, hypothesis.id).status == "unverified"


def test_promotion_leaves_the_transaction_to_the_caller(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    seed_supported_evidence(session, hypothesis)
    promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    session.rollback()

    assert session.scalars(select(Finding)).all() == []
    assert session.scalars(select(PromotionAudit)).all() == []
    assert session.get(Hypothesis, hypothesis.id) is None


# --- structural guards -----------------------------------------------------


def python_sources(*directories: str) -> list[Path]:
    paths: list[Path] = []
    for directory in directories:
        paths.extend(sorted((REPO_ROOT / directory).glob("*.py")))
    return paths


def test_only_the_promotion_gate_writes_a_hypothesis_status() -> None:
    # ``Investigation.status`` is a separate lifecycle field, written only by
    # ``verification/investigation_lifecycle.py``, so this guard scopes to
    # hypothesis-status writes rather than any ``.status`` assignment. It scans
    # every tracked Python source directory - not just the verification stack -
    # so no module anywhere can slip a status write past the single promotion
    # gate.
    writers = [
        path.name
        for path in python_sources(
            "verification",
            "intelligence",
            "gateway",
            "data",
            "orchestration",
            "scripts",
            "workers",
        )
        if re.search(r"hypothesis\.status\s*=(?!=)", path.read_text(encoding="utf-8"))
    ]

    assert writers == [STATUS_WRITER], (
        "a hypothesis status may only be written by the human promotion gate"
    )


def test_only_the_promotion_gate_creates_findings() -> None:
    creators = [
        path.name
        for path in python_sources("verification", "intelligence", "gateway", "data")
        if re.search(r"(?<!class )\bFinding\(", path.read_text(encoding="utf-8"))
    ]

    assert creators == [STATUS_WRITER]


def test_the_promotion_gate_has_no_model_or_network_path() -> None:
    source = (REPO_ROOT / "verification" / STATUS_WRITER).read_text(encoding="utf-8")

    for forbidden in (
        "import requests",
        "llm_client",
        "generate_completion",
        ".commit(",
        "check_verdict",  # the gate delegates the binding check, never re-decides
        "probe_endpoint",
    ):
        assert forbidden not in source, forbidden


VERIFICATION_MODULES = (
    "verdict_checker.py",
    "verdict_integrity.py",
    "run_hypothesis_verification.py",
    "evidence.py",
    "finding_report.py",
)


def test_no_other_verification_module_can_reach_the_promotion_gate() -> None:
    """3.1, 3.2 and their helpers must not import or call the gate."""
    for name in VERIFICATION_MODULES:
        source = (REPO_ROOT / "verification" / name).read_text(encoding="utf-8")

        assert "finding_promotion" not in source, name
        assert not re.search(r"promote_to_finding\s*\(", source), name
