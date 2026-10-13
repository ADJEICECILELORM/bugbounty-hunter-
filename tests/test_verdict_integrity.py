"""Tests for the verdict integrity binding: verdict -> evidence -> hypothesis -> target.

Every tamper below is applied to a row that the real writer stored, and the
fixtures use the exact values the Part 1 lab run recorded, so what is under test
is the binding rather than a hand-made shape.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import (
    Asset,
    Hypothesis,
    Investigation,
    Observation,
    Program,
    Verdict,
)
from verification.diff_check import DiffResult, build_diff_result
from verification.evidence import diff_data, store_diff_evidence, store_verdict
from verification.http_probe import ProbeResult
from verification.verdict_checker import (
    CROSS_ACCOUNT_SAME_BYTES,
    VerdictClaim,
    check_verdict,
)
from verification.verdict_integrity import (
    DIGEST_MALFORMED,
    DIGEST_MISMATCH,
    DIGEST_MISSING,
    EVIDENCE_HYPOTHESIS_MISMATCH,
    EVIDENCE_INVALID,
    EVIDENCE_MISSING,
    EVIDENCE_SUBSTITUTED,
    EVIDENCE_TYPE_MISMATCH,
    RE_DERIVED_DISAGREES,
    VERDICT_HYPOTHESIS_MISMATCH,
    VERDICT_SHAPE_INVALID,
    canonical_json,
    digest_for,
    evidence_digest,
    target_urls,
    verdict_digest,
    verify_verdict,
)

BASKET_A = "http://127.0.0.1:3000/rest/basket/6"
BASKET_B = "http://127.0.0.1:3000/rest/basket/7"
SHA_MATCH_A = "62224ea89597345427001c549b8510aaea3a49d13c98715f67f64710db4738c9"
SHA_OTHER = "77200416dba5b985bf6a26926536c18681c40d4d7cb02915fa5a288bb5eaea56"

CLAIM = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES)
CONTROL = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False)

REPO_ROOT = Path(__file__).resolve().parent.parent
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


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


def seed_hypothesis(session: Session) -> Hypothesis:
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
        status="unverified",
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
) -> tuple[Observation, Verdict, Any]:
    """Store one comparison the way the runner does, digest and all."""
    diff: DiffResult = build_diff_result(url_a, url_b, probe_a, probe_b)
    observation = store_diff_evidence(hypothesis.id, diff, session)
    result = check_verdict(diff_data(diff), claim)
    verdict = store_verdict(hypothesis.id, observation, result, session)
    return observation, verdict, result


def record_claim_pair(
    session: Session, hypothesis: Hypothesis, url: str = BASKET_A
) -> tuple[Observation, Verdict, Any]:
    return record_pair(session, hypothesis, url, url, probe(url), probe(url), CLAIM)


def record_control_pair(
    session: Session, hypothesis: Hypothesis
) -> tuple[Observation, Verdict, Any]:
    return record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_B,
        probe(BASKET_A),
        probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        CONTROL,
    )


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


# --- rows the writer stored verify as stored --------------------------------


def test_a_stored_verdict_verifies_against_its_evidence(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, result = record_claim_pair(session, hypothesis)

    assert result.verdict == "supported"
    assert _SHA256.match(verdict.integrity_digest), "the row carries a sha256"
    assert verdict.integrity_digest == digest_for(verdict, observation)

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    assert check.ok is True
    assert (check.reason, check.detail) == ("", "")


def test_a_stored_control_verdict_also_verifies(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_control_pair(session, hypothesis)

    assert verdict.is_control is True
    assert verify_verdict(verdict, observation, hypothesis_id=hypothesis.id).ok is True


# --- the digest itself ------------------------------------------------------


def test_the_digest_is_deterministic_and_field_sensitive() -> None:
    base: dict[str, Any] = {
        "claim_type": CROSS_ACCOUNT_SAME_BYTES,
        "is_control": False,
        "verdict": "supported",
        "rationale": "both probes matched",
        "hypothesis_id": 1,
        "observation_id": 2,
        "target": (BASKET_A, BASKET_A),
        "evidence_sha256": "a" * 64,
    }

    assert verdict_digest(**base) == verdict_digest(**base)
    assert _SHA256.match(verdict_digest(**base))

    for field, forged in (
        ("claim_type", "open_redirect"),
        ("is_control", True),
        ("verdict", "inconclusive"),
        ("rationale", "forged"),
        ("hypothesis_id", 99),
        ("observation_id", 98),
        ("target", (BASKET_B, BASKET_B)),
        ("evidence_sha256", "b" * 64),
    ):
        assert verdict_digest(**dict(base, **{field: forged})) != verdict_digest(
            **base
        ), field


def test_canonical_json_ignores_key_order() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"a": 2}) == b'{"a":2}'


def test_the_evidence_digest_tracks_the_stored_bytes(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, _, _ = record_claim_pair(session, hypothesis)

    first = evidence_digest(observation)
    assert first == evidence_digest(observation)

    observation.data["probe_b"] = dict(observation.data["probe_b"], content_length=154)
    assert evidence_digest(observation) != first


def test_evidence_that_is_not_a_mapping_has_no_digest() -> None:
    raw = Observation(asset_id=1, observation_type="diff_check", data=[1, 2])

    assert evidence_digest(raw) is None


def test_target_urls_are_read_from_the_recorded_probes(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    claim, _, _ = record_claim_pair(session, hypothesis)
    control, _, _ = record_control_pair(session, hypothesis)

    assert target_urls(claim) == (BASKET_A, BASKET_A)
    assert target_urls(control) == (BASKET_A, BASKET_B)


# --- tampering: each binding in turn ---------------------------------------


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        pytest.param("verdict", "inconclusive", id="verdict"),
        pytest.param("claim_type", "open_redirect", id="claim-type"),
        pytest.param("rationale", "a forged rationale", id="rationale"),
        pytest.param("is_control", True, id="control-flag"),
    ],
)
def test_an_edited_field_no_longer_matches_its_digest(
    session: Session, field: str, forged: Any
) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)
    assert verify_verdict(verdict, observation, hypothesis_id=hypothesis.id).ok

    setattr(verdict, field, forged)

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    assert check.ok is False
    assert check.reason == DIGEST_MISMATCH


def test_editing_the_evidence_invalidates_the_verdict_that_judged_it(
    session: Session,
) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)

    observation.data["probe_b"] = dict(
        observation.data["probe_b"], body_sha256=SHA_OTHER
    )

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    assert check.reason == DIGEST_MISMATCH


def test_a_valid_looking_digest_over_the_wrong_evidence_is_rejected(
    session: Session,
) -> None:
    """The digest can be made consistent with another row; the judgement cannot."""
    hypothesis = seed_hypothesis(session)
    claim_observation, verdict, _ = record_claim_pair(session, hypothesis)
    control_observation, _, _ = record_control_pair(session, hypothesis)
    assert claim_observation.id != control_observation.id

    verdict.observation_id = control_observation.id
    verdict.integrity_digest = digest_for(verdict, control_observation)
    assert verdict.integrity_digest is not None, "the forged digest looks valid"

    check = verify_verdict(verdict, control_observation, hypothesis_id=hypothesis.id)
    assert check.ok is False
    assert check.reason == RE_DERIVED_DISAGREES
    assert "supported" in check.detail


def test_a_digest_rebound_to_another_hypothesis_is_rejected(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)
    other = seed_hypothesis(session)

    verdict.hypothesis_id = other.id
    verdict.integrity_digest = digest_for(verdict, observation)

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    assert check.reason == VERDICT_HYPOTHESIS_MISMATCH


def test_evidence_from_another_hypothesis_is_rejected(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    _, verdict, _ = record_claim_pair(session, hypothesis)
    other = seed_hypothesis(session)
    foreign_observation, _, _ = record_claim_pair(session, other)

    verdict.observation_id = foreign_observation.id
    verdict.integrity_digest = digest_for(verdict, foreign_observation)

    check = verify_verdict(verdict, foreign_observation, hypothesis_id=hypothesis.id)
    assert check.reason == EVIDENCE_HYPOTHESIS_MISMATCH


def test_a_digest_rebound_to_another_target_is_rejected(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)
    other_url = "http://127.0.0.1:3000/rest/basket/1"

    verdict.integrity_digest = verdict_digest(
        claim_type=verdict.claim_type,
        is_control=verdict.is_control,
        verdict=verdict.verdict,
        rationale=verdict.rationale,
        hypothesis_id=hypothesis.id,
        observation_id=observation.id,
        target=(other_url, other_url),
        evidence_sha256=evidence_digest(observation),
    )

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    assert check.reason == DIGEST_MISMATCH


def test_a_row_without_a_digest_is_invalid() -> None:
    observation = Observation(
        id=1, asset_id=1, hypothesis_id=1, observation_type="diff_check", data={}
    )
    verdict = Verdict(
        hypothesis_id=1,
        observation_id=1,
        claim_type=CROSS_ACCOUNT_SAME_BYTES,
        is_control=False,
        verdict="supported",
        rationale="hand-written, nothing binds it",
        integrity_digest="",
    )

    assert (
        verify_verdict(verdict, observation, hypothesis_id=1).reason == DIGEST_MISSING
    )

    verdict.integrity_digest = "not-a-sha256"
    assert (
        verify_verdict(verdict, observation, hypothesis_id=1).reason == DIGEST_MALFORMED
    )


def test_missing_or_substituted_evidence_is_invalid(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)
    other_observation, _, _ = record_control_pair(session, hypothesis)

    assert (
        verify_verdict(verdict, None, hypothesis_id=hypothesis.id).reason
        == EVIDENCE_MISSING
    )
    assert (
        verify_verdict(verdict, other_observation, hypothesis_id=hypothesis.id).reason
        == EVIDENCE_SUBSTITUTED
    )


def test_non_comparison_evidence_is_rejected(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)
    observation.observation_type = "http_headers"

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    assert check.reason == EVIDENCE_TYPE_MISMATCH


def test_a_claim_type_the_checker_cannot_judge_is_bound_by_its_digest_only(
    session: Session,
) -> None:
    hypothesis = seed_hypothesis(session)
    observation, verdict, _ = record_claim_pair(session, hypothesis)
    verdict.claim_type = "open_redirect"
    verdict.integrity_digest = digest_for(verdict, observation)

    assert verify_verdict(verdict, observation, hypothesis_id=hypothesis.id).ok is True

    verdict.rationale = "edited after the fact"
    assert (
        verify_verdict(verdict, observation, hypothesis_id=hypothesis.id).reason
        == DIGEST_MISMATCH
    )


@pytest.mark.parametrize(
    "rubbish",
    [
        pytest.param(None, id="none"),
        pytest.param(42, id="int"),
        pytest.param(object(), id="object"),
    ],
)
def test_a_verdict_that_is_not_a_row_is_invalid_not_a_crash(
    session: Session, rubbish: Any
) -> None:
    hypothesis = seed_hypothesis(session)
    observation, _, _ = record_claim_pair(session, hypothesis)

    check = verify_verdict(rubbish, observation, hypothesis_id=hypothesis.id)
    assert check.ok is False
    assert check.reason == VERDICT_SHAPE_INVALID


def test_evidence_that_is_not_a_row_is_invalid_not_a_crash(session: Session) -> None:
    hypothesis = seed_hypothesis(session)
    _, verdict, _ = record_claim_pair(session, hypothesis)

    check = verify_verdict(verdict, "not a row", hypothesis_id=hypothesis.id)
    assert check.ok is False
    assert check.reason == EVIDENCE_INVALID


# --- purity guards ---------------------------------------------------------


def test_the_judge_and_the_verifier_are_offline_and_session_free() -> None:
    for name in ("verdict_checker.py", "verdict_integrity.py"):
        source = (REPO_ROOT / "verification" / name).read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "llm_client",
            "generate_completion",
            "sqlalchemy",
            ".commit(",
            ".add(",
            "datetime.now",
            "promote_to_finding(",
        ):
            assert forbidden not in source, f"{name} must not contain {forbidden}"

    verify_source = (REPO_ROOT / "verification" / "verdict_integrity.py").read_text(
        encoding="utf-8"
    )
    assert "def verify_verdict(" in verify_source
    assert "def digest_for(" in verify_source
