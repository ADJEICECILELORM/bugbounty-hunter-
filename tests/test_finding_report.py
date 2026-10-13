"""Tests for the Markdown finding report: pure, offline, deterministic."""

from __future__ import annotations

from datetime import UTC, datetime
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
    Verdict,
)
from verification.diff_check import build_diff_result
from verification.evidence import diff_data, store_diff_evidence, store_verdict
from verification.finding_promotion import promote_to_finding
from verification.finding_report import (
    LAB_BANNER,
    FindingReportContext,
    FindingReportContextError,
    collect_finding_context,
    render_finding_report,
)
from verification.http_probe import ProbeResult
from verification.verdict_checker import (
    CROSS_ACCOUNT_SAME_BYTES,
    VerdictClaim,
    check_verdict,
)
from verification.verdict_integrity import DIGEST_SCHEMA

BASKET_A = "http://127.0.0.1:3000/rest/basket/6"
BASKET_B = "http://127.0.0.1:3000/rest/basket/7"
SHA_MATCH_A = "62224ea89597345427001c549b8510aaea3a49d13c98715f67f64710db4738c9"
SHA_OTHER = "77200416dba5b985bf6a26926536c18681c40d4d7cb02915fa5a288bb5eaea56"
TOKEN = "lab-token-secret"

CLAIM = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES)
CONTROL = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False)

REPO_ROOT = Path(__file__).resolve().parent.parent


def probe(
    url: str,
    *,
    content_length: int = 747,
    body_sha256: str = SHA_MATCH_A,
) -> ProbeResult:
    return ProbeResult(
        url=url,
        status_code=200,
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
) -> None:
    diff = build_diff_result(url_a, url_b, probe_a, probe_b)
    observation = store_diff_evidence(hypothesis.id, diff, session)
    store_verdict(hypothesis.id, observation, check_verdict(diff_data(diff), claim), session)


def promote_part_one_finding(session: Session) -> Finding:
    hypothesis = seed_hypothesis(session)
    record_pair(
        session, hypothesis, BASKET_A, BASKET_A, probe(BASKET_A), probe(BASKET_A), CLAIM
    )
    record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_B,
        probe(BASKET_A),
        probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        CONTROL,
    )
    return promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")


def render(session: Session, finding: Finding) -> str:
    return render_finding_report(collect_finding_context(session, finding))


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


# --- content ---------------------------------------------------------------


def test_report_declares_the_lab_origin_and_every_section(session: Session) -> None:
    finding = promote_part_one_finding(session)

    report = render(session, finding)

    assert report.startswith(f"# {finding.title}\n")
    assert LAB_BANNER in report
    for heading in (
        "## Affected asset",
        "## Reproduction",
        "## Observed comparison",
        "## Verdicts",
        "## Limitations",
        "## Approval trail",
    ):
        assert heading in report, heading


def test_report_states_the_values_the_evidence_actually_recorded(
    session: Session,
) -> None:
    finding = promote_part_one_finding(session)

    report = render(session, finding)

    assert "747 bytes" in report
    assert "154 bytes" in report
    assert SHA_MATCH_A[:12] in report
    assert SHA_OTHER[:12] in report
    assert "identical" in report
    assert "HTTP 200" in report


def test_report_records_the_approver_and_the_audit_row(session: Session) -> None:
    finding = promote_part_one_finding(session)

    report = render(session, finding)

    assert "Ada Reviewer" in report
    assert "promote_to_finding" in report
    assert finding.created_at.isoformat() in report


def test_report_never_contains_credentials(session: Session) -> None:
    """Credentials are never stored, so they cannot be rendered."""
    hypothesis = seed_hypothesis(session)
    record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_A,
        probe(BASKET_A),
        probe(BASKET_A),
        CLAIM,
    )
    record_pair(
        session,
        hypothesis,
        BASKET_A,
        BASKET_B,
        probe(BASKET_A),
        probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        CONTROL,
    )
    finding = promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")

    report = render(session, finding)

    assert TOKEN not in report
    assert "Authorization" not in report
    assert "Bearer" not in report


def test_report_does_not_claim_more_than_the_evidence(session: Session) -> None:
    finding = promote_part_one_finding(session)

    report = render(session, finding)

    assert "not a severity assessment" in report
    for overclaim in ("critical", "high severity", "CVSS", "exploitable by anyone"):
        assert overclaim not in report, overclaim


def test_report_lists_the_local_lab_limits(session: Session) -> None:
    finding = promote_part_one_finding(session)

    report = render(session, finding)

    assert "Local lab only" in report
    assert "Credentials are not stored" in report
    assert "Machine-checked, not human-confirmed" in report
    assert "no program has reviewed this report" in report


def test_report_is_not_a_raw_evidence_dump(session: Session) -> None:
    finding = promote_part_one_finding(session)

    report = render(session, finding)

    for raw_key in ("response_time_ms", "header_differences", "content_length_delta"):
        assert raw_key not in report, raw_key
    assert TOKEN not in report, "credentials are never stored, so never rendered"


def test_the_same_evidence_always_renders_identically(session: Session) -> None:
    finding = promote_part_one_finding(session)

    first = render(session, finding)
    second = render(session, finding)
    third = render_finding_report(collect_finding_context(session, finding))

    assert first == second == third


# --- refusals --------------------------------------------------------------


def test_report_refuses_to_render_without_supporting_evidence() -> None:
    """Refuse, rather than emit a report with empty sections."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    finding = Finding(
        hypothesis_id=1,
        title="nothing supported",
        category="access_control",
        approved_by="Ada",
        created_at=now,
    )
    hypothesis = Hypothesis(
        asset_id=1,
        category="access_control",
        description="nothing supported",
        status="verified",
        created_at=now,
    )
    context = FindingReportContext(
        finding=finding,
        hypothesis=hypothesis,
        verdicts=(),
        observations=(),
        control_observations=(),
        audits=(),
    )

    with pytest.raises(FindingReportContextError):
        render_finding_report(context)


def test_context_collection_refuses_a_missing_hypothesis(session: Session) -> None:
    orphan = Finding(
        hypothesis_id=999,
        title="orphan",
        category="access_control",
        approved_by="Ada",
    )
    session.add(orphan)
    session.flush()

    with pytest.raises(FindingReportContextError):
        collect_finding_context(session, orphan)


def test_context_collection_refuses_a_verdict_that_was_edited(
    session: Session,
) -> None:
    finding = promote_part_one_finding(session)
    verdict = session.scalars(select(Verdict).order_by(Verdict.id)).first()
    verdict.rationale = "edited after promotion"
    session.flush()

    with pytest.raises(FindingReportContextError) as error:
        collect_finding_context(session, finding)

    assert "not bound to the evidence" in str(error.value)


def test_context_collection_refuses_a_verdict_with_no_digest(session: Session) -> None:
    finding = promote_part_one_finding(session)
    verdict = session.scalars(select(Verdict).order_by(Verdict.id)).first()
    verdict.integrity_digest = ""
    session.flush()

    with pytest.raises(FindingReportContextError) as error:
        collect_finding_context(session, finding)

    assert "integrity_digest_missing" in str(error.value)


def test_report_states_that_every_verdict_verified(session: Session) -> None:
    finding = promote_part_one_finding(session)

    report = render_finding_report(collect_finding_context(session, finding))

    assert "**Verdict integrity:**" in report
    assert DIGEST_SCHEMA in report


def test_pipes_in_recorded_text_cannot_break_a_table() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    data = {
        "probe_a": {
            "url": BASKET_A,
            "status_code": 200,
            "content_length": 747,
            "body_sha256": SHA_MATCH_A,
        },
        "probe_b": {
            "url": BASKET_A,
            "status_code": 200,
            "content_length": 747,
            "body_sha256": SHA_MATCH_A,
        },
    }
    observation = Observation(
        id=7,
        asset_id=1,
        hypothesis_id=1,
        observation_type="diff_check",
        data=data,
        created_at=now,
    )
    verdict = Verdict(
        id=3,
        hypothesis_id=1,
        observation_id=7,
        claim_type=CROSS_ACCOUNT_SAME_BYTES,
        is_control=False,
        verdict="supported",
        rationale="a | b",
        created_at=now,
    )
    finding = Finding(
        hypothesis_id=1,
        title="pipes",
        category="access_control",
        approved_by="Ada",
        created_at=now,
    )
    hypothesis = Hypothesis(
        asset_id=1,
        category="access_control",
        description="pipes",
        status="verified",
        created_at=now,
    )
    context = FindingReportContext(
        finding=finding,
        hypothesis=hypothesis,
        verdicts=(verdict,),
        observations=(observation,),
        control_observations=(),
        audits=(),
    )

    report = render_finding_report(context)

    row = next(line for line in report.splitlines() if "a \\| b" in line)
    assert row.count("|") == 7, "6 delimiters plus the escaped pipe"
    assert row.startswith("| #3 |")
    assert row.endswith("a \\| b |")


# --- purity guards ---------------------------------------------------------


def test_the_renderer_is_pure_and_offline() -> None:
    source = (REPO_ROOT / "verification" / "finding_report.py").read_text(
        encoding="utf-8"
    )

    for forbidden in (
        "import requests",
        "llm_client",
        "generate_completion",
        "datetime.now",
        "time.time",
        ".commit(",
        ".add(",
        ".status =",
    ):
        assert forbidden not in source, forbidden

    assert "def render_finding_report(context" in source, (
        "the renderer must take a loaded context rather than a session"
    )
