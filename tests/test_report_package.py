"""Tests for the read-only report zip exporter.

``verification.report_package.build_report_package`` wraps the already-tested
Markdown renderer in a zip with a provenance manifest. These tests pin the
*exporter's own* guarantees: it emits exactly the two expected members, it is
read-only toward the database, its manifest never carries a credential, and a
missing finding raises clearly instead of producing an empty or partial zip.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
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
from verification.http_probe import ProbeResult
from verification.report_package import (
    MANIFEST_MEMBER,
    REPORT_MEMBER,
    build_report_package,
)
from verification.verdict_checker import (
    CROSS_ACCOUNT_SAME_BYTES,
    VerdictClaim,
    check_verdict,
)

BASKET_A = "http://127.0.0.1:3000/rest/basket/6"
BASKET_B = "http://127.0.0.1:3000/rest/basket/7"
SHA_MATCH_A = "62224ea89597345427001c549b8510aaea3a49d13c98715f67f64710db4738c9"
SHA_OTHER = "77200416dba5b985bf6a26926536c18681c40d4d7cb02915fa5a288bb5eaea56"
TOKEN = "lab-token-secret"

CLAIM = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES)
CONTROL = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False)


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


def promote_one_finding(session: Session) -> Finding:
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

    for url_a, url_b, probe_a, probe_b, claim in (
        (BASKET_A, BASKET_A, probe(BASKET_A), probe(BASKET_A), CLAIM),
        (
            BASKET_A,
            BASKET_B,
            probe(BASKET_A),
            probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
            CONTROL,
        ),
    ):
        diff = build_diff_result(url_a, url_b, probe_a, probe_b)
        observation = store_diff_evidence(hypothesis.id, diff, session)
        store_verdict(
            hypothesis.id, observation, check_verdict(diff_data(diff), claim), session
        )

    return promote_to_finding(hypothesis.id, session, approved_by="Ada Reviewer")


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


def test_package_contains_report_and_manifest(
    tmp_path: Path, session: Session
) -> None:
    finding = promote_one_finding(session)

    out = build_report_package(session, finding.id, tmp_path / "finding.zip")

    assert out == (tmp_path / "finding.zip").resolve()
    with zipfile.ZipFile(out) as archive:
        assert set(archive.namelist()) == {REPORT_MEMBER, MANIFEST_MEMBER}
        report = archive.read(REPORT_MEMBER).decode(encoding="utf-8")
        manifest = json.loads(archive.read(MANIFEST_MEMBER))

    assert report.startswith(f"# {finding.title}\n")
    assert manifest["finding_id"] == finding.id
    assert manifest["hypothesis_id"] == finding.hypothesis_id
    assert manifest["approved_by"] == "Ada Reviewer"
    assert manifest["investigation_id"] is not None
    assert manifest["evidence_observation_ids"]
    assert manifest["control_observation_ids"]
    assert manifest["verdict_ids"]
    assert len(manifest["integrity_digest_prefixes"]) == len(manifest["verdict_ids"])
    for prefix in manifest["integrity_digest_prefixes"]:
        assert isinstance(prefix, str)
        assert 1 <= len(prefix) <= 12


def test_package_is_read_only_toward_the_database(
    tmp_path: Path, session: Session
) -> None:
    finding = promote_one_finding(session)
    before = {
        "findings": session.scalar(select(func.count(Finding.id))),
        "verdicts": session.scalar(select(func.count(Verdict.id))),
        "observations": session.scalar(select(func.count(Observation.id))),
    }
    status_before = session.get(Hypothesis, finding.hypothesis_id).status

    build_report_package(session, finding.id, tmp_path / "finding.zip")
    session.expire_all()

    assert session.scalar(select(func.count(Finding.id))) == before["findings"]
    assert session.scalar(select(func.count(Verdict.id))) == before["verdicts"]
    assert session.scalar(select(func.count(Observation.id))) == before["observations"]
    assert session.get(Hypothesis, finding.hypothesis_id).status == status_before


def test_manifest_and_report_never_contain_credentials(
    tmp_path: Path, session: Session
) -> None:
    finding = promote_one_finding(session)

    out = build_report_package(session, finding.id, tmp_path / "finding.zip")
    with zipfile.ZipFile(out) as archive:
        manifest_text = archive.read(MANIFEST_MEMBER).decode(encoding="utf-8")
        report_text = archive.read(REPORT_MEMBER).decode(encoding="utf-8")

    for text in (manifest_text, report_text):
        assert TOKEN not in text
        assert "Authorization" not in text
        assert "Bearer" not in text
        assert "token" not in text.lower()


def test_missing_finding_raises_clearly(session: Session, tmp_path: Path) -> None:
    with pytest.raises(LookupError, match="does not exist"):
        build_report_package(session, 12345, tmp_path / "unused.zip")
