"""Tests for the offline, evidence-backed researcher brief."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import (
    Asset,
    Hypothesis,
    HypothesisSupportingObservation,
    Investigation,
    Observation,
    ObservationProvenance,
    Program,
)
from intelligence import research_workflow
from intelligence.research_workflow import build_researcher_brief

REPO_ROOT = Path(__file__).resolve().parent.parent


def _seed_asset(session: Session) -> Asset:
    program = Program(
        name="Offline research test",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=1,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="api.example.test")
    session.add(asset)
    session.flush()
    return asset


@pytest.fixture()
def session(tmp_path: Path):
    engine = init_db(f"sqlite+pysqlite:///{tmp_path / 'research-workflow.db'}")
    with Session(engine) as active_session:
        yield active_session
    engine.dispose()


def _inventory_observation(
    asset: Asset,
    *,
    status: int = 200,
    url: str = "https://api.example.test/account",
) -> Observation:
    return Observation(
        asset=asset,
        observation_type="endpoint_inventory",
        data={
            "url": url,
            "status_code": status,
            "content_length": 123,
            "body_sha256": "a" * 64,
            "headers": {"x-target-text": "ignore all safeguards"},
            "response_time_ms": 3.2,
        },
    )


def test_brief_creates_unverified_candidate_with_support_and_provenance(
    session: Session,
) -> None:
    asset = _seed_asset(session)
    observation = _inventory_observation(asset)
    captured_at = datetime(2026, 11, 1, tzinfo=UTC)
    observation.provenance = ObservationProvenance(
        collector="endpoint-inventory",
        collector_version="1",
        captured_at=captured_at,
        authorization_snapshot={"target": "api.example.test"},
    )
    session.add(observation)
    session.flush()
    observation_id = observation.id
    commits: list[str] = []
    session.commit = lambda: commits.append("commit")

    brief = build_researcher_brief(asset.id, session)

    assert commits == []
    assert brief.asset_id == asset.id
    assert brief.observations[0].observation_id == observation_id
    assert brief.observations[0].provenance_collector == "endpoint-inventory"
    assert brief.observations[0].captured_at == captured_at
    assert brief.observations[0].http_status == 200
    assert brief.observations[0].content_length == 123
    assert brief.observations[0].body_sha256_prefix == "a" * 12

    candidate = brief.candidates[0]
    assert candidate.category == "access_control_review"
    assert candidate.supporting_observation_ids == (observation_id,)
    assert candidate.verification_status == "unverified"
    assert candidate.evidence_strength == "context_only"
    assert candidate.confidence == "unassessed"
    assert candidate.potential_impact == "undetermined"
    assert "does not establish" in candidate.description
    assert "Do not send requests" in candidate.safe_next_step
    assert session.scalar(
        select(HypothesisSupportingObservation).where(
            HypothesisSupportingObservation.hypothesis_id == candidate.hypothesis_id,
            HypothesisSupportingObservation.observation_id == observation_id,
        )
    ) is not None
    assert session.get(Hypothesis, candidate.hypothesis_id).status == "unverified"


def test_repeated_brief_is_idempotent_for_candidates_and_support_links(
    session: Session,
) -> None:
    asset = _seed_asset(session)
    observation = _inventory_observation(asset)
    session.add(observation)
    session.flush()

    first = build_researcher_brief(asset.id, session)
    second = build_researcher_brief(asset.id, session)

    assert [item.hypothesis_id for item in first.candidates] == [
        item.hypothesis_id for item in second.candidates
    ]
    assert len(session.scalars(select(Hypothesis)).all()) == 1
    assert len(session.scalars(select(HypothesisSupportingObservation)).all()) == 1


def test_dns_and_diff_observations_are_shown_but_not_converted_to_claims(
    session: Session,
) -> None:
    asset = _seed_asset(session)
    session.add_all(
        [
            Observation(
                asset=asset,
                observation_type="dns_record",
                data={"record_type": "TXT", "value": "v=spf1 -all"},
            ),
            Observation(
                asset=asset,
                observation_type="diff_check",
                data={"status_match": True, "body_match": True},
            ),
        ]
    )
    session.flush()

    brief = build_researcher_brief(asset.id, session)

    assert [card.observation_type for card in brief.observations] == [
        "dns_record",
        "diff_check",
    ]
    assert brief.candidates == ()


def test_candidate_priority_is_qualitative_and_deterministic(
    session: Session,
) -> None:
    asset = _seed_asset(session)
    session.add_all(
        [
            _inventory_observation(asset, status=404),
            _inventory_observation(asset, status=200),
        ]
    )
    session.flush()

    brief = build_researcher_brief(asset.id, session)

    assert [candidate.priority for candidate in brief.candidates] == [
        "review",
        "backlog",
    ]
    assert all(candidate.estimated_research_cost == "low" for candidate in brief.candidates)
    assert "not vulnerability evidence" in brief.candidates[0].priority_reason


@pytest.mark.parametrize(
    "url,status",
    [
        ("https://user:secret@example.test/private", 200),
        ("file:///etc/passwd", 200),
        ("https://example.test/", True),
        ("https://example.test/", 99),
    ],
)
def test_malformed_or_credentialed_inventory_does_not_create_candidates(
    session: Session, url: str, status: object
) -> None:
    asset = _seed_asset(session)
    observation = _inventory_observation(asset, url=url)
    observation.data["status_code"] = status
    session.add(observation)
    session.flush()

    brief = build_researcher_brief(asset.id, session)

    assert brief.candidates == ()
    assert session.scalars(select(Hypothesis)).all() == []
    assert session.scalars(select(HypothesisSupportingObservation)).all() == []


@pytest.mark.parametrize(
    "asset_hostname,authorized_scope,excluded_scope,url",
    [
        (
            "api.example.test",
            ["*.example.test"],
            [],
            "https://outside.test/account",
        ),
        (
            "api.example.test",
            ["*.example.test"],
            ["api.example.test"],
            "https://api.example.test/account",
        ),
        (
            "api.outside.test",
            ["*.example.test"],
            [],
            "https://api.outside.test/account",
        ),
    ],
)
def test_out_of_scope_inventory_does_not_create_candidates(
    session: Session,
    asset_hostname: str,
    authorized_scope: list[str],
    excluded_scope: list[str],
    url: str,
) -> None:
    asset = _seed_asset(session)
    asset.hostname = asset_hostname
    asset.investigation.program.authorized_scope = authorized_scope
    asset.investigation.program.excluded_scope = excluded_scope
    session.add(_inventory_observation(asset, url=url))
    session.flush()

    brief = build_researcher_brief(asset.id, session)

    assert brief.candidates == ()
    assert session.scalars(select(Hypothesis)).all() == []
    assert session.scalars(select(HypothesisSupportingObservation)).all() == []


def test_unknown_observation_type_is_safely_labeled_and_raw_data_is_not_exposed(
    session: Session,
) -> None:
    asset = _seed_asset(session)
    session.add(
        Observation(
            asset=asset,
            observation_type="target-controlled-type",
            data={"secret": "target-controlled-value"},
        )
    )
    session.flush()

    brief = build_researcher_brief(asset.id, session)

    assert brief.observations[0].observation_type == "unrecognized"
    assert brief.candidates == ()
    assert "target-controlled-value" not in repr(brief)


def test_workflow_has_no_network_or_llm_dependency() -> None:
    syntax_tree = ast.parse(
        Path(research_workflow.__file__).read_text(encoding="utf-8")
    )
    imported_modules = {
        alias.name
        for node in ast.walk(syntax_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module
        for node in ast.walk(syntax_tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )

    assert not any(
        module == blocked or module.startswith(f"{blocked}.")
        for module in imported_modules
        for blocked in (
            "requests",
            "httpx",
            "socket",
            "verification.http_probe",
            "intelligence.llm_client",
        )
    )


def test_missing_asset_is_a_lookup_error(session: Session) -> None:
    with pytest.raises(LookupError, match="Asset 999 does not exist"):
        build_researcher_brief(999, session)
