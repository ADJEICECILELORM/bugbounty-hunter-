"""Tests for hypothesis generation: the first live llm_client caller."""

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Hypothesis, Investigation, Observation, Program
from intelligence import hypothesis_generation
from intelligence.hypothesis_generation import (
    MAX_HYPOTHESES,
    UNVERIFIED,
    generate_hypotheses,
    parse_hypothesis_lines,
)
from intelligence.llm_client import LLMClientError, UntrustedText

HEADER_VALUE = 'W/"2eb-9kubiLGtNeEFmO88UVMd/XM30hU"'
GOOD_RESPONSE = (
    "access_control: Compare GET /rest/basket/6 as account A and account B; the "
    "response bytes match, so confirm whether ownership is enforced server-side.\n"
    "information_disclosure: The 747-byte basket response exposes product data; "
    "check whether basket ids are enumerable without an owner check.\n"
)


def _seed_asset(session: Session, *, with_observation: bool = True) -> Asset:
    program = Program(
        name="Example Program",
        authorized_scope=["api.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="api.example.test")
    if with_observation:
        asset.observations.append(
            Observation(
                observation_type="diff_check",
                data={
                    "status_match": True,
                    "body_match": True,
                    "header_differences": {"etag": [HEADER_VALUE, 'W/"9a-other"']},
                    "probe_a": {
                        "url": "https://api.example.test/rest/basket/6",
                        "status_code": 200,
                        "headers": {"etag": HEADER_VALUE},
                        "response_time_ms": 4.5,
                        "content_length": 747,
                        "body_sha256": "a" * 64,
                    },
                },
            )
        )
    session.add(asset)
    session.flush()
    return asset


def _patch_completion(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: str = GOOD_RESPONSE,
    error: Exception | None = None,
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_generate(
        system_prompt: str,
        user_prompt: str,
        *,
        untrusted_context: list[UntrustedText] | None = None,
        **_kwargs: Any,
    ) -> str:
        calls.append(
            {
                "system": system_prompt,
                "user": user_prompt,
                "untrusted": untrusted_context,
            }
        )
        if error is not None:
            raise error
        return response

    monkeypatch.setattr(hypothesis_generation, "generate_completion", fake_generate)
    return calls


def test_generated_rows_are_unverified_and_tied_to_the_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    calls = _patch_completion(monkeypatch)

    with Session(engine) as session:
        asset = _seed_asset(session)
        hypotheses = generate_hypotheses(asset.id, session)

        assert [item.category for item in hypotheses] == [
            "access_control",
            "information_disclosure",
        ]
        assert {item.status for item in hypotheses} == {UNVERIFIED}
        assert all(item.asset_id == asset.id for item in hypotheses)
        assert all(item.id is not None for item in hypotheses)

        stored = session.scalars(select(Hypothesis).order_by(Hypothesis.id)).all()
        assert len(stored) == 2
        assert {item.status for item in stored} == {UNVERIFIED}
        assert stored[0].asset_id == asset.id
        assert "ownership is enforced server-side" in stored[0].description

        assert "suggestions for human review" in calls[0]["system"]
        assert "never state that a vulnerability is confirmed" in calls[0]["system"]
        assert "observation_count=1" in calls[0]["user"]

    engine.dispose()


def test_target_text_reaches_the_model_only_through_untrusted_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    calls = _patch_completion(monkeypatch)

    with Session(engine) as session:
        asset = _seed_asset(session)
        generate_hypotheses(asset.id, session)

        call = calls[0]
        assert HEADER_VALUE not in call["user"]
        assert "etag" not in call["user"]
        assert isinstance(call["untrusted"], list)
        assert call["untrusted"]
        assert all(isinstance(item, UntrustedText) for item in call["untrusted"])
        assert any(HEADER_VALUE in item.content for item in call["untrusted"])
        assert all(item.source.startswith("observation_") for item in call["untrusted"])

    engine.dispose()


def test_llm_client_error_propagates_and_adds_no_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    original_error = LLMClientError("DeepSeek API request failed")
    _patch_completion(monkeypatch, error=original_error)

    with Session(engine) as session:
        asset = _seed_asset(session)

        with pytest.raises(LLMClientError) as error:
            generate_hypotheses(asset.id, session)

        assert error.value is original_error
        assert session.scalars(select(Hypothesis)).all() == []

    engine.dispose()


def test_generation_never_commits_the_callers_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    _patch_completion(monkeypatch)
    commits: list[str] = []

    with Session(engine) as session:
        asset = _seed_asset(session)
        monkeypatch.setattr(session, "commit", lambda *args, **kwargs: commits.append("commit"))

        generate_hypotheses(asset.id, session)

        assert commits == []
        assert session.in_transaction()
        assert len(session.scalars(select(Hypothesis)).all()) == 2

        session.rollback()
        assert session.scalars(select(Hypothesis)).all() == []

    engine.dispose()


def test_hallucinated_status_severity_and_confidence_lines_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = (
        "- access_control: Verify GET /rest/basket/6 rejects a different owner.\n"
        "status: confirmed\n"
        "severity: critical\n"
        "confidence: 0.99\n"
        "**access_control: Verify GET /rest/basket/6 rejects a different owner.**\n"
    )
    engine = init_db("sqlite+pysqlite:///:memory:")
    _patch_completion(monkeypatch, response=response)

    with Session(engine) as session:
        asset = _seed_asset(session)
        hypotheses = generate_hypotheses(asset.id, session)

        assert len(hypotheses) == 1
        assert hypotheses[0].category == "access_control"
        assert hypotheses[0].status == UNVERIFIED
        assert hypotheses[0].description == (
            "Verify GET /rest/basket/6 rejects a different owner."
        )
        assert {item.status for item in session.scalars(select(Hypothesis)).all()} == {
            UNVERIFIED
        }

    engine.dispose()


def test_list_markers_and_emphasis_are_cleaned_and_output_is_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = "\n".join(
        [
            "1. access_control: check the basket endpoint",
            "- **idor: enumerate /rest/basket/{id}**",
            "* injection: probe the search query parameter",
            "misconfiguration: review CORS headers",
        ]
    )
    engine = init_db("sqlite+pysqlite:///:memory:")
    _patch_completion(monkeypatch, response=response)

    with Session(engine) as session:
        asset = _seed_asset(session)
        hypotheses = generate_hypotheses(asset.id, session)

        assert len(hypotheses) == MAX_HYPOTHESES
        assert [(item.category, item.description) for item in hypotheses] == [
            ("access_control", "check the basket endpoint"),
            ("idor", "enumerate /rest/basket/{id}"),
            ("injection", "probe the search query parameter"),
        ]

    engine.dispose()


def test_response_without_usable_lines_adds_no_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    _patch_completion(monkeypatch, response="I cannot help with that.\n\n")

    with Session(engine) as session:
        asset = _seed_asset(session)

        assert generate_hypotheses(asset.id, session) == []
        assert session.scalars(select(Hypothesis)).all() == []

    engine.dispose()


def test_missing_asset_raises_lookup_error_before_any_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    calls = _patch_completion(monkeypatch)

    with Session(engine) as session:
        with pytest.raises(LookupError, match="does not exist"):
            generate_hypotheses(4242, session)

    assert calls == []
    engine.dispose()


def test_asset_without_observations_makes_no_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    calls = _patch_completion(monkeypatch)

    with Session(engine) as session:
        asset = _seed_asset(session, with_observation=False)

        assert generate_hypotheses(asset.id, session) == []
        assert session.scalars(select(Hypothesis)).all() == []

    assert calls == []
    engine.dispose()


def test_parser_ignores_reserved_metadata_and_lines_without_a_colon() -> None:
    assert parse_hypothesis_lines("") == []
    assert parse_hypothesis_lines("status: confirmed\ngarbage\n\n") == []
    assert parse_hypothesis_lines(" access : \n") == []
    assert parse_hypothesis_lines("ACCESS CONTROL: check the basket") == [
        ("access_control", "check the basket")
    ]


def test_parser_canonicalizes_punctuation_so_categories_cannot_drift() -> None:
    """Whatever the model's spelling, the stored category is canonical.

    The ranker weights a stored category by name, so a parser that passed
    ``Information Disclosure`` or ``access-control`` through unchanged would
    produce a row that silently misses the access-control tier.
    """
    assert parse_hypothesis_lines("Information Disclosure: check the basket id\n") == [
        ("information_disclosure", "check the basket id")
    ]
    assert parse_hypothesis_lines("access-control: compare two accounts\n") == [
        ("access_control", "compare two accounts")
    ]
    assert parse_hypothesis_lines("  IDOR / basket: enumerate ids\n") == [
        ("idor_basket", "enumerate ids")
    ]
