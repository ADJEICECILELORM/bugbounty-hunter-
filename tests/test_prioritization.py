"""Tests for the deterministic hypothesis prioritization rule."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from data.models import Hypothesis
from intelligence import prioritization
from intelligence.prioritization import prioritize_hypotheses

_START = datetime(2026, 1, 1, tzinfo=UTC)


def _at(days: int) -> datetime:
    return _START + timedelta(days=days)


def _hypothesis(
    hypothesis_id: int | None,
    category: str,
    *,
    created_at: datetime | None = _START,
    status: str = "unverified",
    description: str = "check the endpoint",
) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        asset_id=1,
        category=category,
        description=description,
        status=status,
        created_at=created_at,
    )


def test_access_control_and_idor_rank_above_generic_categories() -> None:
    """Category weight outranks recency, and recency orders within a tier."""
    hypotheses = [
        _hypothesis(1, "injection", created_at=_at(3)),
        _hypothesis(2, "idor", created_at=_at(0)),
        _hypothesis(3, "access_control", created_at=_at(1)),
        _hypothesis(4, "authentication", created_at=_at(4)),
    ]

    ordered = prioritize_hypotheses(hypotheses)

    assert [item.id for item in ordered] == [3, 2, 4, 1]


def test_recency_orders_hypotheses_within_the_same_category() -> None:
    hypotheses = [
        _hypothesis(1, "access_control", created_at=_at(0)),
        _hypothesis(2, "access_control", created_at=_at(2)),
        _hypothesis(3, "access_control", created_at=_at(1)),
    ]

    ordered = prioritize_hypotheses(hypotheses)

    assert [item.id for item in ordered] == [2, 3, 1]


def test_ties_fall_back_to_row_id_then_category_alphabetically() -> None:
    hypotheses = [
        _hypothesis(1, "injection"),
        _hypothesis(2, "authentication"),
        _hypothesis(3, "misconfiguration"),
    ]

    ordered = prioritize_hypotheses(hypotheses)

    assert [item.id for item in ordered] == [3, 2, 1]

    transient = [
        Hypothesis(category="injection", description="second", status="unverified"),
        Hypothesis(category="authentication", description="first", status="unverified"),
    ]
    assert [item.category for item in prioritize_hypotheses(transient)] == [
        "authentication",
        "injection",
    ]


def test_confirmed_and_rejected_hypotheses_are_not_returned() -> None:
    hypotheses = [
        _hypothesis(1, "access_control", status="confirmed"),
        _hypothesis(2, "idor", status="rejected"),
        _hypothesis(3, "injection", status="unverified"),
    ]

    ordered = prioritize_hypotheses(hypotheses)

    assert [item.id for item in ordered] == [3]


def test_only_the_exact_unverified_status_counts_as_a_candidate() -> None:
    """Anything else - including no status yet - is excluded, fail closed."""
    for status in ("confirmed", "rejected", "unverified ", "UNVERIFIED", "", None):
        candidate = _hypothesis(1, "access_control")
        candidate.status = status
        assert prioritize_hypotheses([candidate]) == []


def test_order_is_deterministic_and_the_input_list_is_not_mutated() -> None:
    hypotheses = [
        _hypothesis(1, "injection", created_at=_at(1)),
        _hypothesis(2, "idor", created_at=_at(2)),
        _hypothesis(3, "access_control", created_at=_at(3)),
        _hypothesis(4, "access_control", created_at=_at(3)),
    ]
    original = list(hypotheses)

    first = prioritize_hypotheses(hypotheses)
    second = prioritize_hypotheses(list(reversed(hypotheses)))

    assert [item.id for item in first] == [4, 3, 2, 1]
    assert [item.id for item in first] == [item.id for item in second]
    assert hypotheses == original
    assert first is not hypotheses


def test_category_matching_ignores_case_and_surrounding_space() -> None:
    hypotheses = [
        _hypothesis(1, "injection"),
        _hypothesis(2, " Access_Control "),
    ]

    assert [item.id for item in prioritize_hypotheses(hypotheses)] == [2, 1]


def test_the_module_stays_deterministic_and_model_free() -> None:
    """The ranker must not gain a model call, network call, or session access."""
    source = Path(prioritization.__file__).read_text(encoding="utf-8")

    assert "generate_completion" not in source
    assert "requests" not in source
    assert "Session" not in source
