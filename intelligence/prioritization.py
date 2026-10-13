"""Deterministic, explainable ordering of unverified hypotheses for human review.

There is no model call, no confidence weighting, and no hidden score. The whole
rule fits in one sentence: **unverified hypotheses are ordered by category weight
(access-control and IDOR first, then everything else), then newest first, then by
row id, category, and description so the result never depends on input order.**
Category matching goes through :mod:`intelligence.categories`, so ``access-control``
and ``Access Control`` in a stored row are ranked exactly like ``access_control``.

Deliberately simpler than the design document's confidence-weighted "Task
Priority" formula: that formula has no validation behind it, and a ranking a human
cannot audit in one sentence is worse than no ranking at all.

Confirmed or rejected hypotheses are not returned. They are no longer candidates
for investigation, so this function only ranks work that still needs a human. Only
a status of exactly ``"unverified"`` counts as a candidate: any other value - or
none at all - is excluded, which is deliberately fail-closed.
"""

from __future__ import annotations

from datetime import UTC

from data.models import Hypothesis
from intelligence.categories import PRIORITIZED_CATEGORIES, is_prioritized

UNVERIFIED = "unverified"

_PRIORITIZED_WEIGHT = 0
_GENERIC_WEIGHT = 1


def _category_weight(category: str | None) -> int:
    """Weight by category using the shared normalization, never a local copy.

    The weight lookup deliberately shares
    :func:`intelligence.categories.normalize_category` with the parser instead of
    re-deriving a canonical form here: a row written by any path other than the
    parser (a fixture, an operator, a future importer) must still be ranked by
    the same rule, or it would silently miss the tier below.
    """
    if is_prioritized(category):
        return _PRIORITIZED_WEIGHT
    return _GENERIC_WEIGHT


def _recency_key(hypothesis: Hypothesis) -> float:
    """Return an orderable timestamp, treating a missing value as oldest."""
    created_at = hypothesis.created_at
    if created_at is None:
        return float("-inf")
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return created_at.timestamp()


def _sort_key(hypothesis: Hypothesis) -> tuple[int, float, int, str, str]:
    return (
        _category_weight(hypothesis.category),
        -_recency_key(hypothesis),
        -(hypothesis.id or 0),
        hypothesis.category or "",
        hypothesis.description or "",
    )


def prioritize_hypotheses(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    """Return the unverified hypotheses in review order; the input is untouched."""
    return sorted(
        (item for item in hypotheses if item.status == UNVERIFIED),
        key=_sort_key,
    )
