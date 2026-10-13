"""Single source of truth for hypothesis category matching.

Two modules need the same answer to "which category is this?": the parser in
:mod:`intelligence.hypothesis_generation`, which derives a category from model
output, and the ranker in :mod:`intelligence.prioritization`, which weights a
category that has already been stored. Both import this module so they cannot
drift apart - a ranker that normalized differently from the parser would
silently mis-rank a real row.

Categories are **normalized but not whitelisted**. Anchoring to a fixed
vocabulary would discard a model's novel category (``race_condition``, say)
together with the legitimate hypothesis attached to it, and a category only ever
affects review *order*: it never sets a status, authorizes an action, or writes
a finding. Normalization is therefore lossless, and an unknown category simply
ranks as generic rather than being dropped or promoted.
"""

from __future__ import annotations

import re

MAX_CATEGORY_LENGTH = 64

# Categories whose whole point is an ownership or authorization boundary - the
# class of check this project can currently produce differential evidence for.
PRIORITIZED_CATEGORIES = frozenset({"access_control", "idor"})

_NON_CATEGORY_CHARS = re.compile(r"[^a-z0-9]+")


def normalize_category(raw: str | None) -> str:
    """Return the canonical form: lowercase ``[a-z0-9_]``, bounded length.

    ``"Access-Control"``, ``"access control"`` and ``" ACCESS_CONTROL "`` all
    normalize to ``"access_control"``, so a stored category is matched the same
    way whether it arrived from the model, a fixture, or an operator.
    """
    return _NON_CATEGORY_CHARS.sub("_", (raw or "").strip().lower()).strip("_")[
        :MAX_CATEGORY_LENGTH
    ]


def is_prioritized(category: str | None) -> bool:
    """True when ``category`` is one the ranker puts ahead of everything else."""
    return normalize_category(category) in PRIORITIZED_CATEGORIES
