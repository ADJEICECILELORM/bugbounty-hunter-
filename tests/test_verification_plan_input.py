"""The CLI verification-plan reader keeps request secrets transient."""

from __future__ import annotations

from io import StringIO
import json

import pytest

from verification.plan_input import (
    VerificationPlanInputError,
    read_verification_plan,
)
from verification.verdict_checker import CROSS_ACCOUNT_SAME_BYTES


def _plan_document() -> dict[str, object]:
    return {
        "hypothesis_id": 42,
        "pairs": [
            {
                "name": "control",
                "url_a": "http://127.0.0.1:3000/a",
                "url_b": "http://127.0.0.1:3000/b",
                "claim_type": CROSS_ACCOUNT_SAME_BYTES,
                "control_expected_match": False,
            },
            {
                "name": "claim",
                "url_a": "http://127.0.0.1:3000/a",
                "url_b": "http://127.0.0.1:3000/a",
                "claim_type": CROSS_ACCOUNT_SAME_BYTES,
                "headers_a": {"Authorization": "Bearer secret-a"},
                "headers_b": {"Authorization": "Bearer secret-b"},
            },
        ]
    }


def test_reader_returns_plan_and_keeps_headers_only_in_memory() -> None:
    plan = read_verification_plan(StringIO(json.dumps(_plan_document())))

    assert plan.pairs[1].extra_headers_a["Authorization"] == "Bearer secret-a"
    assert plan.pairs[1].extra_headers_b["Authorization"] == "Bearer secret-b"
    assert plan.hypothesis_id == 42
    assert "secret-a" not in repr(plan.pairs[0])


@pytest.mark.parametrize(
    "document",
    [
        {"hypothesis_id": 42, "pairs": [], "token": "top-secret"},
        {"pairs": [{"name": "x", "url_a": "https://user:pass@example.test", "url_b": "https://example.test", "claim_type": CROSS_ACCOUNT_SAME_BYTES}]},
        {"pairs": [{"name": "x", "url_a": "https://example.test", "url_b": "https://example.test", "claim_type": CROSS_ACCOUNT_SAME_BYTES, "headers_a": {"Bad\nName": "secret"}}]},
    ],
)
def test_reader_rejects_unsafe_input_without_echoing_values(document) -> None:
    raw = json.dumps(document)

    with pytest.raises(VerificationPlanInputError) as error:
        read_verification_plan(StringIO(raw))

    assert "secret" not in str(error.value)
    assert "top-secret" not in str(error.value)


def test_reader_bounds_input_and_rejects_duplicate_keys() -> None:
    with pytest.raises(VerificationPlanInputError, match="64 KiB"):
        read_verification_plan(StringIO(" " * 65_537))
    with pytest.raises(VerificationPlanInputError, match="duplicate JSON keys"):
        read_verification_plan(StringIO('{"pairs": [], "pairs": []}'))


def test_reader_requires_positive_hypothesis_binding() -> None:
    document = _plan_document()
    document["hypothesis_id"] = 0
    with pytest.raises(VerificationPlanInputError, match="hypothesis_id"):
        read_verification_plan(StringIO(json.dumps(document)))
