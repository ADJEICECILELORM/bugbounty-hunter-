"""Tests for the deterministic verdict checker.

The fixtures use the shapes and, where recorded, the exact values the local
Juice Shop lab produced, so the rules are exercised against evidence the
project has actually stored rather than invented shapes alone.
"""

from __future__ import annotations

from typing import Any

import pytest

from verification.verdict_checker import (
    BOTH_BODIES_EMPTY,
    CLAIM_TYPE_MISSING,
    CONTROL_DISCRIMINATED,
    CONTROL_MATCHED,
    CROSS_ACCOUNT_SAME_BYTES,
    HASH_ALGORITHM_MISMATCH,
    INCONCLUSIVE,
    LENGTH_HASH_INCONSISTENT,
    OBSERVATION_NOT_A_MAPPING,
    PROBE_FIELD_INVALID,
    PROBE_MISSING,
    REFUTED,
    STATUS_AND_BYTES_MATCH,
    STATUS_OR_BYTES_DIFFER,
    STORED_FLAGS_DISAGREE,
    SUPPORTED,
    UNKNOWN_CLAIM_TYPE,
    URLS_DIFFER,
    VerdictClaim,
    check_verdict,
)

BASKET_A = "http://127.0.0.1:3000/rest/basket/6"
BASKET_B = "http://127.0.0.1:3000/rest/basket/7"
# Recorded by the Part 1 lab run: 747 bytes for the matching pair.
SHA_MATCH_A = "62224ea89597345427001c549b8510aaea3a49d13c98715f67f64710db4738c9"
# Recorded by the Part 1 lab run: the control pair's second, 154-byte body.
SHA_OTHER = "77200416dba5b985bf6a26926536c18681c40d4d7cb02915fa5a288bb5eaea56"
SHA_NEVER_SEEN = "0" * 64

PRIMARY = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES)
CONTROL = VerdictClaim(CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False)


def probe(
    url: str = BASKET_A,
    status_code: int = 200,
    content_length: int = 747,
    body_sha256: str = SHA_MATCH_A,
) -> dict[str, Any]:
    return {
        "url": url,
        "status_code": status_code,
        "content_length": content_length,
        "body_sha256": body_sha256,
    }


def observation(**overrides: Any) -> dict[str, Any]:
    """The matching diff_check shape the runner stores for a primary pair."""
    data: dict[str, Any] = {
        "probe_a": probe(),
        "probe_b": probe(),
        "status_match": True,
        "body_match": True,
    }
    data.update(overrides)
    return data


def has_reason(result: Any, code: str) -> bool:
    """Reason codes may carry a field suffix, e.g. ``probe_missing:probe_a``."""
    return any(reason == code or reason.startswith(f"{code}:") for reason in result.reasons)


# --- the two outcomes that matter most -------------------------------------


def test_matching_same_url_pair_supports_the_claim() -> None:
    result = check_verdict(observation(), PRIMARY)

    assert result.verdict == SUPPORTED
    assert result.is_control is False
    assert result.reasons == (STATUS_AND_BYTES_MATCH,)
    assert BASKET_A in result.rationale
    assert "747 bytes" in result.rationale


def test_control_pair_that_differs_never_supports_the_claim() -> None:
    data = {
        "probe_a": probe(BASKET_A, content_length=747, body_sha256=SHA_MATCH_A),
        "probe_b": probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
        "status_match": True,
        "body_match": False,
    }

    result = check_verdict(data, CONTROL)

    assert result.verdict == INCONCLUSIVE, "a discriminating control is not proof"
    assert result.reasons == (CONTROL_DISCRIMINATED,)
    assert result.is_control is True


def test_control_allows_different_urls_because_that_is_the_point() -> None:
    """A control pair compares two different resources by design."""
    data = {
        "probe_a": probe(BASKET_A),
        "probe_b": probe(BASKET_B, content_length=154, body_sha256=SHA_OTHER),
    }

    assert check_verdict(data, CONTROL).reasons == (CONTROL_DISCRIMINATED,)


def test_primary_claim_refuses_to_compare_two_different_urls() -> None:
    data = {"probe_a": probe(BASKET_A), "probe_b": probe(BASKET_B)}

    result = check_verdict(data, PRIMARY)

    assert result.verdict == INCONCLUSIVE
    assert result.reasons == (URLS_DIFFER,)


def test_control_that_matches_is_refuted() -> None:
    """A control that fails to discriminate invalidates the setup entirely."""
    result = check_verdict(observation(), CONTROL)

    assert result.verdict == REFUTED
    assert result.reasons == (CONTROL_MATCHED,)


# --- refutation beyond the control ----------------------------------------


def test_differing_primaries_refute_the_same_bytes_claim() -> None:
    data = {
        "probe_a": probe(),
        "probe_b": probe(content_length=154, body_sha256=SHA_OTHER),
        "status_match": True,
        "body_match": False,
    }

    result = check_verdict(data, PRIMARY)

    assert result.verdict == REFUTED
    assert result.reasons == (STATUS_OR_BYTES_DIFFER,)
    assert "747 bytes" in result.rationale
    assert "154 bytes" in result.rationale
    assert "bodies differ" in result.rationale


def test_differing_status_codes_refute_even_with_identical_bodies() -> None:
    data = {"probe_a": probe(status_code=200), "probe_b": probe(status_code=403)}

    result = check_verdict(data, PRIMARY)

    assert result.verdict == REFUTED
    assert result.reasons == (STATUS_OR_BYTES_DIFFER,)


# --- fail-closed paths ----------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected_reason"),
    [
        pytest.param({}, PROBE_MISSING, id="no-probes"),
        pytest.param({"probe_a": probe()}, PROBE_MISSING, id="missing-probe-b"),
        pytest.param(
            {"probe_a": "not a mapping", "probe_b": probe()},
            PROBE_MISSING,
            id="probe-is-not-a-mapping",
        ),
        pytest.param(
            {
                "probe_a": {k: v for k, v in probe().items() if k != "url"},
                "probe_b": probe(),
            },
            PROBE_FIELD_INVALID,
            id="missing-url",
        ),
        pytest.param(
            {"probe_a": probe(status_code="200"), "probe_b": probe()},
            PROBE_FIELD_INVALID,
            id="status-is-a-string",
        ),
        pytest.param(
            {"probe_a": probe(content_length=None), "probe_b": probe()},
            PROBE_FIELD_INVALID,
            id="length-is-none",
        ),
        pytest.param(
            {"probe_a": probe(body_sha256=""), "probe_b": probe()},
            HASH_ALGORITHM_MISMATCH,
            id="empty-digest",
        ),
        pytest.param(
            {"probe_a": probe(body_sha256="md5:abc"), "probe_b": probe()},
            HASH_ALGORITHM_MISMATCH,
            id="wrong-algorithm",
        ),
        pytest.param(
            {"probe_a": probe(body_sha256=SHA_MATCH_A[:40]), "probe_b": probe()},
            HASH_ALGORITHM_MISMATCH,
            id="truncated-digest",
        ),
    ],
)
def test_thin_or_malformed_evidence_is_inconclusive(
    data: dict[str, Any], expected_reason: str
) -> None:
    result = check_verdict(data, PRIMARY)

    assert result.verdict == INCONCLUSIVE
    assert has_reason(result, expected_reason)


def test_two_empty_bodies_are_absence_of_data_not_a_match() -> None:
    data = {
        "probe_a": probe(content_length=0, body_sha256=SHA_NEVER_SEEN),
        "probe_b": probe(content_length=0, body_sha256=SHA_NEVER_SEEN),
    }

    result = check_verdict(data, PRIMARY)

    assert result.verdict == INCONCLUSIVE
    assert result.reasons == (BOTH_BODIES_EMPTY,)


def test_stored_flags_are_recomputed_not_trusted() -> None:
    """A row claiming a mismatch while storing identical probes is inconsistent."""
    data = observation(status_match=False, body_match=False)

    result = check_verdict(data, PRIMARY)

    assert result.verdict == INCONCLUSIVE
    assert result.reasons == (STORED_FLAGS_DISAGREE,)


def test_identical_digests_with_different_lengths_are_inconsistent() -> None:
    data = {"probe_a": probe(content_length=747), "probe_b": probe(content_length=154)}

    result = check_verdict(data, PRIMARY)

    assert result.verdict == INCONCLUSIVE
    assert result.reasons == (LENGTH_HASH_INCONSISTENT,)


def test_bad_claim_shapes_are_inconclusive() -> None:
    assert check_verdict(observation(), {"type": ""}).reasons == (CLAIM_TYPE_MISSING,)
    assert check_verdict(observation(), "same-bytes").reasons == (CLAIM_TYPE_MISSING,)
    assert check_verdict(observation(), None).reasons == (CLAIM_TYPE_MISSING,)
    assert check_verdict(
        observation(), {"type": CROSS_ACCOUNT_SAME_BYTES, "control_expected_match": "no"}
    ).reasons == (CLAIM_TYPE_MISSING,)


def test_unknown_claim_type_is_inconclusive_not_support() -> None:
    result = check_verdict(observation(), VerdictClaim("sql_injection_bypass"))

    assert result.verdict == INCONCLUSIVE
    assert has_reason(result, UNKNOWN_CLAIM_TYPE)


def test_observation_without_a_mapping_is_inconclusive() -> None:
    result = check_verdict("747 bytes", PRIMARY)

    assert result.verdict == INCONCLUSIVE
    assert result.reasons == (OBSERVATION_NOT_A_MAPPING,)


def test_mapping_claim_descriptors_are_accepted() -> None:
    """Callers may pass a claim as stored JSON rather than as a dataclass."""
    supporting = check_verdict(
        observation(), {"type": CROSS_ACCOUNT_SAME_BYTES, "control_expected_match": True}
    )
    control = check_verdict(
        observation(), {"type": CROSS_ACCOUNT_SAME_BYTES, "control_expected_match": False}
    )

    assert supporting.verdict == SUPPORTED
    assert control.verdict == REFUTED


def test_uppercase_digests_compare_as_lowercase() -> None:
    data = {
        "probe_a": probe(body_sha256=SHA_MATCH_A.upper()),
        "probe_b": probe(body_sha256=SHA_MATCH_A),
    }

    assert check_verdict(data, PRIMARY).verdict == SUPPORTED


def test_no_path_ever_reports_supported_for_a_control() -> None:
    """Exhaustive guard: no control input combination may yield supported."""
    candidates = [
        probe(),
        probe(BASKET_B),
        probe(content_length=154, body_sha256=SHA_OTHER),
        probe(status_code=403),
        probe(content_length=0, body_sha256=SHA_NEVER_SEEN),
    ]
    for first in candidates:
        for second in candidates:
            data = {"probe_a": first, "probe_b": second}
            result = check_verdict(data, CONTROL)
            assert result.verdict != SUPPORTED, (first, second)
