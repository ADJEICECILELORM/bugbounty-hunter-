"""Parse operator-supplied verification plans from a transient JSON stream."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import TextIO
from urllib.parse import urlsplit

from verification.run_hypothesis_verification import (
    RequestPair,
    VerificationTestPlan,
    validate_test_plan,
)
from verification.verdict_checker import VerdictClaim

MAX_PLAN_BYTES = 65_536
MAX_HEADER_VALUE_CHARS = 4_096
MAX_HEADER_COUNT = 32
_HEADER_NAME = re.compile(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class VerificationPlanInputError(ValueError):
    """Raised without echoing plan contents that may contain credentials."""


def read_verification_plan(stream: TextIO) -> VerificationTestPlan:
    """Read and validate a bounded JSON plan without persisting or logging it.

    Expected JSON shape::

        {"hypothesis_id": 12, "pairs": [{"name": "...", "url_a": "...", "url_b": "...",
                    "claim_type": "cross_account_same_bytes",
                    "control_expected_match": false,
                    "headers_a": {}, "headers_b": {}}]}

    Header values remain only in the returned in-memory objects. The function
    intentionally uses generic error messages rather than including raw JSON.
    """
    raw = stream.read(MAX_PLAN_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_PLAN_BYTES:
        raise VerificationPlanInputError("verification plan exceeds the 64 KiB limit")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise VerificationPlanInputError("verification plan is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {"hypothesis_id", "pairs"}:
        raise VerificationPlanInputError(
            "verification plan must contain only a hypothesis_id and pairs list"
        )
    hypothesis_id = document["hypothesis_id"]
    if type(hypothesis_id) is not int or hypothesis_id <= 0:
        raise VerificationPlanInputError("verification plan hypothesis_id must be positive")
    pairs_raw = document["pairs"]
    if not isinstance(pairs_raw, list) or len(pairs_raw) > 64:
        raise VerificationPlanInputError("verification plan pairs must be a list of at most 64")

    pairs: list[RequestPair] = []
    required = {"name", "url_a", "url_b", "claim_type"}
    allowed = required | {"control_expected_match", "headers_a", "headers_b"}
    for item in pairs_raw:
        if not isinstance(item, dict) or not required <= set(item) or set(item) - allowed:
            raise VerificationPlanInputError("verification plan pair has an invalid shape")
        if not all(isinstance(item[key], str) for key in ("name", "url_a", "url_b", "claim_type")):
            raise VerificationPlanInputError("verification plan pair fields must be strings")
        if not _safe_url(item["url_a"]) or not _safe_url(item["url_b"]):
            raise VerificationPlanInputError("verification plan contains an unsafe URL")
        control_expected_match = item.get("control_expected_match", True)
        if type(control_expected_match) is not bool:
            raise VerificationPlanInputError("control_expected_match must be boolean")
        headers_a = _headers(item.get("headers_a", {}))
        headers_b = _headers(item.get("headers_b", {}))
        pairs.append(
            RequestPair(
                name=item["name"],
                url_a=item["url_a"],
                url_b=item["url_b"],
                claim=VerdictClaim(
                    type=item["claim_type"],
                    control_expected_match=control_expected_match,
                ),
                extra_headers_a=headers_a,
                extra_headers_b=headers_b,
            )
        )

    plan = VerificationTestPlan(pairs=tuple(pairs), hypothesis_id=hypothesis_id)
    try:
        # Verification is currently a lab-only path. This validates plan shape
        # without pinning or sending requests; the runtime still requires the
        # independent explicit approval flag and scope checks.
        validate_test_plan(plan, allow_private_network=True)
    except Exception as error:
        raise VerificationPlanInputError(
            "verification plan failed structural validation"
        ) from None
    return plan


def _headers(value: object) -> Mapping[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_HEADER_COUNT:
        raise VerificationPlanInputError("request headers must be a bounded object")
    result: dict[str, str] = {}
    canonical_names: set[str] = set()
    for name, header_value in value.items():
        if not isinstance(name, str) or not isinstance(header_value, str):
            raise VerificationPlanInputError("request header names and values must be strings")
        if (
            not _HEADER_NAME.fullmatch(name)
            or len(name) > 256
            or name.lower() in canonical_names
            or len(header_value) > MAX_HEADER_VALUE_CHARS
            or any(ord(character) < 32 and character != "\t" for character in header_value)
            or "\x7f" in header_value
        ):
            raise VerificationPlanInputError("request header is malformed or too large")
        canonical_names.add(name.lower())
        result[name] = header_value
    return result


def _safe_url(value: str) -> bool:
    if not value or len(value) > 4_096 or value != value.strip():
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationPlanInputError("verification plan contains duplicate JSON keys")
        result[key] = value
    return result
