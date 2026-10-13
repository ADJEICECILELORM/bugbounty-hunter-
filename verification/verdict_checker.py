"""Deterministic, offline verdicts for stored ``diff_check`` evidence.

This module is the closest thing the project has to a judge, so it is built to
hold no judgement of its own beyond arithmetic:

* it is a pure function - no session, no model, no network, no clock;
* it reads only fields already present in a stored observation and never
  invents a value, so every rationale traces back to evidence a human can open;
* it fails closed: anything missing, malformed, thin, or internally
  contradictory is ``inconclusive``, never ``supported``;
* it never trusts the stored summary flags - they are recomputed from the two
  probe records, and a disagreement invalidates the comparison;
* a **control pair can never yield ``supported``**, so control evidence can
  never be mistaken for proof of the claim under test. A control that differs
  as expected is reported ``inconclusive`` with the reason
  :data:`CONTROL_DISCRIMINATED`: it shows the setup works, not the finding.

A verdict is not a finding. Nothing here writes a status or promotes anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SUPPORTED = "supported"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"

CROSS_ACCOUNT_SAME_BYTES = "cross_account_same_bytes"

# Reason codes. They are stable, greppable, and asserted by tests; the
# human-readable rationale is derived from these plus values actually present.
OBSERVATION_NOT_A_MAPPING = "observation_not_a_mapping"
CLAIM_TYPE_MISSING = "claim_type_missing"
UNKNOWN_CLAIM_TYPE = "unknown_claim_type"
PROBE_MISSING = "probe_missing"
PROBE_FIELD_INVALID = "probe_field_invalid"
HASH_ALGORITHM_MISMATCH = "hash_algorithm_mismatch"
BOTH_BODIES_EMPTY = "both_bodies_empty"
URLS_DIFFER = "urls_differ"
STORED_FLAGS_DISAGREE = "stored_flags_disagree"
LENGTH_HASH_INCONSISTENT = "length_hash_inconsistent"
STATUS_AND_BYTES_MATCH = "status_and_bytes_match"
STATUS_OR_BYTES_DIFFER = "status_or_bytes_differ"
CONTROL_MATCHED = "control_matched"
CONTROL_DISCRIMINATED = "control_discriminated"

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_DIGEST_PREFIX_LENGTH = 12


@dataclass(frozen=True)
class VerdictClaim:
    """What the evidence is being asked to support.

    ``control_expected_match=False`` marks a control pair: a comparison that is
    *supposed* to differ, used to show the two identities or URLs really are
    distinguishable. A control pair never supports a claim.
    """

    type: str
    control_expected_match: bool = True

    @property
    def is_control(self) -> bool:
        return not self.control_expected_match


@dataclass(frozen=True)
class VerdictResult:
    verdict: str
    rationale: str
    claim_type: str
    is_control: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class _Probe:
    url: str
    status_code: int
    content_length: int
    body_sha256: str


def _read_probe(raw: Any, label: str, reasons: list[str]) -> _Probe | None:
    """Read one probe record, recording a reason for every unusable field."""
    if not isinstance(raw, Mapping):
        reasons.append(f"{PROBE_MISSING}:{label}")
        return None

    url = raw.get("url")
    status_code = raw.get("status_code")
    content_length = raw.get("content_length")
    body_sha256 = raw.get("body_sha256")

    usable = True
    if not isinstance(url, str) or not url.strip():
        reasons.append(f"{PROBE_FIELD_INVALID}:{label}.url")
        usable = False
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        reasons.append(f"{PROBE_FIELD_INVALID}:{label}.status_code")
        usable = False
    if (
        isinstance(content_length, bool)
        or not isinstance(content_length, int)
        or content_length < 0
    ):
        reasons.append(f"{PROBE_FIELD_INVALID}:{label}.content_length")
        usable = False
    if not isinstance(body_sha256, str) or not _SHA256.match(
        body_sha256.strip().lower()
    ):
        # Absent covers a missing field and a digest that is not sha256: two
        # digests from different algorithms are both "non-empty strings", so
        # comparing them would be meaningless rather than merely imprecise.
        reasons.append(f"{HASH_ALGORITHM_MISMATCH}:{label}.body_sha256")
        usable = False
    if not usable:
        return None
    return _Probe(url.strip(), status_code, content_length, body_sha256.strip().lower())


def _stored_flags_agree(
    data: Mapping[str, Any],
    *,
    status_match: bool,
    body_match: bool,
) -> bool:
    """Recompute the stored summary flags instead of believing them."""
    for key, recomputed in (("status_match", status_match), ("body_match", body_match)):
        if key not in data:
            continue
        stored = data[key]
        if not isinstance(stored, bool) or stored != recomputed:
            return False
    return True


def _inconclusive(
    claim_type: str,
    is_control: bool,
    reasons: tuple[str, ...],
    rationale: str,
) -> VerdictResult:
    return VerdictResult(
        verdict=INCONCLUSIVE,
        rationale=rationale,
        claim_type=claim_type,
        is_control=is_control,
        reasons=reasons,
    )


def _resolve_claim(claim: VerdictClaim | Mapping[str, Any]) -> VerdictClaim | None:
    if isinstance(claim, VerdictClaim):
        return claim
    if isinstance(claim, Mapping):
        claim_type = claim.get("type")
        expected = claim.get("control_expected_match", True)
        if not isinstance(claim_type, str) or not claim_type.strip():
            return None
        if not isinstance(expected, bool):
            return None
        return VerdictClaim(claim_type.strip(), expected)
    return None


def check_verdict(
    observation_data: Mapping[str, Any] | Any,
    claim: VerdictClaim | Mapping[str, Any],
) -> VerdictResult:
    """Judge one stored ``diff_check`` observation against one claim.

    Returns :data:`SUPPORTED`, :data:`REFUTED`, or :data:`INCONCLUSIVE`. Thin,
    malformed, or self-contradictory data can only ever produce
    :data:`INCONCLUSIVE`.
    """
    resolved = _resolve_claim(claim)
    if resolved is None:
        return _inconclusive(
            "",
            False,
            (CLAIM_TYPE_MISSING,),
            "No usable claim was supplied, so there is nothing to judge.",
        )
    if resolved.type != CROSS_ACCOUNT_SAME_BYTES:
        return _inconclusive(
            resolved.type,
            resolved.is_control,
            (f"{UNKNOWN_CLAIM_TYPE}:{resolved.type}",),
            f"The claim type {resolved.type!r} has no deterministic rule, so the "
            "evidence cannot be judged.",
        )
    if not isinstance(observation_data, Mapping):
        return _inconclusive(
            resolved.type,
            resolved.is_control,
            (OBSERVATION_NOT_A_MAPPING,),
            "The observation carries no readable data mapping, so the evidence "
            "cannot be judged.",
        )

    reasons: list[str] = []
    probe_a = _read_probe(observation_data.get("probe_a"), "probe_a", reasons)
    probe_b = _read_probe(observation_data.get("probe_b"), "probe_b", reasons)
    if probe_a is None or probe_b is None:
        return _inconclusive(
            resolved.type,
            resolved.is_control,
            tuple(reasons),
            "The observation is missing usable probe fields "
            f"({', '.join(reasons)}), so no comparison is possible.",
        )

    status_match = probe_a.status_code == probe_b.status_code
    body_match = probe_a.body_sha256 == probe_b.body_sha256

    if not _stored_flags_agree(
        observation_data, status_match=status_match, body_match=body_match
    ):
        return _inconclusive(
            resolved.type,
            resolved.is_control,
            (STORED_FLAGS_DISAGREE,),
            "The stored comparison flags disagree with the stored probes, so the "
            "evidence is internally inconsistent.",
        )
    if probe_a.content_length == 0 and probe_b.content_length == 0:
        return _inconclusive(
            resolved.type,
            resolved.is_control,
            (BOTH_BODIES_EMPTY,),
            "Both probes returned zero bytes, so identical bodies are the "
            "absence of data rather than a match.",
        )
    if body_match and probe_a.content_length != probe_b.content_length:
        return _inconclusive(
            resolved.type,
            resolved.is_control,
            (LENGTH_HASH_INCONSISTENT,),
            "The recorded bodies hash identically but their recorded lengths "
            f"differ ({probe_a.content_length} vs {probe_b.content_length} bytes), "
            "so the evidence is internally inconsistent.",
        )

    description_a = (
        f"HTTP {probe_a.status_code}, {probe_a.content_length} bytes, "
        f"sha256 {probe_a.body_sha256[:_DIGEST_PREFIX_LENGTH]}..."
    )
    description_b = (
        f"HTTP {probe_b.status_code}, {probe_b.content_length} bytes, "
        f"sha256 {probe_b.body_sha256[:_DIGEST_PREFIX_LENGTH]}..."
    )

    if resolved.control_expected_match:
        if probe_a.url != probe_b.url:
            return _inconclusive(
                resolved.type,
                resolved.is_control,
                (URLS_DIFFER,),
                f"The two probes requested different URLs ({probe_a.url} and "
                f"{probe_b.url}), so they do not test the same-bytes claim.",
            )
        if status_match and body_match:
            return VerdictResult(
                verdict=SUPPORTED,
                rationale=(
                    f"Both probes requested {probe_a.url} and returned the same "
                    f"status and byte-identical bodies ({description_a}); that is "
                    "what a cross-account same-bytes claim predicts."
                ),
                claim_type=resolved.type,
                is_control=False,
                reasons=(STATUS_AND_BYTES_MATCH,),
            )
        return VerdictResult(
            verdict=REFUTED,
            rationale=(
                f"The probes for {probe_a.url} differ (probe A: {description_a}; "
                f"probe B: {description_b}; bodies "
                f"{'match' if body_match else 'differ'}), so this pair does not "
                "show identical bytes for the same URL."
            ),
            claim_type=resolved.type,
            is_control=False,
            reasons=(STATUS_OR_BYTES_DIFFER,),
        )

    if status_match and body_match:
        return VerdictResult(
            verdict=REFUTED,
            rationale=(
                "The control probes matched exactly "
                f"(probe A: {description_a}; probe B: {description_b}) although a "
                "control pair is expected to differ, so this pair cannot "
                "discriminate and must not be used as evidence."
            ),
            claim_type=resolved.type,
            is_control=True,
            reasons=(CONTROL_MATCHED,),
        )
    return VerdictResult(
        verdict=INCONCLUSIVE,
        rationale=(
            "The control probes differed as expected (probe A: "
            f"{description_a}; probe B: {description_b}), so the comparison "
            "discriminates; a control pair never supports the claim by itself."
        ),
        claim_type=resolved.type,
        is_control=True,
        reasons=(CONTROL_DISCRIMINATED,),
    )
