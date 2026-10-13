"""Bind every stored verdict to the evidence, hypothesis and target it judged.

A verdict row is derived data: :mod:`verification.verdict_checker` can recompute
it from the stored observation at any time. That is exactly why a row is never
trusted merely because it exists. :func:`verify_verdict` re-derives the judgement
from the stored bytes and re-computes an integrity digest that binds four things
together::

    verdict semantic content -> evidence row -> hypothesis -> target URLs

plus the canonical digest of the stored evidence body, so editing the evidence
invalidates the verdict that judged it. Two things must therefore agree before a
verdict may be used: the digest must match the stored fields *and* the stored
judgement must be what the checker derives today. A hand-written row, a row
rebound to another observation, another hypothesis or another target, and a row
whose evidence or wording was edited all fail.

This module is pure: no session, no network, no model, no clock. Every consumer
of a verdict - the promotion gate and the report loader - calls
:func:`verify_verdict`, so the binding is checked where verdicts are consumed,
not only where they are written. :data:`DIGEST_SCHEMA` versions the digest:
changing the checker's own wording changes every digest, which is a deliberate
schema bump rather than a silent one.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from data.models import Observation, Verdict
from verification.verdict_checker import (
    CROSS_ACCOUNT_SAME_BYTES,
    VerdictClaim,
    check_verdict,
)

DIGEST_SCHEMA = "verdict-integrity-v1"
EVIDENCE_SCHEMA = "verdict-evidence-v1"
OBSERVATION_TYPE = "diff_check"
DIGEST_PREFIX_LENGTH = 12

# Reason codes: stable, greppable, and asserted by tests.
VERDICT_HYPOTHESIS_MISMATCH = "verdict_hypothesis_mismatch"
EVIDENCE_MISSING = "evidence_missing"
EVIDENCE_INVALID = "evidence_invalid"
EVIDENCE_SUBSTITUTED = "evidence_substituted"
EVIDENCE_HYPOTHESIS_MISMATCH = "evidence_hypothesis_mismatch"
EVIDENCE_TYPE_MISMATCH = "evidence_type_mismatch"
EVIDENCE_NOT_A_MAPPING = "evidence_not_a_mapping"
VERDICT_SHAPE_INVALID = "verdict_shape_invalid"
DIGEST_MISSING = "integrity_digest_missing"
DIGEST_MALFORMED = "integrity_digest_malformed"
DIGEST_MISMATCH = "integrity_digest_mismatch"
RE_DERIVED_DISAGREES = "rederived_verdict_disagrees"

# Claim types whose judgement this verifier can re-derive. A verdict for any
# other claim type is bound by its digest only, so a future rule cannot be
# invalidated by an older verifier that does not know how to check it.
_RE_DERIVABLE_CLAIM_TYPES = frozenset({CROSS_ACCOUNT_SAME_BYTES})
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class IntegrityCheck:
    """One binding check. ``reason`` is empty exactly when ``ok`` is true."""

    ok: bool
    reason: str = ""
    detail: str = ""


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """One payload, one byte string - on every machine and every run."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def evidence_digest(observation: Observation) -> str | None:
    """Digest the stored evidence, or ``None`` when it is not a mapping."""
    data = observation.data if isinstance(observation.data, Mapping) else None
    if data is None:
        return None
    return hashlib.sha256(
        canonical_json(
            {
                "schema": EVIDENCE_SCHEMA,
                "observation_type": observation.observation_type,
                "data": data,
            }
        )
    ).hexdigest()


def target_urls(observation: Observation) -> tuple[str, str]:
    """The two probe URLs actually recorded: the target binding of a verdict."""
    data = observation.data if isinstance(observation.data, Mapping) else {}
    urls: list[str] = []
    for key in ("probe_a", "probe_b"):
        probe = data.get(key)
        url = probe.get("url") if isinstance(probe, Mapping) else None
        urls.append(url if isinstance(url, str) else "")
    return (urls[0], urls[1])


def verdict_digest(
    *,
    claim_type: str,
    is_control: bool,
    verdict: str,
    rationale: str,
    hypothesis_id: int,
    observation_id: int,
    target: Sequence[str],
    evidence_sha256: str,
) -> str:
    """The digest a verdict must carry: its content bound to what it judged."""
    return hashlib.sha256(
        canonical_json(
            {
                "schema": DIGEST_SCHEMA,
                "claim_type": claim_type,
                "is_control": is_control,
                "verdict": verdict,
                "rationale": rationale,
                "hypothesis_id": hypothesis_id,
                "observation_id": observation_id,
                "target": list(target),
                "evidence_sha256": evidence_sha256,
            }
        )
    ).hexdigest()


def _shape_ok(verdict: Verdict) -> bool:
    if not isinstance(verdict, Verdict):
        return False
    return (
        isinstance(verdict.claim_type, str)
        and bool(verdict.claim_type)
        and isinstance(verdict.verdict, str)
        and bool(verdict.verdict)
        and isinstance(verdict.rationale, str)
        and isinstance(verdict.is_control, bool)
    )


def digest_for(verdict: Verdict, observation: Observation) -> str | None:
    """Recompute the digest the given verdict and evidence require."""
    evidence_sha256 = evidence_digest(observation)
    if evidence_sha256 is None or not _shape_ok(verdict):
        return None
    return verdict_digest(
        claim_type=verdict.claim_type,
        is_control=verdict.is_control,
        verdict=verdict.verdict,
        rationale=verdict.rationale,
        hypothesis_id=verdict.hypothesis_id,
        observation_id=observation.id,
        target=target_urls(observation),
        evidence_sha256=evidence_sha256,
    )


def _rederive(verdict: Verdict, observation: Observation) -> str | None:
    """What the checker says today, or ``None`` for a claim type it cannot judge."""
    if verdict.claim_type not in _RE_DERIVABLE_CLAIM_TYPES:
        return None
    claim = VerdictClaim(
        verdict.claim_type, control_expected_match=not verdict.is_control
    )
    return check_verdict(observation.data, claim).verdict


def verify_verdict(
    verdict: Verdict,
    observation: Observation | None,
    *,
    hypothesis_id: int,
) -> IntegrityCheck:
    """Check that ``verdict`` is bound to ``observation`` under ``hypothesis_id``.

    Returns a failing :class:`IntegrityCheck` - never an exception - so a caller
    can name every failure it found. ``observation`` is the row the caller loaded
    for ``verdict.observation_id``; passing ``None`` means the evidence is gone.
    """
    if not _shape_ok(verdict):
        return IntegrityCheck(False, VERDICT_SHAPE_INVALID)
    if verdict.hypothesis_id != hypothesis_id:
        return IntegrityCheck(
            False,
            VERDICT_HYPOTHESIS_MISMATCH,
            f"the row is bound to hypothesis {verdict.hypothesis_id}",
        )
    if observation is None:
        return IntegrityCheck(
            False, EVIDENCE_MISSING, f"observation {verdict.observation_id} is gone"
        )
    if not isinstance(observation, Observation):
        return IntegrityCheck(
            False,
            EVIDENCE_INVALID,
            f"{type(observation).__name__} is not an evidence row",
        )
    if observation.id != verdict.observation_id:
        return IntegrityCheck(
            False,
            EVIDENCE_SUBSTITUTED,
            f"the row cites observation {verdict.observation_id}, "
            f"but observation {observation.id} was supplied",
        )
    if observation.hypothesis_id != hypothesis_id:
        return IntegrityCheck(
            False,
            EVIDENCE_HYPOTHESIS_MISMATCH,
            f"the evidence belongs to hypothesis {observation.hypothesis_id}",
        )
    if observation.observation_type != OBSERVATION_TYPE:
        return IntegrityCheck(
            False,
            EVIDENCE_TYPE_MISMATCH,
            f"the evidence is {observation.observation_type!r}, not "
            f"{OBSERVATION_TYPE!r}",
        )

    evidence_sha256 = evidence_digest(observation)
    if evidence_sha256 is None:
        return IntegrityCheck(False, EVIDENCE_NOT_A_MAPPING)

    stored = verdict.integrity_digest
    if not isinstance(stored, str) or not stored:
        return IntegrityCheck(False, DIGEST_MISSING)
    if not _SHA256.match(stored):
        return IntegrityCheck(False, DIGEST_MALFORMED, f"{stored!r} is not a sha256")

    expected = verdict_digest(
        claim_type=verdict.claim_type,
        is_control=verdict.is_control,
        verdict=verdict.verdict,
        rationale=verdict.rationale,
        hypothesis_id=hypothesis_id,
        observation_id=observation.id,
        target=target_urls(observation),
        evidence_sha256=evidence_sha256,
    )
    if stored != expected:
        return IntegrityCheck(
            False,
            DIGEST_MISMATCH,
            f"the stored digest {stored[:DIGEST_PREFIX_LENGTH]}... is not the "
            f"digest of these fields, this evidence, hypothesis and target",
        )

    derived = _rederive(verdict, observation)
    if derived is not None and derived != verdict.verdict:
        return IntegrityCheck(
            False,
            RE_DERIVED_DISAGREES,
            f"the bound evidence yields {derived!r}, the row records "
            f"{verdict.verdict!r}",
        )
    return IntegrityCheck(True)
