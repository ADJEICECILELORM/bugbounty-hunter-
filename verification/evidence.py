"""Persist sanitized verification results as hypothesis-linked observations."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from data.models import Asset, Hypothesis, Observation, Verdict
from verification.diff_check import DiffResult
from verification.http_probe import ProbeResult
from verification.verdict_checker import VerdictResult
from verification.verdict_integrity import digest_for, verify_verdict

# Asset-level observation context, never a judgement input: no verdict rule reads
# these rows, and ``verify_verdict()`` accepts ``diff_check`` evidence only, so a
# row stored with this type cannot be cited as a verdict's evidence.
INVENTORY_OBSERVATION_TYPE = "endpoint_inventory"


def _probe_evidence(probe: ProbeResult) -> dict[str, object]:
    return {
        "url": probe.url,
        "status_code": probe.status_code,
        "headers": probe.headers,
        "response_time_ms": probe.response_time_ms,
        "content_length": probe.content_length,
        "body_sha256": probe.body_sha256,
    }


def diff_data(diff_result: DiffResult) -> dict[str, Any]:
    """The allowlisted evidence mapping, exactly as it is stored.

    The verdict checker reads this same mapping, so a verdict is always derived
    from the bytes that were actually persisted rather than from a parallel
    interpretation of the probe objects.
    """
    return {
        "status_match": diff_result.status_match,
        "status_a": diff_result.status_a,
        "status_b": diff_result.status_b,
        "body_match": diff_result.body_match,
        "content_length_delta": diff_result.content_length_delta,
        "header_differences": {
            name: [value_a, value_b]
            for name, (value_a, value_b) in diff_result.header_differences.items()
        },
        "probe_a": _probe_evidence(diff_result.probe_a),
        "probe_b": _probe_evidence(diff_result.probe_b),
    }


def store_diff_evidence(
    hypothesis_id: int,
    diff_result: DiffResult,
    session: Session,
) -> Observation:
    """Store an allowlisted diff result linked to its hypothesis and asset."""
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise LookupError(f"Hypothesis {hypothesis_id} does not exist")

    observation = Observation(
        asset_id=hypothesis.asset_id,
        hypothesis_id=hypothesis.id,
        observation_type="diff_check",
        data=diff_data(diff_result),
    )
    session.add(observation)
    session.flush()
    return observation


def inventory_data(probe: ProbeResult) -> dict[str, object]:
    """The allowlisted evidence mapping for one inventory probe.

    Deliberately the same mapping a comparison records for one probe: an
    integrity digest binds whatever is stored here for as long as the row exists,
    so this reuses the audited allowlist instead of inventing a second field set
    that older readers would not know, and no collector can add a field to it.
    """
    return _probe_evidence(probe)


def store_inventory_evidence(
    asset_id: int,
    probe: ProbeResult,
    session: Session,
) -> Observation:
    """Store one authorized inventory probe as asset-level context.

    The row carries no ``hypothesis_id``: an inventory is not evidence for any
    claim, so nothing here judges it, promotes it, or binds it to a hypothesis.
    ``verification.verdict_integrity.verify_verdict()`` accepts ``diff_check``
    evidence only, which is what keeps that true even if a caller later tries to
    cite the row. Flush only, never commit - the caller owns the transaction.
    """
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"Asset {asset_id} does not exist")

    observation = Observation(
        asset_id=asset.id,
        hypothesis_id=None,
        observation_type=INVENTORY_OBSERVATION_TYPE,
        data=inventory_data(probe),
    )
    session.add(observation)
    session.flush()
    return observation


def store_verdict(
    hypothesis_id: int,
    observation: Observation,
    result: VerdictResult,
    session: Session,
) -> Verdict:
    """Store one deterministic verdict for one stored observation.

    A verdict is derived data - it can be recomputed from the observation at any
    time - so it is never allowed to float free of the evidence it judges: the
    observation must already belong to the same hypothesis, and the row carries
    an integrity digest binding the judgement to that observation, this
    hypothesis, and the recorded target URLs. Nothing is written unless the row
    passes the same check its consumers will later apply, so the writer and the
    verifier cannot drift apart.

    Nothing here writes a hypothesis status; only ``promote_to_finding`` may do
    that.
    """
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise LookupError(f"Hypothesis {hypothesis_id} does not exist")
    if observation.hypothesis_id != hypothesis.id:
        raise ValueError(
            f"Observation {observation.id} belongs to hypothesis "
            f"{observation.hypothesis_id}, not {hypothesis.id}"
        )

    verdict = Verdict(
        hypothesis_id=hypothesis.id,
        observation_id=observation.id,
        claim_type=result.claim_type,
        is_control=result.is_control,
        verdict=result.verdict,
        rationale=result.rationale,
        integrity_digest="",
    )
    digest = digest_for(verdict, observation)
    if digest is None:
        raise ValueError(
            f"Observation {observation.id} cannot be bound to a verdict: its "
            "evidence is not a recordable mapping"
        )
    verdict.integrity_digest = digest

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    if not check.ok:
        raise RuntimeError(
            "Refusing to store a verdict that fails its own integrity check "
            f"({check.reason}): {check.detail}"
        )

    session.add(verdict)
    session.flush()
    return verdict