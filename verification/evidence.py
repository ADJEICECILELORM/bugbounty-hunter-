"""Persist sanitized verification results as hypothesis-linked observations."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from data.models import Hypothesis, Observation
from verification.diff_check import DiffResult
from verification.http_probe import ProbeResult


def _probe_evidence(probe: ProbeResult) -> dict[str, object]:
    return {
        "url": probe.url,
        "status_code": probe.status_code,
        "headers": probe.headers,
        "response_time_ms": probe.response_time_ms,
        "content_length": probe.content_length,
        "body_sha256": probe.body_sha256,
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

    data: dict[str, Any] = {
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
    observation = Observation(
        asset_id=hypothesis.asset_id,
        hypothesis_id=hypothesis.id,
        observation_type="diff_check",
        data=data,
    )
    session.add(observation)
    session.flush()
    return observation