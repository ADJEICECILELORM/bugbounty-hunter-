"""Human-initiated, single-shot verification with persisted evidence."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from data.models import Hypothesis, Observation
from gateway.dns_pin import Resolver, URLAuthorizer
from verification.diff_check import DiffResult, compare_requests
from verification.evidence import store_diff_evidence


@dataclass(frozen=True)
class VerificationRunResult:
    hypothesis_id: int
    observation: Observation
    diff: DiffResult


def run_verification(
    hypothesis_id: int,
    url_a: str,
    url_b: str,
    *,
    authorize: URLAuthorizer,
    session: Session,
    extra_headers_a: dict[str, str] | None = None,
    extra_headers_b: dict[str, str] | None = None,
    resolver: Resolver | None = None,
    timeout_seconds: float = 5.0,
) -> VerificationRunResult:
    """Compare two authorized requests and store evidence without judging it."""
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise ValueError(f"Hypothesis with id {hypothesis_id} does not exist")

    diff = compare_requests(
        url_a,
        url_b,
        authorize=authorize,
        extra_headers_a=extra_headers_a,
        extra_headers_b=extra_headers_b,
        resolver=resolver,
        timeout_seconds=timeout_seconds,
    )
    observation = store_diff_evidence(hypothesis.id, diff, session)
    return VerificationRunResult(
        hypothesis_id=hypothesis.id,
        observation=observation,
        diff=diff,
    )