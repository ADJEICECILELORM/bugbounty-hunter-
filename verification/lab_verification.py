"""Manually invoked local-lab verification; never used by normal flows."""

from __future__ import annotations

from sqlalchemy.orm import Session

from data.models import Hypothesis
from gateway.dns_pin import Resolver, URLAuthorizer
from gateway.lab_mode import pin_lab_url
from verification.diff_check import DiffResult, build_diff_result
from verification.evidence import store_diff_evidence
from verification.http_probe import ProbeResult, probe_lab_target, validate_timeout
from verification.run_verification import VerificationRunResult


def run_lab_verification(
    hypothesis_id: int,
    url_a: str,
    url_b: str,
    *,
    allow_private_network: bool,
    authorize: URLAuthorizer,
    session: Session,
    extra_headers_a: dict[str, str] | None = None,
    extra_headers_b: dict[str, str] | None = None,
    resolver: Resolver | None = None,
    timeout_seconds: float = 5.0,
) -> VerificationRunResult:
    """Run one explicitly enabled lab comparison and persist its evidence.

    This entry point is intentionally separate from ``run_verification``. It
    requires the lab opt-in, and both targets still pass the supplied authorizer.
    """
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise ValueError(f"Hypothesis with id {hypothesis_id} does not exist")
    validate_timeout(timeout_seconds)

    target_a = pin_lab_url(
        url_a,
        allow_private_network=allow_private_network,
        authorize=authorize,
        resolver=resolver,
    )
    target_b = pin_lab_url(
        url_b,
        allow_private_network=allow_private_network,
        authorize=authorize,
        resolver=resolver,
    )
    probe_a: ProbeResult = probe_lab_target(
        target_a,
        allow_private_network=allow_private_network,
        timeout_seconds=timeout_seconds,
        extra_headers=extra_headers_a,
    )
    probe_b: ProbeResult = probe_lab_target(
        target_b,
        allow_private_network=allow_private_network,
        timeout_seconds=timeout_seconds,
        extra_headers=extra_headers_b,
    )
    diff: DiffResult = build_diff_result(url_a, url_b, probe_a, probe_b)
    observation = store_diff_evidence(hypothesis.id, diff, session)
    return VerificationRunResult(
        hypothesis_id=hypothesis.id,
        observation=observation,
        diff=diff,
    )