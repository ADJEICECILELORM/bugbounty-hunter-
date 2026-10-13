"""Gated, human-invoked verification that stores evidence and verdicts.

This is the only way to run Task 3.1's checker against live targets, and it is
built so that a mistake here cannot manufacture a finding:

* it uses **only** the guarded lab transport (``pin_lab_url`` plus the
  pre-pinned ``probe_lab_target``). There is no public gateway path, no raw HTTP
  client, and no second, weaker pinning code path in this module;
* the plan is validated **before** any request, so a malformed plan costs
  nothing and a missing identity can never silently compare a target against
  itself;
* every target in the plan is authorized and pinned **before** the first
  request, so a plan containing an out-of-scope target is refused before any
  request is sent rather than after the pairs ahead of it were probed;
* the control pairs are probed and judged **before** any claim pair is probed,
  and a control that fails to discriminate aborts the run, so a setup that
  cannot tell the two sides apart can never produce supporting evidence;
* it writes ``Observations`` and ``Verdicts`` and flushes them at the caller's
  request; it never commits and **never writes a ``Hypothesis.status``**;
* it returns verdicts, not conclusions. Promotion is a separate, human-only step
  (``promote_to_finding``).

The caller owns the transaction: nothing here is durable unless the caller
commits, so a refused run leaves no partial evidence behind.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from data.models import Hypothesis, Observation, Verdict
from gateway.dns_pin import Resolver, URLAuthorizer
from gateway.lab_mode import (
    LabModeNotExplicitlyEnabled,
    LabPinnedTarget,
    pin_lab_url,
)
from verification.diff_check import DiffResult, build_diff_result
from verification.evidence import diff_data, store_diff_evidence, store_verdict
from verification.http_probe import ProbeResult, probe_lab_target, validate_timeout
from verification.verdict_checker import (
    CONTROL_DISCRIMINATED,
    CROSS_ACCOUNT_SAME_BYTES,
    VerdictClaim,
    VerdictResult,
    check_verdict,
)


class SetupControlError(Exception):
    """Raised when a control pair fails to show that the setup discriminates."""


class InvalidTestPlan(ValueError):
    """Raised when a test plan cannot be run as written."""


@dataclass(frozen=True)
class RequestPair:
    """One comparison: what is sent to ``url_a`` and ``url_b``, and why.

    Header values are supplied by the operator at call time and are never
    written to evidence, so a token cannot leak into the database or a report.
    """

    name: str
    url_a: str
    url_b: str
    claim: VerdictClaim
    extra_headers_a: Mapping[str, str] = field(default_factory=dict)
    extra_headers_b: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationTestPlan:
    """The pairs to run: at least one control pair and at least one claim pair."""

    pairs: tuple[RequestPair, ...]


@dataclass(frozen=True)
class PairOutcome:
    pair: RequestPair
    observation: Observation
    result: VerdictResult
    verdict: Verdict


@dataclass(frozen=True)
class HypothesisVerificationResult:
    hypothesis_id: int
    control_outcomes: tuple[PairOutcome, ...]
    primary_outcomes: tuple[PairOutcome, ...]

    @property
    def outcomes(self) -> tuple[PairOutcome, ...]:
        return self.control_outcomes + self.primary_outcomes


def _is_control(pair: RequestPair) -> bool:
    return (
        isinstance(pair, RequestPair)
        and isinstance(pair.claim, VerdictClaim)
        and pair.claim.is_control
    )


def _validate_pair(pair: RequestPair) -> None:
    if not isinstance(pair, RequestPair):
        raise InvalidTestPlan(f"plan entries must be RequestPair, got {pair!r}")
    if not pair.name.strip():
        raise InvalidTestPlan("every pair needs a non-empty name")
    if not isinstance(pair.claim, VerdictClaim):
        raise InvalidTestPlan(f"pair {pair.name!r} needs a VerdictClaim")
    if pair.claim.type != CROSS_ACCOUNT_SAME_BYTES:
        raise InvalidTestPlan(
            f"pair {pair.name!r} claims {pair.claim.type!r}, which has no "
            "deterministic rule"
        )
    if not isinstance(pair.url_a, str) or not pair.url_a.strip():
        raise InvalidTestPlan(f"pair {pair.name!r} needs a url_a")
    if not isinstance(pair.url_b, str) or not pair.url_b.strip():
        raise InvalidTestPlan(f"pair {pair.name!r} needs a url_b")

    if _is_control(pair):
        if pair.url_a == pair.url_b:
            raise InvalidTestPlan(
                f"control pair {pair.name!r} compares the same URL twice, so it "
                "cannot show that the setup discriminates"
            )
        return

    if pair.url_a != pair.url_b:
        raise InvalidTestPlan(
            f"claim pair {pair.name!r} must request the same URL on both sides "
            "for a same-bytes claim"
        )
    if not pair.extra_headers_a or not pair.extra_headers_b:
        raise InvalidTestPlan(
            f"claim pair {pair.name!r} needs request headers for both sides; "
            "without them both requests carry the same identity"
        )
    if dict(pair.extra_headers_a) == dict(pair.extra_headers_b):
        raise InvalidTestPlan(
            f"claim pair {pair.name!r} sends identical headers on both sides, so "
            "it cannot show that the response depends on identity"
        )


def validate_test_plan(
    plan: VerificationTestPlan,
    *,
    allow_private_network: bool,
) -> None:
    """Validate the plan and the lab opt-in before a single request is made."""
    if allow_private_network is not True:
        raise LabModeNotExplicitlyEnabled(
            "Pass allow_private_network=True to explicitly enable lab mode"
        )
    if not isinstance(plan, VerificationTestPlan):
        raise InvalidTestPlan("plan must be a VerificationTestPlan")
    if len(plan.pairs) < 2:
        raise InvalidTestPlan(
            "a plan needs at least one control pair and one claim pair"
        )

    names = [pair.name for pair in plan.pairs if isinstance(pair, RequestPair)]
    if len(set(names)) != len(names):
        raise InvalidTestPlan("pair names must be unique")

    pairs = list(plan.pairs)
    if not any(_is_control(pair) for pair in pairs):
        raise InvalidTestPlan(
            "a plan needs at least one control pair that is expected to differ"
        )
    if not any(not _is_control(pair) for pair in pairs):
        raise InvalidTestPlan("a plan needs at least one claim pair")

    for pair in pairs:
        _validate_pair(pair)


def _pin_targets(
    pairs: list[RequestPair],
    *,
    allow_private_network: bool,
    authorize: URLAuthorizer,
    resolver: Resolver | None,
) -> dict[str, LabPinnedTarget]:
    """Authorize and pin every URL in the plan before the first request.

    This is where an out-of-scope target stops the run: because every URL is
    pinned up front, a plan containing one is refused before any request is sent,
    not after the pairs ahead of it have already been probed.
    """
    targets: dict[str, LabPinnedTarget] = {}
    for pair in pairs:
        for url in (pair.url_a, pair.url_b):
            if url not in targets:
                targets[url] = pin_lab_url(
                    url,
                    allow_private_network=allow_private_network,
                    authorize=authorize,
                    resolver=resolver,
                )
    return targets


def _probe(
    target: LabPinnedTarget,
    headers: Mapping[str, str],
    *,
    allow_private_network: bool,
    timeout_seconds: float,
) -> ProbeResult:
    """Probe one pre-pinned target through the guarded lab transport only."""
    return probe_lab_target(
        target,
        allow_private_network=allow_private_network,
        timeout_seconds=timeout_seconds,
        extra_headers=dict(headers) or None,
    )


def _measure(
    pair: RequestPair,
    pinned: Mapping[str, LabPinnedTarget],
    *,
    allow_private_network: bool,
    timeout_seconds: float,
) -> tuple[DiffResult, VerdictResult]:
    """Probe both sides of one pair and judge it, without writing anything."""
    probe_a = _probe(
        pinned[pair.url_a],
        pair.extra_headers_a,
        allow_private_network=allow_private_network,
        timeout_seconds=timeout_seconds,
    )
    probe_b = _probe(
        pinned[pair.url_b],
        pair.extra_headers_b,
        allow_private_network=allow_private_network,
        timeout_seconds=timeout_seconds,
    )
    diff = build_diff_result(pair.url_a, pair.url_b, probe_a, probe_b)
    return diff, check_verdict(diff_data(diff), pair.claim)


def run_hypothesis_verification(
    hypothesis_id: int,
    plan: VerificationTestPlan,
    *,
    allow_private_network: bool,
    authorize: URLAuthorizer,
    session: Session,
    resolver: Resolver | None = None,
    timeout_seconds: float = 5.0,
) -> HypothesisVerificationResult:
    """Run a gated test plan and persist its evidence and verdicts.

    Raises :class:`InvalidTestPlan` before any request when the plan is not
    runnable, :class:`~gateway.lab_mode.LabModeNotExplicitlyEnabled` when the lab
    opt-in is absent, and :class:`SetupControlError` when a control pair fails to
    discriminate - in that last case no evidence is written. Every URL in the
    plan is authorized and pinned before the first request, so a target outside
    the authorized scope stops the run with nothing sent and nothing written.
    """
    validate_test_plan(plan, allow_private_network=allow_private_network)
    validate_timeout(timeout_seconds)

    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise LookupError(f"Hypothesis with id {hypothesis_id} does not exist")

    pairs = list(plan.pairs)
    pinned = _pin_targets(
        pairs,
        allow_private_network=allow_private_network,
        authorize=authorize,
        resolver=resolver,
    )
    transport = {
        "allow_private_network": allow_private_network,
        "timeout_seconds": timeout_seconds,
    }
    measured: dict[int, tuple[DiffResult, VerdictResult]] = {}

    # Controls first, and nothing is written until every control has passed: a
    # setup that could not tell the two sides apart cannot support a claim.
    for index, pair in enumerate(pairs):
        if not _is_control(pair):
            continue
        diff, result = _measure(pair, pinned, **transport)
        if result.reasons != (CONTROL_DISCRIMINATED,):
            raise SetupControlError(
                f"Control pair {pair.name!r} did not discriminate, so the run is "
                f"refused before any evidence is written: {result.rationale}"
            )
        measured[index] = (diff, result)

    for index, pair in enumerate(pairs):
        if _is_control(pair):
            continue
        measured[index] = _measure(pair, pinned, **transport)

    outcomes: list[PairOutcome] = []
    for index, pair in enumerate(pairs):
        diff, result = measured[index]
        observation = store_diff_evidence(hypothesis.id, diff, session)
        verdict = store_verdict(hypothesis.id, observation, result, session)
        outcomes.append(PairOutcome(pair, observation, result, verdict))

    return HypothesisVerificationResult(
        hypothesis_id=hypothesis.id,
        control_outcomes=tuple(
            outcome for outcome in outcomes if _is_control(outcome.pair)
        ),
        primary_outcomes=tuple(
            outcome for outcome in outcomes if not _is_control(outcome.pair)
        ),
    )
