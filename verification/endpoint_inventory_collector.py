"""Probe the authorized seed inventory once per candidate and store what came back.

:mod:`verification.endpoint_inventory` decides *which* candidates policy would
let us look at, purely and offline. This module is the live half: it takes that
list, sends exactly one guarded request per candidate, and stores each response
as asset-level observation context for a human and for
:mod:`intelligence.observation_summary`. Nothing here judges, scores, ranks, or
promotes anything.

The rules this module does not bend:

* **Every candidate is authorized before the first request.** ``authorize`` is the
  only scope gate, and ``inventory_from_seeds()`` filters the whole list before
  anything is probed, so one out-of-scope URL means no request is sent at all. An
  authorizer that rejects everything yields ``[]`` and zero requests.
* **Nothing is caught, so nothing fails quietly.** There is no ``try``/``except``
  anywhere in this module: a transport failure, a refused target, a malformed base
  or an unknown asset propagates to the caller. ``[]`` therefore always means
  "policy authorized nothing" and never "the run failed" - the two outcomes are
  never confusable, and a caller cannot mistake a broken run for an empty one.
* **One request per candidate, nothing else.** At most ``len(SEED_PATHS)`` GETs,
  no retry, no crawling what a response links to, and no redirect: the transport
  in :mod:`verification.http_probe` already refuses to follow one.
* **No second network path.** The public branch is ``probe_endpoint()``; the lab
  branch is ``pin_lab_url()`` and then ``probe_lab_target()``, which requires both
  the explicit ``allow_private_network=True`` opt-in and a target marked as a lab
  target by the pinning escape hatch. This module builds no HTTP client, no
  socket, and no pinned target of its own, and the lab branch pins the entire
  candidate list before the first probe, so a later candidate that is
  out-of-scope or unresolvable stops the run with nothing sent.
* **Store, never commit.** Every row is flushed only: the caller owns the
  transaction, exactly as everywhere else in this project.
* **No credential can reach evidence.** There is no parameter through which
  request headers could be passed, and only the allowlisted probe mapping is
  stored.

An inventory is context, never a verdict: ``verdict_integrity.verify_verdict()``
accepts ``diff_check`` evidence only, so no verdict can cite a row stored here.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from sqlalchemy.orm import Session

from data.models import Observation
from gateway.dns_pin import Resolver, URLAuthorizer
from gateway.lab_mode import pin_lab_url
from verification.endpoint_inventory import inventory_from_seeds
from verification.evidence import store_inventory_evidence
from verification.http_probe import ProbeResult, probe_endpoint, probe_lab_target

# The one seam a test may replace: given an already-authorized candidate, return
# its probe result. Production never passes one, so the guarded routing below -
# and the guarantees that depend on it - cannot be replaced by a double.
Transport = Callable[[str], ProbeResult]


def _public_transport(
    *,
    authorize: URLAuthorizer,
    resolver: Resolver | None,
    timeout_seconds: float,
) -> Transport:
    """The public-only path: every URL is authorized and pinned again per request."""

    def transport(url: str) -> ProbeResult:
        return probe_endpoint(
            url,
            authorize=authorize,
            resolver=resolver,
            timeout_seconds=timeout_seconds,
        )

    return transport


def _lab_transport(
    candidates: Sequence[str],
    *,
    authorize: URLAuthorizer,
    resolver: Resolver | None,
    timeout_seconds: float,
) -> Transport:
    """The lab path: pin the whole list first, then probe only those targets.

    Pinning up front mirrors the verification runner: every candidate is validated
    while nothing has been sent yet, so an unauthorized or unresolvable one stops
    the run instead of aborting it halfway through.
    """
    targets = {
        url: pin_lab_url(
            url,
            allow_private_network=True,
            authorize=authorize,
            resolver=resolver,
        )
        for url in candidates
    }

    def transport(url: str) -> ProbeResult:
        return probe_lab_target(
            targets[url],
            allow_private_network=True,
            timeout_seconds=timeout_seconds,
        )

    return transport


def collect_seed_inventory(
    base_url: str,
    authorize: URLAuthorizer,
    *,
    session: Session,
    asset_id: int,
    allow_private_network: bool = False,
    resolver: Resolver | None = None,
    timeout_seconds: float = 5.0,
    transport: Transport | None = None,
) -> list[Observation]:
    """Probe the authorized seed inventory of ``base_url`` and store every result.

    Returns the stored observations in candidate order, or ``[]`` when policy
    authorizes nothing. Anything the transport raises (``TargetRejected``,
    ``ProbeTimeoutError``, ...) propagates to the caller; because nothing here
    commits, a caller that rolls back leaves no trace of a partial run.

    ``transport`` replaces the guarded routing for tests only. It is never the
    production path, and it cannot be reached at all when ``authorize`` rejects
    every candidate.
    """
    candidates = inventory_from_seeds(base_url, authorize)
    if not candidates:
        return []

    probe = transport
    if probe is None:
        if allow_private_network:
            probe = _lab_transport(
                candidates,
                authorize=authorize,
                resolver=resolver,
                timeout_seconds=timeout_seconds,
            )
        else:
            probe = _public_transport(
                authorize=authorize,
                resolver=resolver,
                timeout_seconds=timeout_seconds,
            )

    return [
        store_inventory_evidence(asset_id, probe(url), session) for url in candidates
    ]
