"""Build an offline, evidence-linked researcher brief from stored observations.

This module performs no network, LLM, or verification calls. It only reads
already-stored observations and may add unverified review hypotheses plus their
support links to the caller's transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import (
    Asset,
    Hypothesis,
    HypothesisSupportingObservation,
    Observation,
    ObservationProvenance,
)
from gateway.scope_policy import ScopePolicy

UNVERIFIED = "unverified"
_ENDPOINT_INVENTORY = "endpoint_inventory"
_REVIEW_CATEGORY = "access_control_review"
_REVIEW_STATUSES = frozenset({200, 201, 202, 204, 301, 302, 307, 308, 401, 403})


@dataclass(frozen=True)
class ObservationCard:
    """Safe, bounded metadata for one stored observation."""

    observation_id: int
    observation_type: str
    recorded_at: datetime
    provenance_collector: str | None
    captured_at: datetime | None
    http_status: int | None
    content_length: int | None
    body_sha256_prefix: str | None


@dataclass(frozen=True)
class ResearchCandidate:
    """An unverified review hypothesis, with its supporting records and caveats."""

    hypothesis_id: int
    category: str
    description: str
    supporting_observation_ids: tuple[int, ...]
    evidence_strength: Literal["context_only"]
    confidence: Literal["unassessed"]
    potential_impact: Literal["undetermined"]
    testability: Literal["requires_researcher_review"]
    estimated_research_cost: Literal["low"]
    priority: Literal["review", "backlog"]
    priority_reason: str
    safe_next_step: str
    verification_status: Literal["unverified"]


@dataclass(frozen=True)
class ResearcherBrief:
    """Offline summary of one asset's stored evidence and review candidates."""

    asset_id: int
    hostname: str
    observations: tuple[ObservationCard, ...]
    candidates: tuple[ResearchCandidate, ...]


def _http_status(data: object) -> int | None:
    if not isinstance(data, dict):
        return None
    status = data.get("status_code")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return None
    return status


def _valid_endpoint_observation(asset: Asset, observation: Observation) -> bool:
    if observation.observation_type != _ENDPOINT_INVENTORY:
        return False
    if not isinstance(observation.data, dict) or _http_status(observation.data) is None:
        return False
    url = observation.data.get("url")
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False
        investigation = asset.investigation
        policy = ScopePolicy(
            investigation.program.authorized_scope,
            investigation.program.excluded_scope,
        )
        asset_policy = ScopePolicy([asset.hostname])
        return (
            policy.is_authorized(asset.hostname)
            and policy.is_authorized(parsed.hostname)
            and asset_policy.is_authorized(parsed.hostname)
        )
    except ValueError:
        return False


def _observation_card(
    observation: Observation,
    provenance: ObservationProvenance | None,
) -> ObservationCard:
    known_types = {"dns_record", "endpoint_inventory", "diff_check"}
    observation_type = (
        observation.observation_type
        if observation.observation_type in known_types
        else "unrecognized"
    )
    data = observation.data if isinstance(observation.data, dict) else {}
    status = (
        _http_status(data) if observation_type == _ENDPOINT_INVENTORY else None
    )
    content_length = data.get("content_length") if status is not None else None
    if (
        isinstance(content_length, bool)
        or not isinstance(content_length, int)
        or content_length < 0
    ):
        content_length = None
    digest = data.get("body_sha256") if status is not None else None
    digest_prefix = (
        digest[:12]
        if isinstance(digest, str)
        and len(digest) == 64
        and all(character in "0123456789abcdefABCDEF" for character in digest)
        else None
    )
    return ObservationCard(
        observation_id=observation.id,
        observation_type=observation_type,
        recorded_at=observation.created_at,
        provenance_collector=provenance.collector if provenance else None,
        captured_at=provenance.captured_at if provenance else None,
        http_status=status,
        content_length=content_length,
        body_sha256_prefix=digest_prefix,
    )


def _candidate_description(observation_id: int, status: int) -> str:
    return (
        f"Review the intended access-control policy for the HTTP endpoint recorded "
        f"in observation {observation_id}. Its stored response status is {status}; "
        "response metadata alone does not establish an access-control weakness."
    )


def _get_or_create_hypothesis(
    asset: Asset,
    observation: Observation,
    session: Session,
) -> Hypothesis | None:
    if not _valid_endpoint_observation(asset, observation):
        return None

    status = _http_status(observation.data)
    if status is None:
        return None
    description = _candidate_description(observation.id, status)
    hypothesis = session.scalar(
        select(Hypothesis)
        .where(
            Hypothesis.asset_id == asset.id,
            Hypothesis.category == _REVIEW_CATEGORY,
            Hypothesis.description == description,
        )
        .order_by(Hypothesis.id)
        .limit(1)
    )
    if hypothesis is None:
        hypothesis = Hypothesis(
            asset_id=asset.id,
            category=_REVIEW_CATEGORY,
            description=description,
            status=UNVERIFIED,
        )
        session.add(hypothesis)
        session.flush()
    elif hypothesis.status != UNVERIFIED:
        return None

    link_exists = session.scalar(
        select(HypothesisSupportingObservation.id).where(
            HypothesisSupportingObservation.hypothesis_id == hypothesis.id,
            HypothesisSupportingObservation.observation_id == observation.id,
        )
    )
    if link_exists is None:
        session.add(
            HypothesisSupportingObservation(
                hypothesis_id=hypothesis.id,
                observation_id=observation.id,
            )
        )
        session.flush()
    return hypothesis


def _candidate_for(
    hypothesis: Hypothesis,
    observation: Observation,
) -> ResearchCandidate:
    status = _http_status(observation.data)
    if status is None:
        raise ValueError(
            f"Observation {observation.id} is not a valid endpoint inventory row"
        )
    priority: Literal["review", "backlog"] = (
        "review" if status in _REVIEW_STATUSES else "backlog"
    )
    reason = (
        f"HTTP status {status} records a response useful for comparing the endpoint "
        "with its intended access policy; it is context, not vulnerability evidence."
        if priority == "review"
        else f"HTTP status {status} is retained as context; defer access-policy review "
        "until a researcher identifies a relevant requirement."
    )
    return ResearchCandidate(
        hypothesis_id=hypothesis.id,
        category=hypothesis.category,
        description=hypothesis.description,
        supporting_observation_ids=(observation.id,),
        evidence_strength="context_only",
        confidence="unassessed",
        potential_impact="undetermined",
        testability="requires_researcher_review",
        estimated_research_cost="low",
        priority=priority,
        priority_reason=reason,
        safe_next_step=(
            "Compare the recorded endpoint with the program's documented access "
            "policy. Do not send requests until a researcher confirms authorization "
            "and approves a verification plan."
        ),
        verification_status=UNVERIFIED,
    )


def build_researcher_brief(asset_id: int, session: Session) -> ResearcherBrief:
    """Create an offline evidence brief for an asset without committing.

    Endpoint inventory rows can yield one generic, unverified access-policy
    review candidate each. No observation content is sent to an LLM or network.
    Target-provided URLs, headers, DNS values, and response bodies are not copied
    into the brief. The caller owns the transaction and must explicitly commit
    any generated hypotheses and support links.
    """
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"Asset {asset_id} does not exist")

    observations = session.scalars(
        select(Observation)
        .where(Observation.asset_id == asset_id)
        .order_by(Observation.id)
    ).all()
    provenance_rows = session.scalars(
        select(ObservationProvenance).where(
            ObservationProvenance.observation_id.in_(
                [observation.id for observation in observations]
            )
        )
    ).all() if observations else []
    provenance_by_observation_id = {
        row.observation_id: row for row in provenance_rows
    }

    cards = tuple(
        _observation_card(
            observation,
            provenance_by_observation_id.get(observation.id),
        )
        for observation in observations
    )
    candidates = []
    for observation in observations:
        hypothesis = _get_or_create_hypothesis(asset, observation, session)
        if hypothesis is not None:
            candidates.append(_candidate_for(hypothesis, observation))

    candidates.sort(
        key=lambda item: (
            0 if item.priority == "review" else 1,
            item.supporting_observation_ids,
            item.hypothesis_id,
        )
    )
    session.flush()
    return ResearcherBrief(
        asset_id=asset.id,
        hostname=asset.hostname,
        observations=cards,
        candidates=tuple(candidates),
    )
