"""The human promotion gate: the only writer of a ``Hypothesis.status``.

Everything upstream of this module produces evidence and verdicts. None of it
can assert that a vulnerability was verified, because none of it can write a
status or a finding. This module is the single, deliberately narrow choke point
where a named human turns supported verdicts into a finding.

It is not an autonomous step. ``approved_by`` is required and is recorded in
both the finding and an append-only audit row, so every promotion carries a
name. It refuses rather than guesses:

* no approver, or an unknown hypothesis;
* a hypothesis that is not still ``unverified`` - which is also what makes a
  double promotion impossible;
* no ``supported`` verdict at all (nothing to promote);
* any ``refuted`` verdict (the evidence contradicts itself);
* a supporting verdict whose evidence is missing, belongs to another
  hypothesis, or is not a ``diff_check``;
* a verdict whose integrity digest does not verify against its bound evidence,
  hypothesis and target - which is what a hand-written row, a row rebound to
  other evidence, and a row whose evidence or wording was edited all look like.

The gate decides nothing on its own: it reads stored verdicts and delegates the
binding check to :func:`verification.verdict_integrity.verify_verdict`, the same
function the report loader uses, so a verdict that is not genuinely bound to its
evidence cannot be consumed anywhere.

It never commits: like every other writer in this project, the caller owns the
transaction.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Finding, Hypothesis, Observation, PromotionAudit, Verdict
from verification.verdict_checker import REFUTED, SUPPORTED
from verification.verdict_integrity import IntegrityCheck, verify_verdict

PROMOTION_ACTION = "promote_to_finding"
PROMOTABLE_STATUS = "unverified"
VERIFIED_STATUS = "verified"
_TITLE_LIMIT = 255


class PromotionRefused(Exception):
    """Raised when a hypothesis may not be promoted to a finding."""


def _default_title(hypothesis: Hypothesis, observation: Observation) -> str:
    """Build a title from stored values only."""
    hostname = "unknown host"
    if hypothesis.asset is not None and hypothesis.asset.hostname:
        hostname = hypothesis.asset.hostname

    data = observation.data if isinstance(observation.data, dict) else {}
    probe_a = data.get("probe_a")
    url = probe_a.get("url") if isinstance(probe_a, dict) else None
    endpoint = urlsplit(url).path if isinstance(url, str) and url else ""
    if not endpoint:
        endpoint = f" {hypothesis.category} hypothesis"
    return f"{hypothesis.category}: {hostname}{endpoint}"[:_TITLE_LIMIT]


def _supporting_evidence(
    hypothesis: Hypothesis, session: Session
) -> tuple[list[Verdict], list[Observation]]:
    """Collect the supported verdicts and their evidence, or refuse."""
    verdicts = list(
        session.scalars(
            select(Verdict)
            .where(Verdict.hypothesis_id == hypothesis.id)
            .order_by(Verdict.id)
        )
    )
    supporting = [
        verdict
        for verdict in verdicts
        if verdict.verdict == SUPPORTED and not verdict.is_control
    ]
    contradicted = [verdict for verdict in verdicts if verdict.verdict == REFUTED]

    if not supporting:
        raise PromotionRefused(
            f"Hypothesis {hypothesis.id} has no supported verdict, so there is "
            "nothing to promote"
        )
    if contradicted:
        refuted_ids = ", ".join(str(verdict.id) for verdict in contradicted)
        raise PromotionRefused(
            f"Hypothesis {hypothesis.id} has refuted verdicts ({refuted_ids}), so "
            "its evidence is contradictory and cannot be promoted"
        )

    observations: list[Observation] = []
    for verdict in supporting:
        observation = session.get(Observation, verdict.observation_id)
        if observation is None:
            raise PromotionRefused(
                f"Verdict {verdict.id} references observation "
                f"{verdict.observation_id}, which does not exist"
            )
        if observation.hypothesis_id != hypothesis.id:
            raise PromotionRefused(
                f"Verdict {verdict.id} references evidence belonging to hypothesis "
                f"{observation.hypothesis_id}, not {hypothesis.id}"
            )
        if observation.observation_type != "diff_check":
            raise PromotionRefused(
                f"Verdict {verdict.id} references {observation.observation_type!r} "
                "evidence, which is not a diff_check"
            )
        observations.append(observation)

    invalid = _integrity_failures(hypothesis, verdicts, session)
    if invalid:
        listed = ", ".join(
            f"#{verdict.id} ({check.reason})" for verdict, check in invalid
        )
        raise PromotionRefused(
            f"Hypothesis {hypothesis.id} has verdicts whose integrity digest does "
            "not verify against the stored evidence, hypothesis and target "
            f"({listed}), so no verdict here can be trusted"
        )

    return supporting, observations


def _integrity_failures(
    hypothesis: Hypothesis, verdicts: list[Verdict], session: Session
) -> list[tuple[Verdict, IntegrityCheck]]:
    """Every verdict on this hypothesis that is not bound to what it judged.

    Every verdict is checked, not just the supporting one: an edited control row
    means the stored judgements for this hypothesis cannot be trusted either.
    """
    failures: list[tuple[Verdict, IntegrityCheck]] = []
    for verdict in verdicts:
        observation = session.get(Observation, verdict.observation_id)
        check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
        if not check.ok:
            failures.append((verdict, check))
    return failures


def promote_to_finding(
    hypothesis_id: int,
    session: Session,
    *,
    approved_by: str,
    title: str | None = None,
) -> Finding:
    """Promote a hypothesis that stored evidence supports, as a named human.

    Raises :class:`PromotionRefused` when any precondition fails, in which case
    nothing at all is written, and :class:`LookupError` for an unknown
    hypothesis id.
    """
    approver = approved_by.strip() if isinstance(approved_by, str) else ""
    if not approver:
        raise PromotionRefused(
            "A named human approver (approved_by) is required to promote a hypothesis"
        )

    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise LookupError(f"Hypothesis {hypothesis_id} does not exist")
    if hypothesis.status != PROMOTABLE_STATUS:
        raise PromotionRefused(
            f"Hypothesis {hypothesis.id} is {hypothesis.status!r}, not "
            f"{PROMOTABLE_STATUS!r}, so it cannot be promoted"
        )

    supporting, observations = _supporting_evidence(hypothesis, session)

    finding = Finding(
        hypothesis_id=hypothesis.id,
        title=(title or _default_title(hypothesis, observations[0])).strip()[
            :_TITLE_LIMIT
        ],
        category=hypothesis.category,
        approved_by=approver,
    )
    session.add(finding)
    session.flush()

    hypothesis.status = VERIFIED_STATUS

    session.add(
        PromotionAudit(
            action=PROMOTION_ACTION,
            actor=approver,
            hypothesis_id=hypothesis.id,
            finding_id=finding.id,
            evidence_ids=[observation.id for observation in observations],
            verdict_ids=[verdict.id for verdict in supporting],
        )
    )
    session.flush()
    return finding
