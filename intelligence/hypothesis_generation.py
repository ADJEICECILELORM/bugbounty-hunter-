"""Propose unverified, human-reviewable hypotheses from an asset's observations.

This is the first live caller of :mod:`intelligence.llm_client` and the only place
in the project that spends model tokens. It stays inside the project's founding
rule - a hypothesis is a candidate, not a finding:

* it never confirms anything, and never writes a status other than ``"unverified"``;
* it never triggers a tool call, probe, or any action beyond one text completion;
* it passes every target-originated string to the model through the
  :class:`~intelligence.llm_client.UntrustedText` boundary built by
  :mod:`intelligence.observation_summary`, so target text stays data;
* it adds rows with ``session.add()`` and ``session.flush()`` but never commits -
  the caller owns the transaction, as in every other module here;
* it lets :class:`~intelligence.llm_client.LLMClientError` propagate, so a failed
  generation is visible to the caller instead of looking like "no hypotheses";
* it enforces the investigation's LLM-call budget before spending a token, so a
  direct call is refused with :class:`BudgetExhausted` once the budget is full.
"""

from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from data.models import Asset, Hypothesis, Investigation, Observation, Task
from intelligence.categories import normalize_category
from intelligence.llm_client import generate_completion
from intelligence.observation_summary import summarize_observations
from verification.investigation_tasks import (
    LLM_TASK_KIND,
    MAX_LLM_CALLS_PER_INVESTIGATION,
    RUNNING,
    BudgetExhausted,
)

UNVERIFIED = "unverified"

MAX_HYPOTHESES = 3
_MAX_DESCRIPTION_LENGTH = 1000

SYSTEM_PROMPT = (
    "You assist a human security researcher reviewing observations from one "
    "authorized target. Propose 1-3 specific, testable security hypotheses. "
    "Output exactly one hypothesis per line, formatted as `category: description`, "
    "and nothing else. Use a short lowercase category such as access_control, "
    "idor, authentication, authorization, injection, information_disclosure, or "
    "misconfiguration. Each description must name the exact endpoint or record and "
    "the observable check a human should run next. These are suggestions for human "
    "review: never state that a vulnerability is confirmed or verified, never "
    "propose an action to take, and never emit a status, severity, confidence, or "
    "priority line."
)

# A line whose leading token is one of these is a metadata claim, not a
# hypothesis. It is dropped rather than reinterpreted as a category, so a model
# cannot turn "status: confirmed" text into a category or a row status.
_RESERVED_CATEGORIES = frozenset(
    {
        "status",
        "confidence",
        "severity",
        "verified",
        "verification",
        "priority",
    }
)

_LIST_MARKER = re.compile(r"^(?:[-*\u2022]|\d+[.)])\s+")
_WHITESPACE = re.compile(r"\s+")


def _clean_text(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()


def _clean_description(raw: str) -> str:
    return _clean_text(raw)[:_MAX_DESCRIPTION_LENGTH]


def _strip_markdown(line: str) -> str:
    """Remove emphasis/code markers without touching meaningful single asterisks."""
    return line.replace("**", "").replace("`", "").strip()


def parse_hypothesis_lines(response_text: str) -> list[tuple[str, str]]:
    """Parse ``category: description`` lines into candidate hypotheses.

    Everything the model returns is treated as untrusted text: blank lines, list
    markers, prose without a colon, and metadata claims whose category is in
    :data:`_RESERVED_CATEGORIES` are ignored. At most :data:`MAX_HYPOTHESES`
    unique pairs are returned, in the order the model produced them. A response
    with no usable line yields an empty list rather than a fabricated row.
    """
    parsed: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in response_text.splitlines():
        line = _strip_markdown(_LIST_MARKER.sub("", raw_line.strip()).strip())
        if not line or ":" not in line:
            continue
        raw_category, _, raw_description = line.partition(":")
        category = normalize_category(raw_category)
        if not category or category in _RESERVED_CATEGORIES:
            continue
        description = _clean_description(raw_description)
        if not description:
            continue
        candidate = (category, description)
        if candidate in seen:
            continue
        seen.add(candidate)
        parsed.append(candidate)
        if len(parsed) == MAX_HYPOTHESES:
            break
    return parsed


def generate_hypotheses(asset_id: int, session: Session) -> list[Hypothesis]:
    """Add unverified hypotheses for one asset, without committing.

    Returns the rows added to ``session``. Raises :class:`LookupError` when the
    asset does not exist, and lets
    :class:`~intelligence.llm_client.LLMClientError` propagate when the model
    call fails. An asset with no observations returns an empty list and makes no
    model call at all: with no evidence there is nothing to base a hypothesis on.

    Before any model call it enforces the investigation's LLM-call budget by
    counting ``hypothesis_generation`` tasks, the same proxy ``create_task``
    uses. :func:`orchestration.task_runner.run_task` marks the dispatched task
    ``running`` before calling this, so that in-flight task is excluded from the
    count (its slot was already reserved at creation); a direct call is refused
    with :class:`~verification.investigation_tasks.BudgetExhausted` once the
    investigation already holds ``max_llm_calls`` such tasks.
    """
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"Asset {asset_id} does not exist")

    observations = session.scalars(
        select(Observation)
        .where(Observation.asset_id == asset_id)
        .order_by(Observation.id)
    ).all()
    if not observations:
        return []

    not_running_llm_tasks = session.scalar(
        select(func.count(Task.id)).where(
            Task.investigation_id == asset.investigation_id,
            Task.kind == LLM_TASK_KIND,
            Task.status != RUNNING,
        )
    )
    investigation = session.get(Investigation, asset.investigation_id)
    max_llm_calls = (
        investigation.max_llm_calls
        if investigation.max_llm_calls is not None
        else MAX_LLM_CALLS_PER_INVESTIGATION
    )
    # ``run_task`` marks the dispatched task ``running`` before this runs, so a
    # running task is the call being made right now rather than a prior spend;
    # excluding it keeps the task path from double-counting its reserved slot. A
    # direct call has no running task and is refused once the recorded tasks
    # already fill the budget.
    if not_running_llm_tasks + 1 > max_llm_calls:
        raise BudgetExhausted(
            f"Investigation {asset.investigation_id} LLM call budget exhausted: "
            f"{not_running_llm_tasks} of {max_llm_calls} hypothesis_generation "
            "tasks already recorded"
        )

    summary = summarize_observations(
        observations,
        asset_id=asset.id,
        hostname=asset.hostname,
    )
    response = generate_completion(
        SYSTEM_PROMPT,
        summary.text,
        untrusted_context=summary.untrusted,
    )

    hypotheses: list[Hypothesis] = []
    for category, description in parse_hypothesis_lines(response):
        hypothesis = Hypothesis(
            asset_id=asset.id,
            category=category,
            description=description,
            status=UNVERIFIED,
        )
        session.add(hypothesis)
        hypotheses.append(hypothesis)

    session.flush()
    return hypotheses
