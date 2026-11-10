"""Read-only operator status board for investigations, tasks, and budgets.

This module answers "what is stored right now" and writes nothing. It never
commits, never changes an ``Investigation``, ``Task``, ``Hypothesis``,
``Finding``, or ``Verdict``, never reaches the network, and imports neither the
dispatcher, the supervisor, nor the promotion gate. Stuck-task detection uses
the same rule as :func:`verification.task_recovery.find_stuck_tasks` - a task
is stuck when it is ``running`` and ``started_at`` is older than a threshold -
so the board and the recovery path agree on what "stuck" means.

The schema is read defensively so the board also works against the older
``lab_evidence_v3.db``: the budget-override columns and the ``tasks`` table were
added after the first live-lab run, so a database that lacks them simply
reports no overrides and no tasks rather than failing.

The functions return dataclasses and print nothing; the operator-facing printer
lives in ``scripts/investigation_status.py``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from data.models import (
    Asset,
    Finding,
    Hypothesis,
    HypothesisSupportingObservation,
    Investigation,
    Observation,
    ObservationProvenance,
    Task,
)
from verification.investigation_tasks import (
    LLM_TASK_KIND,
    MAX_LLM_CALLS_PER_INVESTIGATION,
    MAX_TASKS_PER_INVESTIGATION,
    RUNNING,
)

DEFAULT_STUCK_THRESHOLD_SECONDS = 3600.0


@dataclass(frozen=True)
class TaskSummary:
    """A task's stored fields, for display only."""

    task_id: int
    kind: str
    status: str
    title: str
    started_at: datetime | None
    ended_at: datetime | None


@dataclass(frozen=True)
class StuckTask:
    """A running task that has overrun, with the investigation it belongs to."""

    investigation_id: int
    task: TaskSummary


@dataclass(frozen=True)
class BudgetRemaining:
    """How many tasks / LLM calls an investigation's budget still allows."""

    tasks_remaining: int
    llm_calls_remaining: int


@dataclass(frozen=True)
class InvestigationSummary:
    """One investigation in the list view, with per-status task counts."""

    investigation_id: int
    status: str
    max_tasks: int | None
    max_llm_calls: int | None
    total_tasks: int
    task_counts: dict[str, int]


@dataclass(frozen=True)
class InvestigationStatus:
    """The detailed operational view of one investigation."""

    investigation_id: int
    status: str
    max_tasks: int | None
    max_llm_calls: int | None
    tasks: list[TaskSummary]
    stuck_tasks: list[TaskSummary]
    budget: BudgetRemaining
    hypothesis_counts: dict[str, int]
    findings: int


@dataclass(frozen=True)
class ObservationSummary:
    """A bounded, read-only summary of one stored observation."""

    observation_id: int
    asset_id: int
    asset_hostname: str
    observation_type: str
    created_at: datetime
    provenance_collector: str | None
    captured_at: datetime | None
    summary: str
    evidence_interpretation: str


@dataclass(frozen=True)
class HypothesisSummary:
    """Read-only summary of one stored hypothesis with support metadata."""

    hypothesis_id: int
    asset_id: int
    asset_hostname: str
    category: str
    status: str
    description: str
    confidence: str | None
    impact: str | None
    priority: str | None
    priority_reason: str | None
    supporting_observation_ids: tuple[int, ...] | None
    evidence_missing: bool | None
    unavailable_support_count: int | None
    finding_id: int | None
    evidence_interpretation: str
    additional_evidence: str
    recommended_next_step: str


@dataclass(frozen=True)
class IntelligenceDashboard:
    """A read-only, researcher-facing view over an investigation."""

    investigation_id: int
    status: str | None
    max_tasks: int | None
    max_llm_calls: int | None
    assets: int | None
    observations: int | None
    hypotheses: int | None
    findings: int | None
    asset_hostnames: dict[int, str] | None
    observation_groups: dict[int, list[ObservationSummary]] | None
    hypotheses_by_asset: dict[int, list[HypothesisSummary]] | None
    health_indicators: dict[str, str]
    data_availability: dict[str, str]


def _schema(session: Session) -> tuple[bool, bool]:
    """Return (investigations_have_budget_columns, tasks_table_exists)."""
    inspector = inspect(session.connection())
    investigation_columns = {
        column["name"] for column in inspector.get_columns("investigations")
    }
    has_budget_columns = (
        "max_tasks" in investigation_columns and "max_llm_calls" in investigation_columns
    )
    return has_budget_columns, inspector.has_table("tasks")


def _effective_max_tasks(max_tasks: int | None) -> int:
    return max_tasks if max_tasks is not None else MAX_TASKS_PER_INVESTIGATION


def _effective_max_llm_calls(max_llm_calls: int | None) -> int:
    return max_llm_calls if max_llm_calls is not None else MAX_LLM_CALLS_PER_INVESTIGATION


def _to_task_summary(task: Task) -> TaskSummary:
    return TaskSummary(
        task_id=task.id,
        kind=task.kind,
        status=task.status,
        title=task.title,
        started_at=task.started_at,
        ended_at=task.ended_at,
    )


def _running_tasks_older_than(
    session: Session,
    threshold_seconds: float,
    investigation_id: int | None = None,
) -> list[Task]:
    cutoff = datetime.now(UTC) - timedelta(seconds=threshold_seconds)
    stmt = (
        select(Task)
        .where(Task.status == RUNNING, Task.started_at < cutoff)
        .order_by(Task.id)
    )
    if investigation_id is not None:
        stmt = stmt.where(Task.investigation_id == investigation_id)
    return list(session.scalars(stmt))


def list_investigations(session: Session) -> list[InvestigationSummary]:
    """Return every investigation with its task counts by status. Read-only."""
    has_budget_columns, has_tasks = _schema(session)

    rows = session.execute(
        select(Investigation.id, Investigation.status).order_by(Investigation.id)
    ).all()

    overrides: dict[int, tuple[int | None, int | None]] = {}
    if has_budget_columns:
        for investigation_id, max_tasks, max_llm_calls in session.execute(
            select(
                Investigation.id,
                Investigation.max_tasks,
                Investigation.max_llm_calls,
            )
        ).all():
            overrides[investigation_id] = (max_tasks, max_llm_calls)

    task_counts: dict[int, dict[str, int]] = {}
    if has_tasks:
        for investigation_id, status, count in session.execute(
            select(
                Task.investigation_id,
                Task.status,
                func.count(Task.id),
            ).group_by(Task.investigation_id, Task.status)
        ).all():
            task_counts.setdefault(investigation_id, {})[status] = count

    summaries: list[InvestigationSummary] = []
    for investigation_id, status in rows:
        max_tasks, max_llm_calls = overrides.get(
            investigation_id, (None, None)
        )
        counts = dict(sorted(task_counts.get(investigation_id, {}).items()))
        summaries.append(
            InvestigationSummary(
                investigation_id=investigation_id,
                status=status,
                max_tasks=max_tasks,
                max_llm_calls=max_llm_calls,
                total_tasks=sum(counts.values()),
                task_counts=counts,
            )
        )
    return summaries


def find_stuck_tasks(
    session: Session,
    *,
    threshold_seconds: float = DEFAULT_STUCK_THRESHOLD_SECONDS,
) -> list[StuckTask]:
    """Return every running task that has overrun, across all investigations.

    Read-only: nothing is written, started, or committed. Raises
    :class:`ValueError` for a negative ``threshold_seconds``. A database that
    predates the task model simply has no tasks, so it yields an empty list.
    """
    if threshold_seconds < 0:
        raise ValueError("threshold_seconds must be >= 0")

    _, has_tasks = _schema(session)
    if not has_tasks:
        return []

    return [
        StuckTask(
            investigation_id=task.investigation_id,
            task=_to_task_summary(task),
        )
        for task in _running_tasks_older_than(session, threshold_seconds)
    ]


def get_investigation_status(
    session: Session,
    investigation_id: int,
    *,
    threshold_seconds: float = DEFAULT_STUCK_THRESHOLD_SECONDS,
) -> InvestigationStatus:
    """Return one investigation's tasks, stuck tasks, budget, and counters.

    Read-only. Raises :class:`LookupError` for a missing investigation and
    :class:`ValueError` for a negative ``threshold_seconds``.
    """
    has_budget_columns, has_tasks = _schema(session)

    base = session.execute(
        select(Investigation.id, Investigation.status).where(
            Investigation.id == investigation_id
        )
    ).one_or_none()
    if base is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")

    found_id, status = base
    max_tasks: int | None = None
    max_llm_calls: int | None = None
    if has_budget_columns:
        max_tasks, max_llm_calls = session.execute(
            select(Investigation.max_tasks, Investigation.max_llm_calls).where(
                Investigation.id == investigation_id
            )
        ).one()

    tasks: list[TaskSummary] = []
    stuck_tasks: list[TaskSummary] = []
    total_tasks = 0
    llm_tasks = 0
    if has_tasks:
        tasks = [
            _to_task_summary(task)
            for task in session.scalars(
                select(Task)
                .where(Task.investigation_id == investigation_id)
                .order_by(Task.id)
            )
        ]
        stuck_tasks = [
            _to_task_summary(task)
            for task in _running_tasks_older_than(
                session, threshold_seconds, investigation_id
            )
        ]
        total_tasks = len(tasks)
        llm_tasks = (
            session.scalar(
                select(func.count(Task.id)).where(
                    Task.investigation_id == investigation_id,
                    Task.kind == LLM_TASK_KIND,
                )
            )
            or 0
        )

    hypothesis_rows = session.execute(
        select(Hypothesis.status, func.count(Hypothesis.id))
        .join(Asset, Hypothesis.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .group_by(Hypothesis.status)
    ).all()
    hypothesis_counts = {status: count for status, count in hypothesis_rows}

    findings = (
        session.scalar(
            select(func.count(Finding.id))
            .join(Hypothesis, Finding.hypothesis_id == Hypothesis.id)
            .join(Asset, Hypothesis.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id)
        )
        or 0
    )

    return InvestigationStatus(
        investigation_id=found_id,
        status=status,
        max_tasks=max_tasks,
        max_llm_calls=max_llm_calls,
        tasks=tasks,
        stuck_tasks=stuck_tasks,
        budget=BudgetRemaining(
            tasks_remaining=_effective_max_tasks(max_tasks) - total_tasks,
            llm_calls_remaining=_effective_max_llm_calls(max_llm_calls) - llm_tasks,
        ),
        hypothesis_counts=hypothesis_counts,
        findings=findings,
    )


def _display_text(value: str, *, limit: int) -> str:
    """Bound and remove terminal control characters from stored display text."""
    return " ".join(
        "".join(character if character.isprintable() else " " for character in value)
        .split()
    )[:limit]


def _observation_summary(
    observation: Observation,
    asset_hostname: str,
    provenance: ObservationProvenance | None,
) -> ObservationSummary:
    """Create a bounded observation card without exposing raw target content."""
    data = observation.data if isinstance(observation.data, dict) else {}
    if observation.observation_type == "endpoint_inventory":
        status_code = data.get("status_code")
        status = (
            f"HTTP {status_code}"
            if isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and 100 <= status_code <= 599
            else "HTTP status unavailable"
        )
        summary = f"endpoint_inventory ({status})"
    elif observation.observation_type == "dns_record":
        record_type = data.get("record_type")
        safe_record_type = (
            _display_text(record_type, limit=16).upper()
            if isinstance(record_type, str)
            else ""
        )
        summary = (
            f"DNS record observed ({safe_record_type}; value omitted)"
            if safe_record_type
            else "DNS record observed (value omitted)"
        )
    elif observation.observation_type == "diff_check":
        summary = "diff_check (status/body comparison)"
    else:
        summary = "Unrecognized observation type; details omitted"

    return ObservationSummary(
        observation_id=observation.id,
        asset_id=observation.asset_id,
        asset_hostname=asset_hostname,
        observation_type=(
            observation.observation_type
            if observation.observation_type
            in {"dns_record", "endpoint_inventory", "diff_check"}
            else "unrecognized"
        ),
        created_at=observation.created_at,
        provenance_collector=(
            _display_text(provenance.collector, limit=100)
            if provenance
            else None
        ),
        captured_at=provenance.captured_at if provenance else None,
        summary=summary,
        evidence_interpretation=(
            "Stored observation; not independently validated by this dashboard "
            "and not a vulnerability verdict."
        ),
    )


def _hypothesis_summary(
    hypothesis: Hypothesis,
    *,
    asset_hostname: str,
    supporting_observation_ids: tuple[int, ...] | None,
    unavailable_support_count: int | None,
    finding_id: int | None,
    findings_available: bool,
    review_order: int | None,
) -> HypothesisSummary:
    """Summarize a hypothesis without treating support links as verification."""
    evidence_missing = (
        None if supporting_observation_ids is None else not supporting_observation_ids
    )
    if finding_id is not None:
        evidence_interpretation = (
            f"Human-approved Finding #{finding_id} is stored; the dashboard does "
            "not independently re-verify it."
        )
    elif findings_available:
        evidence_interpretation = (
            "Research hypothesis (inference), not a verified vulnerability."
        )
    else:
        evidence_interpretation = (
            "Finding status is unavailable in this database schema; this dashboard "
            "cannot establish whether a human-approved Finding is stored."
        )

    if supporting_observation_ids is None:
        additional_evidence = (
            "Supporting-observation traceability is unavailable in this database "
            "schema; inspect the original records before relying on this hypothesis."
        )
        recommended_next_step = (
            "Restore or inspect the supporting-observation records before considering "
            "verification; do not treat this hypothesis as a finding."
        )
    elif evidence_missing:
        additional_evidence = (
            "No valid same-asset supporting observation is available. Recover or "
            "review the original source evidence before relying on this hypothesis."
        )
        recommended_next_step = (
            "Locate or record traceable supporting evidence before considering "
            "verification; do not treat this hypothesis as a finding."
        )
    else:
        additional_evidence = (
            "To strengthen or disprove this hypothesis, compare the linked "
            "observations with the program's documented requirements and expected "
            "behavior; the links record context, not proof."
        )
        recommended_next_step = (
            "Review the linked stored observations and relevant program policy. "
            "Any active verification requires confirmed authorization and explicit "
            "researcher approval."
        )
    return HypothesisSummary(
        hypothesis_id=hypothesis.id,
        asset_id=hypothesis.asset_id,
        asset_hostname=asset_hostname,
        category=_display_text(hypothesis.category, limit=64),
        status=_display_text(hypothesis.status, limit=32),
        description=_display_text(hypothesis.description, limit=1000),
        confidence=None,
        impact=None,
        priority=f"review order {review_order}" if review_order is not None else None,
        priority_reason=(
            "Existing deterministic unverified-hypothesis ordering; not a severity "
            "or confidence score."
            if review_order is not None
            else None
        ),
        supporting_observation_ids=supporting_observation_ids,
        evidence_missing=evidence_missing,
        unavailable_support_count=unavailable_support_count,
        finding_id=finding_id,
        evidence_interpretation=evidence_interpretation,
        additional_evidence=additional_evidence,
        recommended_next_step=recommended_next_step,
    )


def _table_columns(inspector: Any, table_name: str) -> set[str] | None:
    if not inspector.has_table(table_name):
        return None
    return {column["name"] for column in inspector.get_columns(table_name)}


def _schema_availability(
    columns: set[str] | None,
    required: set[str],
    table_name: str,
) -> str:
    if columns is None:
        return f"unavailable: table {table_name!r} is missing"
    missing = sorted(required - columns)
    if missing:
        return (
            f"unavailable: table {table_name!r} is missing required columns "
            + ", ".join(missing)
        )
    return "available"


def _empty_dashboard(
    investigation_id: int,
    data_availability: dict[str, str],
    *,
    status: str | None = None,
) -> IntelligenceDashboard:
    return IntelligenceDashboard(
        investigation_id=investigation_id,
        status=status,
        max_tasks=None,
        max_llm_calls=None,
        assets=None,
        observations=None,
        hypotheses=None,
        findings=None,
        asset_hostnames=None,
        observation_groups=None,
        hypotheses_by_asset=None,
        health_indicators=dict(data_availability),
        data_availability=data_availability,
    )


def _get_researcher_dashboard_without_autoflush(
    session: Session,
    investigation_id: int,
) -> IntelligenceDashboard:
    inspector = inspect(session.connection())
    table_columns = {
        table_name: _table_columns(inspector, table_name)
        for table_name in (
            "investigations",
            "assets",
            "observations",
            "observation_provenance",
            "hypotheses",
            "hypothesis_supporting_observations",
            "findings",
        )
    }

    required_columns = {
        "investigation": ("investigations", {"id", "status"}),
        "assets": ("assets", {"id", "investigation_id", "hostname"}),
        "observations": (
            "observations",
            {"id", "asset_id", "observation_type", "data", "created_at"},
        ),
        "provenance": (
            "observation_provenance",
            {"observation_id", "collector"},
        ),
        "hypotheses": (
            "hypotheses",
            {"id", "asset_id", "category", "description", "status"},
        ),
        "support": (
            "hypothesis_supporting_observations",
            {"hypothesis_id", "observation_id"},
        ),
        "findings": ("findings", {"id", "hypothesis_id"}),
    }
    data_availability = {
        name: _schema_availability(
            table_columns[table_name], required, table_name
        )
        for name, (table_name, required) in required_columns.items()
    }
    investigation_columns = table_columns["investigations"]
    if data_availability["investigation"] != "available":
        for key in (
            "assets",
            "observations",
            "provenance",
            "hypotheses",
            "support",
            "findings",
            "budget",
        ):
            data_availability[key] = "unavailable: investigation identity is unavailable"
        return _empty_dashboard(investigation_id, data_availability)

    investigation_row = session.execute(
        select(Investigation.id, Investigation.status).where(
            Investigation.id == investigation_id
        )
    ).one_or_none()
    if investigation_row is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")
    investigation_status = _display_text(str(investigation_row.status), limit=32)

    budget_columns = {"max_tasks", "max_llm_calls"}
    present_budget_columns = budget_columns & (investigation_columns or set())
    if present_budget_columns == budget_columns:
        max_tasks, max_llm_calls = session.execute(
            select(Investigation.max_tasks, Investigation.max_llm_calls).where(
                Investigation.id == investigation_id
            )
        ).one()
        data_availability["budget"] = "available"
    else:
        max_tasks = max_llm_calls = None
        missing_budget_columns = sorted(budget_columns - present_budget_columns)
        data_availability["budget"] = (
            "unavailable: missing columns " + ", ".join(missing_budget_columns)
        )

    asset_hostnames: dict[int, str] = {}
    if data_availability["assets"] == "available":
        asset_rows = session.execute(
            select(Asset.id, Asset.hostname)
            .where(Asset.investigation_id == investigation_id)
            .order_by(Asset.id)
        ).all()
        asset_hostnames = {
            asset_id: _display_text(hostname, limit=253)
            for asset_id, hostname in asset_rows
        }
        data_availability["assets"] = "available" if asset_rows else "empty"
    asset_ids = list(asset_hostnames)

    if data_availability["assets"].startswith("unavailable"):
        for key in ("observations", "hypotheses"):
            if data_availability[key] == "available":
                data_availability[key] = (
                    "unavailable: asset data is unavailable for investigation scoping"
                )

    observations: list[tuple[int, int, str, Any, datetime]] = []
    if (
        not data_availability["assets"].startswith("unavailable")
        and data_availability["observations"] == "available"
    ):
        if asset_ids:
            observations = list(
                session.execute(
                    select(
                        Observation.id,
                        Observation.asset_id,
                        Observation.observation_type,
                        Observation.data,
                        Observation.created_at,
                    )
                    .where(Observation.asset_id.in_(asset_ids))
                    .order_by(Observation.id)
                ).all()
            )
        data_availability["observations"] = (
            "available" if observations else "empty"
        )
    observation_by_id = {
        observation_id: (asset_id, observation_type, data, created_at)
        for observation_id, asset_id, observation_type, data, created_at in observations
    }
    observation_ids = list(observation_by_id)

    provenance_by_observation_id: dict[int, tuple[str, datetime | None]] = {}
    provenance_columns = table_columns["observation_provenance"]
    if (
        data_availability["observations"].startswith("unavailable")
        and data_availability["provenance"] == "available"
    ):
        data_availability["provenance"] = (
            "unavailable: observation data is unavailable for provenance lookup"
        )
    if data_availability["provenance"] == "available":
        if observation_ids:
            provenance_select = [
                ObservationProvenance.observation_id,
                ObservationProvenance.collector,
            ]
            has_captured_at = "captured_at" in (provenance_columns or set())
            if has_captured_at:
                provenance_select.append(ObservationProvenance.captured_at)
            rows = session.execute(
                select(*provenance_select).where(
                    ObservationProvenance.observation_id.in_(observation_ids)
                )
            ).all()
            provenance_by_observation_id = {
                row[0]: (row[1], row[2] if has_captured_at else None)
                for row in rows
            }
            if rows and not has_captured_at:
                data_availability["provenance"] = (
                    "partial: column 'captured_at' is missing"
                )
            else:
                data_availability["provenance"] = (
                    "available" if rows else "empty"
                )
        elif "captured_at" not in (provenance_columns or set()):
            data_availability["provenance"] = (
                "partial: column 'captured_at' is missing"
            )
        else:
            data_availability["provenance"] = "empty"

    observation_groups: dict[int, list[ObservationSummary]] = {
        asset_id: [] for asset_id in asset_ids
    }
    for observation_id, asset_id, observation_type, data, created_at in observations:
        hostname = asset_hostnames[asset_id]
        collector, captured_at = provenance_by_observation_id.get(
            observation_id, (None, None)
        )
        observation = Observation(
            id=observation_id,
            asset_id=asset_id,
            observation_type=observation_type,
            data=data,
            created_at=created_at,
        )
        summary = _observation_summary(
            observation,
            hostname,
            (
                ObservationProvenance(
                    observation_id=observation_id,
                    collector=collector,
                    captured_at=captured_at,
                )
                if collector is not None
                else None
            ),
        )
        observation_groups[asset_id].append(summary)

    hypotheses: list[tuple[int, int, str, str, str, datetime | None]] = []
    hypothesis_columns = table_columns["hypotheses"]
    has_created_at = "created_at" in (hypothesis_columns or set())
    if (
        not data_availability["assets"].startswith("unavailable")
        and data_availability["hypotheses"] == "available"
    ):
        if asset_ids:
            hypothesis_select = [
                Hypothesis.id,
                Hypothesis.asset_id,
                Hypothesis.category,
                Hypothesis.description,
                Hypothesis.status,
            ]
            if has_created_at:
                hypothesis_select.append(Hypothesis.created_at)
            rows = session.execute(
                select(*hypothesis_select)
                .where(Hypothesis.asset_id.in_(asset_ids))
                .order_by(Hypothesis.id)
            ).all()
            hypotheses = [
                (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5] if has_created_at else None,
                )
                for row in rows
            ]
        data_availability["hypotheses"] = "available" if hypotheses else "empty"
    hypothesis_ids = [row[0] for row in hypotheses]

    if (
        data_availability["observations"].startswith("unavailable")
        and data_availability["support"] == "available"
    ):
        data_availability["support"] = (
            "unavailable: observations cannot be checked for same-asset support"
        )
    if (
        data_availability["hypotheses"].startswith("unavailable")
        and data_availability["support"] == "available"
    ):
        data_availability["support"] = (
            "unavailable: hypothesis data is unavailable for support lookup"
        )
    support_by_hypothesis: dict[int, list[int]] = defaultdict(list)
    if (
        data_availability["support"] == "available"
        and data_availability["observations"] in {"available", "empty"}
        and hypothesis_ids
    ):
        support_rows = session.execute(
            select(
                HypothesisSupportingObservation.hypothesis_id,
                HypothesisSupportingObservation.observation_id,
            ).where(
                HypothesisSupportingObservation.hypothesis_id.in_(hypothesis_ids)
            )
        ).all()
        for hypothesis_id, observation_id in support_rows:
            support_by_hypothesis[hypothesis_id].append(observation_id)
        data_availability["support"] = (
            "available" if support_rows else "empty"
        )
    elif data_availability["support"] == "available" and not hypothesis_ids:
        data_availability["support"] = "empty"

    findings_by_hypothesis: dict[int, int] = {}
    if (
        data_availability["findings"] == "available"
        and not data_availability["hypotheses"].startswith("unavailable")
        and hypothesis_ids
    ):
        finding_rows = session.execute(
            select(Finding.hypothesis_id, Finding.id).where(
                Finding.hypothesis_id.in_(hypothesis_ids)
            )
        ).all()
        findings_by_hypothesis = dict(finding_rows)
        data_availability["findings"] = (
            "available" if finding_rows else "empty"
        )
    elif (
        data_availability["hypotheses"].startswith("unavailable")
        and data_availability["findings"] == "available"
    ):
        data_availability["findings"] = (
            "unavailable: hypothesis data is unavailable for investigation scoping"
        )
    elif data_availability["findings"] == "available" and not hypothesis_ids:
        data_availability["findings"] = "empty"

    review_order: dict[int, int] = {}
    if hypotheses and has_created_at:
        from intelligence.prioritization import prioritize_hypotheses

        rankable = [
            Hypothesis(
                id=hypothesis_id,
                asset_id=asset_id,
                category=category,
                description=description,
                status=status,
                created_at=created_at,
            )
            for (
                hypothesis_id,
                asset_id,
                category,
                description,
                status,
                created_at,
            ) in hypotheses
        ]
        review_order = {
            hypothesis.id: index
            for index, hypothesis in enumerate(
                prioritize_hypotheses(rankable), start=1
            )
        }
    elif data_availability["hypotheses"] != "unavailable":
        data_availability["review_order"] = (
            "unavailable: hypothesis table is missing column 'created_at'"
        )

    hypotheses_by_asset: dict[int, list[HypothesisSummary]] = {
        asset_id: [] for asset_id in asset_ids
    }
    support_is_available = not data_availability["support"].startswith(
        "unavailable"
    )
    findings_are_available = not data_availability["findings"].startswith(
        "unavailable"
    )
    for (
        hypothesis_id,
        asset_id,
        category,
        description,
        status,
        created_at,
    ) in hypotheses:
        all_support_ids = support_by_hypothesis.get(hypothesis_id, [])
        valid_support_ids = tuple(
            sorted(
                observation_id
                for observation_id in all_support_ids
                if observation_id in observation_by_id
                and observation_by_id[observation_id][0] == asset_id
            )
        )
        hypothesis = Hypothesis(
            id=hypothesis_id,
            asset_id=asset_id,
            category=category,
            description=description,
            status=status,
            created_at=created_at,
        )
        hypotheses_by_asset[asset_id].append(
            _hypothesis_summary(
                hypothesis,
                asset_hostname=asset_hostnames[asset_id],
                supporting_observation_ids=(
                    valid_support_ids if support_is_available else None
                ),
                unavailable_support_count=(
                    len(all_support_ids) - len(valid_support_ids)
                    if support_is_available
                    else None
                ),
                finding_id=findings_by_hypothesis.get(hypothesis_id),
                findings_available=findings_are_available,
                review_order=review_order.get(hypothesis_id),
            )
        )
    for summaries in hypotheses_by_asset.values():
        summaries.sort(
            key=lambda summary: (
                review_order.get(summary.hypothesis_id, float("inf")),
                summary.hypothesis_id,
            )
        )

    def row_count_or_unavailable(name: str, count: int) -> int | None:
        return (
            None
            if data_availability[name].startswith("unavailable")
            else count
        )

    traceability_complete = all(
        summary.evidence_missing is False
        for summaries in hypotheses_by_asset.values()
        for summary in summaries
    )
    health_indicators = {
        "status": investigation_status,
        "assets": data_availability["assets"],
        "observations": data_availability["observations"],
        "hypotheses": data_availability["hypotheses"],
        "evidence_traceability": (
            "unavailable"
            if not support_is_available
            else "complete"
            if hypotheses and traceability_complete
            else "review"
            if hypotheses
            else "empty"
        ),
        "findings": data_availability["findings"],
    }
    return IntelligenceDashboard(
        investigation_id=investigation_id,
        status=investigation_status,
        max_tasks=max_tasks,
        max_llm_calls=max_llm_calls,
        assets=row_count_or_unavailable("assets", len(asset_hostnames)),
        observations=row_count_or_unavailable("observations", len(observations)),
        hypotheses=row_count_or_unavailable("hypotheses", len(hypotheses)),
        findings=row_count_or_unavailable(
            "findings", len(findings_by_hypothesis)
        ),
        asset_hostnames=(
            dict(sorted(asset_hostnames.items()))
            if not data_availability["assets"].startswith("unavailable")
            else None
        ),
        observation_groups=(
            dict(sorted(observation_groups.items()))
            if not data_availability["observations"].startswith("unavailable")
            else None
        ),
        hypotheses_by_asset=(
            dict(sorted(hypotheses_by_asset.items()))
            if not data_availability["hypotheses"].startswith("unavailable")
            else None
        ),
        health_indicators=health_indicators,
        data_availability=data_availability,
    )


def get_researcher_dashboard(
    session: Session,
    investigation_id: int,
) -> IntelligenceDashboard:
    """Return a database-backed dashboard without flushing caller-owned state."""
    with session.no_autoflush:
        return _get_researcher_dashboard_without_autoflush(session, investigation_id)
