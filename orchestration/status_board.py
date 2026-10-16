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

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from data.models import Asset, Finding, Hypothesis, Investigation, Task
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
    """The detailed view of one investigation."""

    investigation_id: int
    status: str
    max_tasks: int | None
    max_llm_calls: int | None
    tasks: list[TaskSummary]
    stuck_tasks: list[TaskSummary]
    budget: BudgetRemaining
    hypothesis_counts: dict[str, int]
    findings: int


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

