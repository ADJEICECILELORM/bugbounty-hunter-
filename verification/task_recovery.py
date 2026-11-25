"""Human-initiated recovery for tasks left ``running`` by a crashed run.

This module is the only recovery path for a task whose process died, and it adds
no automation: nothing here starts, dispatches, schedules, or retries a task on
its own, and nothing reaches the network. It reuses the existing task layer
(:mod:`verification.investigation_tasks`) so status transitions, parameter and
dependency validation, and the append-only ``TaskEvent`` audit all stay
single-sourced - there is no parallel status writer or audit path here.

* ``find_stuck_tasks`` is read-only: it returns running tasks whose
  ``started_at`` is older than a threshold, and never writes.
* ``mark_task_failed_after_crash`` ends a running task as ``failed`` through the
  existing ``complete_task`` path and appends a ``crash_recovery`` event.
* ``create_retry_task`` copies a terminal (failed/cancelled) task into a new
  pending task through the existing ``create_task`` path and appends a
  ``retry_created`` event on the original. It never runs the retry.

The library functions flush only and never commit; the operator script that
calls them owns the transaction.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from data.models import Investigation, Task, TaskEvent
from verification.investigation_tasks import (
    RUNNING,
    append_task_event,
    complete_task,
    create_task,
)

RETRYABLE_STATUSES = frozenset({"failed", "cancelled"})
_SENSITIVE_REASON = re.compile(
    r"(?i)(?:\b(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)\b\s*[:=]|"
    r"\bbearer\s+\S+|https?://[^/\s:@]+:[^/@\s]+@)"
)
MAX_RECOVERY_REASON_CHARS = 500


def find_stuck_tasks(
    investigation_id: int,
    session: Session,
    *,
    running_longer_than_seconds: float,
) -> list[Task]:
    """Return an investigation's running tasks that have overrun. Read-only.

    A task is stuck when its ``status`` is ``running`` and ``started_at`` is
    older than ``running_longer_than_seconds``. Raises :class:`ValueError` for a
    negative threshold and :class:`LookupError` for a missing investigation.
    No side effects: nothing is written, started, or committed.
    """
    if running_longer_than_seconds < 0:
        raise ValueError("running_longer_than_seconds must be >= 0")

    if session.get(Investigation, investigation_id) is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")

    cutoff = datetime.now(UTC) - timedelta(seconds=running_longer_than_seconds)
    return list(
        session.scalars(
            select(Task)
            .where(
                Task.investigation_id == investigation_id,
                Task.status == RUNNING,
                Task.started_at < cutoff,
            )
            .order_by(Task.id)
        )
    )


def mark_task_failed_after_crash(task_id: int, session: Session, *, reason: str) -> Task:
    """End a running task as ``failed`` and record the operator's crash recovery.

    Reuses :func:`verification.investigation_tasks.complete_task` for the
    ``running -> failed`` transition, so a task that is not running is refused
    exactly like any other invalid completion, then appends a
    ``crash_recovery`` event carrying the reason. Flush only; never commits.
    """
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > MAX_RECOVERY_REASON_CHARS
        or any(ord(character) < 32 and character not in "\t\n" for character in reason)
        or _SENSITIVE_REASON.search(reason)
    ):
        raise ValueError(
            "reason must be a short, non-sensitive description without credentials"
        )

    with session.begin_nested():
        task = complete_task(
            task_id, session, final_status="failed", result_summary=reason
        )
        append_task_event(
            task.id,
            session,
            event_type="crash_recovery",
            detail={"reason": reason},
        )
    return task


def create_retry_task(original_task_id: int, session: Session) -> Task:
    """Copy a terminal task into a new pending retry. Never runs the retry.

    The original must be ``failed`` or ``cancelled``; a pending, running, or
    completed task is refused, as is a second retry of the same original. The
    new task reuses the original's ``kind``, ``params``, and ``depends_on``
    through :func:`verification.investigation_tasks.create_task`, so validation
    and the per-investigation cap stay single-sourced. The link back to the
    original is a ``retry_created`` event on the original. Flush only.
    """
    connection = session.connection()
    if connection.dialect.name == "sqlite":
        driver_connection = connection.connection.driver_connection
        if not driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")

    original = session.scalar(
        select(Task)
        .where(Task.id == original_task_id)
        .with_for_update()
    )
    if original is None:
        raise LookupError(f"Task {original_task_id} does not exist")

    if original.status not in RETRYABLE_STATUSES:
        raise ValueError(
            f"Task {original.id} is {original.status!r}; only a failed or "
            "cancelled task can be retried"
        )

    already_retried = session.scalar(
        select(TaskEvent.id).where(
            TaskEvent.task_id == original.id,
            TaskEvent.event_type == "retry_created",
        )
    )
    if already_retried is not None:
        raise ValueError(f"Task {original.id} already has a retry")

    try:
        with session.begin_nested():
            retry = create_task(
                original.investigation_id,
                session,
                kind=original.kind,
                title=original.title,
                params=original.params,
                depends_on=original.depends_on,
                dedupe_key=f"retry:v1:{original.id}",
            )
            append_task_event(
                original.id,
                session,
                event_type="retry_created",
                detail={"retry_task_id": retry.id, "retry_of": original.id},
            )
    except IntegrityError:
        raise ValueError(f"Task {original.id} already has a retry") from None
    return retry
