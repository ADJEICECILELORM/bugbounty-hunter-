"""Operator-tracked tasks inside a running investigation.

Four session functions and nothing else: ``create_task``, ``start_task``,
``complete_task`` and ``list_tasks``. A ``Task`` is a record of work an operator
has decided to do, not a job: nothing in this module (or anywhere in the
project) picks a task up and runs it. Every transition happens only because an
operator called one of these functions.

The writers use ``session.add()``/``session.flush()`` and never commit - the
caller owns the transaction. None of them touches a ``Hypothesis``, ``Finding``,
``Verdict``, or ``Observation``, and the module imports nothing from the gateway
and makes no request.

Transitions::

    pending --start_task--> running --complete_task--> completed | failed | cancelled
    pending --complete_task(final_status="cancelled")--> cancelled

``completed`` and ``failed`` describe work that was attempted, so they require a
running task; a pending task can only be ``cancelled``. Terminal tasks never
change again. While any task is pending or running,
:func:`verification.investigation_lifecycle.close_investigation` refuses to close
its investigation, so a closed investigation never has an open task.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Investigation, Task

# Mirrors ``investigation_lifecycle.RUNNING``; kept local so the lifecycle module
# can import from this one without a cycle (a test asserts the two agree).
INVESTIGATION_RUNNING = "running"

TASK_KINDS = frozenset(
    {"recon", "inventory", "hypothesis_review", "verification", "report"}
)

PENDING = "pending"
RUNNING = "running"
OPEN_STATUSES = frozenset({PENDING, RUNNING})
FINAL_STATUSES = frozenset({"completed", "cancelled", "failed"})


def create_task(
    investigation_id: int,
    session: Session,
    *,
    kind: str,
    title: str,
) -> Task:
    """Add a ``pending`` task to a running investigation and flush it.

    Raises :class:`ValueError` for a ``kind`` outside ``TASK_KINDS``, a blank
    ``title``, or an investigation that is not running, and
    :class:`LookupError` for a missing investigation. Does not commit.
    """
    if kind not in TASK_KINDS:
        raise ValueError(f"kind must be one of {sorted(TASK_KINDS)!r}, got {kind!r}")
    if not title.strip():
        raise ValueError("title must not be blank")

    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")
    if investigation.status != INVESTIGATION_RUNNING:
        raise ValueError(
            f"Investigation {investigation_id} is {investigation.status!r}, "
            f"not {INVESTIGATION_RUNNING!r}"
        )

    task = Task(
        investigation_id=investigation_id, kind=kind, title=title, status=PENDING
    )
    session.add(task)
    session.flush()
    return task


def start_task(task_id: int, session: Session) -> Task:
    """Move a task from ``pending`` to ``running`` and set ``started_at``.

    Raises :class:`LookupError` for a missing task and :class:`ValueError` for a
    task that is not pending. Does not commit.
    """
    task = _get_task(task_id, session)
    if task.status != PENDING:
        raise ValueError(f"Task {task_id} is {task.status!r}, not {PENDING!r}")

    task.status = RUNNING
    task.started_at = datetime.now(UTC)
    session.flush()
    return task


def complete_task(
    task_id: int,
    session: Session,
    *,
    final_status: str,
    result_summary: str | None = None,
) -> Task:
    """Set a terminal ``status``, ``ended_at`` and optional ``result_summary``.

    ``final_status`` must be one of ``FINAL_STATUSES``. ``completed`` and
    ``failed`` require a running task; ``cancelled`` accepts a pending or running
    one. Anything else raises :class:`ValueError`; a missing task raises
    :class:`LookupError`. Does not commit.
    """
    if final_status not in FINAL_STATUSES:
        raise ValueError(
            f"final_status must be one of {sorted(FINAL_STATUSES)!r}, "
            f"got {final_status!r}"
        )

    task = _get_task(task_id, session)
    allowed_from = OPEN_STATUSES if final_status == "cancelled" else {RUNNING}
    if task.status not in allowed_from:
        raise ValueError(
            f"Task {task_id} is {task.status!r} and cannot become {final_status!r}"
        )

    task.status = final_status
    task.ended_at = datetime.now(UTC)
    task.result_summary = result_summary
    session.flush()
    return task


def list_tasks(investigation_id: int, session: Session) -> list[Task]:
    """Return an investigation's tasks in creation order. Read-only."""
    return list(
        session.scalars(
            select(Task)
            .where(Task.investigation_id == investigation_id)
            .order_by(Task.id)
        )
    )


def open_task_ids(investigation_id: int, session: Session) -> list[int]:
    """Return the ids of an investigation's pending or running tasks. Read-only."""
    return list(
        session.scalars(
            select(Task.id)
            .where(
                Task.investigation_id == investigation_id,
                Task.status.in_(OPEN_STATUSES),
            )
            .order_by(Task.id)
        )
    )


def _get_task(task_id: int, session: Session) -> Task:
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError(f"Task {task_id} does not exist")
    return task
