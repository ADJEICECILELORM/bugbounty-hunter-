"""Operator-tracked tasks inside a running investigation.

Session functions only: ``create_task``, ``start_task``, ``complete_task`` and
``append_task_event`` write; ``list_tasks``, ``open_task_ids`` and
``unmet_dependencies`` read. A ``Task`` is a record of work an operator has
decided to do. The only thing that ever executes one is
:func:`orchestration.task_runner.run_task`, and only when an operator calls it;
nothing schedules, loops, or picks a task up on its own.

The writers use ``session.add()``/``session.flush()`` and never commit - the
caller owns the transaction. None of them touches a ``Hypothesis``, ``Finding``,
``Verdict``, or ``Observation`` (``create_task`` *reads* an ``Asset`` or
``Hypothesis`` to check a task's target belongs to its investigation), and the
module imports nothing from the gateway and makes no request.

Transitions, each recorded as an append-only ``TaskEvent``::

    pending --start_task--> running --complete_task--> completed | failed | cancelled
    pending --complete_task(final_status="cancelled")--> cancelled

``completed`` and ``failed`` describe work that was attempted, so they require a
running task; a pending task can only be ``cancelled``. Terminal tasks never
change again. While any task is pending or running,
:func:`verification.investigation_lifecycle.close_investigation` refuses to close
its investigation, so a closed investigation never has an open task.

``depends_on`` may only name tasks that already exist in the same investigation,
and a task id is assigned only when its row is created (flushed), so a
dependency can only point at an earlier id - a forward reference, and therefore
a cycle, is impossible. That acyclicity is an emergent property of autoincrement
ids plus the ``_checked_depends_on`` existence check, not a separate
cycle-detection pass.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from data.models import Asset, Hypothesis, Investigation, Task, TaskEvent

# Mirrors ``investigation_lifecycle.RUNNING``; kept local so the lifecycle module
# can import from this one without a cycle (a test asserts the two agree).
INVESTIGATION_RUNNING = "running"

# Default caps for one investigation's work budget. ``Investigation`` carries a
# nullable ``max_tasks`` / ``max_llm_calls`` override; a NULL column falls back to
# these defaults, so the already-populated database keeps opening without a
# back-fill. Both are enforced here in ``create_task`` - the only writer of tasks.
MAX_TASKS_PER_INVESTIGATION = 50
MAX_LLM_CALLS_PER_INVESTIGATION = 10

# A ``hypothesis_generation`` task is the only production path to the model, so
# counting those tasks is a deterministic record of LLM usage with no new column.
LLM_TASK_KIND = "hypothesis_generation"

TASK_KINDS = frozenset(
    {
        "recon",
        "inventory",
        "hypothesis_generation",
        "hypothesis_review",
        "verification",
        "report",
    }
)

# The exact target parameters each kind takes; a kind missing here takes none.
# Only ids and a base URL - never a header, token, credential, or lab opt-in. A
# ``verification`` task must name a hypothesis in its investigation; no other
# kind may carry a ``hypothesis_id``.
TASK_PARAMS: Mapping[str, frozenset[str]] = {
    "inventory": frozenset({"asset_id", "base_url"}),
    "hypothesis_generation": frozenset({"asset_id"}),
    "verification": frozenset({"hypothesis_id"}),
}


class BudgetExhausted(ValueError):
    """Raised when work would exceed an investigation's task or LLM-call budget."""


PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
OPEN_STATUSES = frozenset({PENDING, RUNNING})
FINAL_STATUSES = frozenset({COMPLETED, "cancelled", "failed"})

EVENT_TYPES = frozenset(
    {
        "created",
        "started",
        *FINAL_STATUSES,
        "dispatched",
        "dispatch_failed",
        "crash_recovery",
        "retry_created",
    }
)


def create_task(
    investigation_id: int,
    session: Session,
    *,
    kind: str,
    title: str,
    params: Mapping[str, Any] | None = None,
    depends_on: list[int] | None = None,
) -> Task:
    """Add a ``pending`` task to a running investigation and flush it.

    Raises :class:`ValueError` for a ``kind`` outside ``TASK_KINDS``, a blank
    ``title``, ``params`` that are not exactly the kind's ``TASK_PARAMS`` (a
    ``verification`` task requires a positive ``hypothesis_id`` on a hypothesis in
    this investigation; ``hypothesis_id`` is forbidden on other kinds) or name a
    target outside this investigation, a ``depends_on`` entry that is not an
    existing task of this investigation, an investigation that is not running,
    or one whose task or LLM-call budget is exhausted (:class:`BudgetExhausted`,
    driven by ``Investigation.max_tasks`` / ``Investigation.max_llm_calls`` with
    the module defaults). :class:`LookupError` means a missing investigation.
    Does not commit.
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

    existing = session.scalar(
        select(func.count(Task.id)).where(Task.investigation_id == investigation_id)
    )
    max_tasks = (
        investigation.max_tasks
        if investigation.max_tasks is not None
        else MAX_TASKS_PER_INVESTIGATION
    )
    if existing >= max_tasks:
        raise BudgetExhausted(
            f"Investigation {investigation_id} task budget exhausted: it already "
            f"holds {existing} of {max_tasks} tasks"
        )

    if kind == LLM_TASK_KIND:
        llm_tasks = session.scalar(
            select(func.count(Task.id)).where(
                Task.investigation_id == investigation_id,
                Task.kind == LLM_TASK_KIND,
            )
        )
        max_llm_calls = (
            investigation.max_llm_calls
            if investigation.max_llm_calls is not None
            else MAX_LLM_CALLS_PER_INVESTIGATION
        )
        if llm_tasks >= max_llm_calls:
            raise BudgetExhausted(
                f"Investigation {investigation_id} LLM call budget exhausted: "
                f"{llm_tasks} of {max_llm_calls} hypothesis_generation tasks "
                "already recorded"
            )

    checked_params = _checked_params(kind, dict(params or {}), investigation_id, session)
    checked_depends_on = _checked_depends_on(list(depends_on or []), investigation_id, session)

    task = Task(
        investigation_id=investigation_id,
        kind=kind,
        title=title,
        status=PENDING,
        params=checked_params,
        depends_on=checked_depends_on,
    )
    session.add(task)
    session.flush()
    _append(task, "created", {"kind": kind, "depends_on": checked_depends_on}, session)
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
    _append(task, "started", {}, session)
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
    _append(task, final_status, {"result_summary": result_summary}, session)
    return task


def append_task_event(
    task_id: int,
    session: Session,
    *,
    event_type: str,
    detail: Mapping[str, Any] | None = None,
) -> TaskEvent:
    """Insert one ``TaskEvent`` for a task. Insert-only; there is no update path.

    ``event_type`` must be one of ``EVENT_TYPES``. Does not commit.
    """
    if event_type not in EVENT_TYPES:
        raise ValueError(
            f"event_type must be one of {sorted(EVENT_TYPES)!r}, got {event_type!r}"
        )
    return _append(_get_task(task_id, session), event_type, dict(detail or {}), session)


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


def unmet_dependencies(task: Task, session: Session) -> list[int]:
    """Return the ids in ``task.depends_on`` that are not ``completed``. Read-only."""
    if not task.depends_on:
        return []
    completed = set(
        session.scalars(
            select(Task.id).where(
                Task.id.in_(task.depends_on), Task.status == COMPLETED
            )
        )
    )
    return [task_id for task_id in task.depends_on if task_id not in completed]


def _checked_params(
    kind: str, params: dict[str, Any], investigation_id: int, session: Session
) -> dict[str, Any]:
    expected = TASK_PARAMS.get(kind, frozenset())
    if set(params) != expected:
        raise ValueError(
            f"{kind!r} tasks take params {sorted(expected)!r}, got {sorted(params)!r}"
        )
    for key in expected & {"asset_id", "hypothesis_id"}:
        if type(params[key]) is not int:
            raise ValueError(f"{key} must be an int")

    if "asset_id" in params:
        asset = session.get(Asset, params["asset_id"])
        if asset is None or asset.investigation_id != investigation_id:
            raise ValueError(
                f"Asset {params['asset_id']} is not part of "
                f"investigation {investigation_id}"
            )
        if "base_url" in params:
            base_url = params["base_url"]
            if not isinstance(base_url, str) or (
                (urlsplit(base_url).hostname or "") != asset.hostname.lower()
            ):
                raise ValueError(
                    f"base_url must be a URL on the asset's host {asset.hostname!r}"
                )

    if "hypothesis_id" in params:
        if params["hypothesis_id"] <= 0:
            raise ValueError("hypothesis_id must be a positive int")
        hypothesis = session.get(Hypothesis, params["hypothesis_id"])
        if hypothesis is None or hypothesis.asset.investigation_id != investigation_id:
            raise ValueError(
                f"Hypothesis {params['hypothesis_id']} is not part of "
                f"investigation {investigation_id}"
            )
    return params


def _checked_depends_on(
    depends_on: list[int], investigation_id: int, session: Session
) -> list[int]:
    """Validate and normalize a task's dependency ids.

    Every entry must be an int naming a task that already exists in this
    investigation. Because a task id is assigned only when its row is created
    (flushed), a dependency can only name an earlier task, so the dependency
    graph is acyclic by construction - this is the *mechanism*, not a separate
    cycle-detection pass.
    """
    if any(type(task_id) is not int for task_id in depends_on):
        raise ValueError("depends_on must be a list of task ids")
    wanted = sorted(set(depends_on))
    found = set(
        session.scalars(
            select(Task.id).where(
                Task.id.in_(wanted), Task.investigation_id == investigation_id
            )
        )
    )
    missing = [task_id for task_id in wanted if task_id not in found]
    if missing:
        raise ValueError(
            f"depends_on names tasks {missing!r} that are not part of "
            f"investigation {investigation_id}"
        )
    return wanted


def _append(
    task: Task, event_type: str, detail: dict[str, Any], session: Session
) -> TaskEvent:
    task_event = TaskEvent(event_type=event_type, detail=detail)
    task.events.append(task_event)
    session.flush()
    return task_event


def _get_task(task_id: int, session: Session) -> Task:
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError(f"Task {task_id} does not exist")
    return task
