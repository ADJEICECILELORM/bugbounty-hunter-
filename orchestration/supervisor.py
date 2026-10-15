"""Deterministic, operator-invoked task proposals. Proposes only, never executes.

``plan_next_tasks`` answers one question: *which of this investigation's pending
tasks can run right now?* It is the planning half of the V4 foundation and the
deliberate opposite of autonomy:

* **Deterministic.** No LLM, no randomness, no wall-clock dependence beyond the
  stored ``Task.id`` order.
* **Proposes only.** It reads tasks and returns them; it never starts, completes,
  dispatches, or commits anything, and it imports nothing that could.
* **Dependency-aware.** A task is ready only when it is ``pending`` and every id
  in its ``depends_on`` list is a completed task of the same investigation.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Investigation, Task
from verification.investigation_tasks import (
    MAX_TASKS_PER_INVESTIGATION,
    PENDING,
    unmet_dependencies,
)


def plan_next_tasks(investigation_id: int, session: Session) -> list[Task]:
    """Return the investigation's ready-to-run pending tasks in creation order.

    A task is "ready" when it is pending and every id in ``depends_on`` names a
    completed task of this investigation. Results are ordered by ``Task.id``, so
    the same state always yields the same list. Returns at most the
    investigation's task budget (``Investigation.max_tasks``, or
    ``MAX_TASKS_PER_INVESTIGATION`` when unset); ``create_task`` already refuses
    to add more than that, so the slice is a defensive bound rather than new
    policy.

    Raises :class:`LookupError` for a missing investigation. Read-only: nothing
    is executed, written, or committed.
    """
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")

    pending = list(
        session.scalars(
            select(Task)
            .where(
                Task.investigation_id == investigation_id,
                Task.status == PENDING,
            )
            .order_by(Task.id)
        )
    )
    ready = [task for task in pending if not unmet_dependencies(task, session)]
    max_tasks = (
        investigation.max_tasks
        if investigation.max_tasks is not None
        else MAX_TASKS_PER_INVESTIGATION
    )
    return ready[:max_tasks]
