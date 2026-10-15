"""Run one piece of operator work inside an owned investigation, flush only.

This module is the thin glue that lets a real operator path own an
``Investigation`` *and* a ``Task`` without re-implementing the lifecycle or task
layers. It adds no verification, probe, or model logic of its own:

* :func:`ensure_running_investigation` returns a running ``Investigation``,
  starting one from a ``program_id`` when only a program is given.
* :func:`run_under_investigation` then creates a task through
  :func:`verification.investigation_tasks.create_task` and runs it either by
  dispatching its kind through :func:`orchestration.task_runner.run_task` (for
  kinds already in ``DISPATCH_TARGETS``) or by calling the operator's ``work``
  callable and completing the task.

Both functions write only with ``session.flush()`` and never commit - the caller
owns the transaction, exactly like every other writer in the project. A raised
``work`` callable is recorded as a ``failed`` task and re-raised; nothing is
swallowed. Neither function touches a ``Hypothesis``, ``Finding``, or
``Verdict``, widens scope, or starts a loop.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from sqlalchemy.orm import Session

from data.models import Investigation, Task
from gateway.dns_pin import URLAuthorizer
from orchestration.task_runner import DISPATCH_TARGETS, run_task
from verification.investigation_lifecycle import RUNNING, start_investigation
from verification.investigation_tasks import complete_task, create_task, start_task
from verification.run_hypothesis_verification import VerificationTestPlan

ERROR_DETAIL_LIMIT = 500


def ensure_running_investigation(
    session: Session,
    *,
    program_id: int | None = None,
    investigation_id: int | None = None,
) -> Investigation:
    """Return a running investigation, starting one from ``program_id`` if needed.

    Exactly one of ``program_id`` or ``investigation_id`` must be given. A missing
    investigation raises :class:`LookupError`; an investigation that is not
    ``running`` raises :class:`ValueError`. Does not commit.
    """
    if investigation_id is not None:
        investigation = session.get(Investigation, investigation_id)
        if investigation is None:
            raise LookupError(f"Investigation {investigation_id} does not exist")
        if investigation.status != RUNNING:
            raise ValueError(
                f"Investigation {investigation_id} is {investigation.status!r}, "
                f"not {RUNNING!r}"
            )
        return investigation
    if program_id is not None:
        return start_investigation(program_id, session)
    raise ValueError("pass either program_id or investigation_id")


def run_under_investigation(
    session: Session,
    *,
    kind: str,
    title: str,
    params: Mapping[str, Any] | None = None,
    work: Callable[[Task], str | None] | None = None,
    program_id: int | None = None,
    investigation_id: int | None = None,
    authorize: URLAuthorizer | None = None,
    allow_private_network: bool = False,
    verification_plan: VerificationTestPlan | None = None,
) -> Task:
    """Create and run one task under a running investigation; flush only.

    Starts the investigation when ``program_id`` is given (or reuses
    ``investigation_id``), creates a ``pending`` task of ``kind`` with ``title``
    and ``params``, and records the outcome:

    * a kind already in ``DISPATCH_TARGETS`` is dispatched through
      :func:`orchestration.task_runner.run_task`, which starts, dispatches, and
      completes (or fails and re-raises) it; ``authorize``,
      ``allow_private_network`` and ``verification_plan`` are passed straight
      through and never stored;
    * any other kind needs a ``work`` callable, which is called with the started
      task and whose return value becomes the task's ``result_summary``.

    A raised ``work`` callable is recorded as a ``failed`` task and re-raised.
    Returns the task. Does not commit.
    """
    dispatchable = kind in DISPATCH_TARGETS
    if dispatchable and work is not None:
        raise ValueError(
            f"{kind!r} tasks are dispatched by run_task; do not pass a work callable"
        )
    if not dispatchable and work is None:
        raise ValueError(f"{kind!r} tasks have no dispatcher; pass a work callable")

    investigation = ensure_running_investigation(
        session, program_id=program_id, investigation_id=investigation_id
    )
    task = create_task(
        investigation.id, session, kind=kind, title=title, params=params
    )

    if dispatchable:
        run_task(
            task.id,
            session,
            authorize=authorize,
            allow_private_network=allow_private_network,
            verification_plan=verification_plan,
        )
        return task

    start_task(task.id, session)
    try:
        summary = work(task)
    except Exception as error:  # noqa: BLE001 - record, then re-raise
        message = f"{type(error).__name__}: {error}"[:ERROR_DETAIL_LIMIT]
        complete_task(task.id, session, final_status="failed", result_summary=message)
        raise
    result_summary = None if summary is None else str(summary)
    complete_task(
        task.id, session, final_status="completed", result_summary=result_summary
    )
    return task
