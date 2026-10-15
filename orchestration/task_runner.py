"""Run exactly one operator-named task by dispatching on its kind.

``run_task`` is the only place a ``Task`` turns into work, and it adds no work of
its own: each dispatchable kind maps to one existing, already-tested function,
called with the task's stored target ids plus the inputs the operator passes in.

* ``inventory`` -> :func:`verification.endpoint_inventory_collector.collect_seed_inventory`
* ``hypothesis_generation`` -> :func:`intelligence.hypothesis_generation.generate_hypotheses`
* ``verification`` -> :func:`verification.run_hypothesis_verification.run_hypothesis_verification`

The rules this module does not bend:

* **No scope of its own.** ``authorize`` is a required operator input for every
  kind that can make a request, and it is handed unchanged to the existing
  function, which pins through the gateway. Nothing here builds, widens, or
  stores an authorizer.
* **The lab opt-in is never stored.** ``allow_private_network`` comes only from
  the caller, on every call, and is passed straight through; the existing
  functions decide which transport that selects.
* **No stored credentials.** A verification plan (which may carry request
  headers) is an operator input for this call only and never reaches a row.
* **Refuse before starting.** A task that is not pending, has an unmet
  dependency, has no dispatcher, or lacks a required input raises
  :class:`TaskNotRunnable` and is left exactly as it was.
* **A failure leaves no partial work.** The dispatch runs inside a savepoint
  (``begin_nested``, not a commit): if it raises, everything it wrote is rolled
  back, the task is marked ``failed`` with a ``dispatch_failed`` event carrying
  the error, and the exception is re-raised.
* **Never a status outside the task.** ``Hypothesis.status`` stays the promotion
  gate's alone, and task status changes only through ``start_task`` and
  ``complete_task``. Flush only; the caller owns the transaction.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from data.models import Task
from gateway.dns_pin import URLAuthorizer
from intelligence.hypothesis_generation import generate_hypotheses
from verification.endpoint_inventory_collector import collect_seed_inventory
from verification.investigation_tasks import (
    PENDING,
    append_task_event,
    complete_task,
    start_task,
    unmet_dependencies,
)
from verification.run_hypothesis_verification import (
    VerificationTestPlan,
    run_hypothesis_verification,
)

DISPATCH_TARGETS = {
    "inventory": "collect_seed_inventory",
    "hypothesis_generation": "generate_hypotheses",
    "verification": "run_hypothesis_verification",
}
NEEDS_AUTHORIZE = frozenset({"inventory", "verification"})
ERROR_DETAIL_LIMIT = 500


class TaskNotRunnable(ValueError):
    """Raised, with nothing changed, when a task cannot be dispatched now."""


def run_task(
    task_id: int,
    session: Session,
    *,
    authorize: URLAuthorizer | None = None,
    allow_private_network: bool = False,
    verification_plan: VerificationTestPlan | None = None,
) -> None:
    """Dispatch one pending task to its existing function and record the outcome.

    Raises :class:`LookupError` for a missing task and :class:`TaskNotRunnable`
    when it cannot run now (both before anything is written). Anything the
    dispatched function raises is recorded as a ``failed`` task and re-raised.
    Does not commit.
    """
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError(f"Task {task_id} does not exist")
    _refuse_unless_runnable(task, session, authorize, verification_plan)

    start_task(task.id, session)
    append_task_event(
        task.id,
        session,
        event_type="dispatched",
        detail={
            "target": DISPATCH_TARGETS[task.kind],
            "allow_private_network": allow_private_network,
        },
    )

    try:
        with session.begin_nested():
            summary = _dispatch(
                task, session, authorize, allow_private_network, verification_plan
            )
    except Exception as error:  # noqa: BLE001 - record anything the target raised
        message = f"{type(error).__name__}: {error}"[:ERROR_DETAIL_LIMIT]
        append_task_event(
            task.id,
            session,
            event_type="dispatch_failed",
            detail={"error_type": type(error).__name__, "error": message},
        )
        complete_task(task.id, session, final_status="failed", result_summary=message)
        raise

    complete_task(task.id, session, final_status="completed", result_summary=summary)


def _refuse_unless_runnable(
    task: Task,
    session: Session,
    authorize: URLAuthorizer | None,
    verification_plan: VerificationTestPlan | None,
) -> None:
    if task.status != PENDING:
        raise TaskNotRunnable(f"Task {task.id} is {task.status!r}, not {PENDING!r}")
    unmet = unmet_dependencies(task, session)
    if unmet:
        raise TaskNotRunnable(f"Task {task.id} depends on unfinished tasks {unmet!r}")
    if task.kind not in DISPATCH_TARGETS:
        raise TaskNotRunnable(
            f"Task {task.id} is a {task.kind!r} task, which has no dispatcher; "
            "the operator does it and records the outcome with complete_task"
        )
    if task.kind in NEEDS_AUTHORIZE and authorize is None:
        raise TaskNotRunnable(f"Task {task.id} needs an operator-supplied authorize")
    if task.kind == "verification" and verification_plan is None:
        raise TaskNotRunnable(
            f"Task {task.id} needs an operator-supplied verification_plan"
        )


def _dispatch(
    task: Task,
    session: Session,
    authorize: URLAuthorizer | None,
    allow_private_network: bool,
    verification_plan: VerificationTestPlan | None,
) -> str:
    params = task.params

    if task.kind == "inventory":
        observations = collect_seed_inventory(
            params["base_url"],
            authorize,
            session=session,
            asset_id=params["asset_id"],
            allow_private_network=allow_private_network,
        )
        ids = [observation.id for observation in observations]
        return f"stored {len(ids)} endpoint_inventory observations: {ids}"

    if task.kind == "hypothesis_generation":
        hypotheses = generate_hypotheses(params["asset_id"], session)
        ids = [hypothesis.id for hypothesis in hypotheses]
        return f"added {len(ids)} unverified hypotheses: {ids}"

    result = run_hypothesis_verification(
        params["hypothesis_id"],
        verification_plan,
        allow_private_network=allow_private_network,
        authorize=authorize,
        session=session,
    )
    ids = [outcome.verdict.id for outcome in result.outcomes]
    return (
        f"stored {len(ids)} verdicts: {ids} "
        f"({len(result.control_outcomes)} control, "
        f"{len(result.primary_outcomes)} claim)"
    )

