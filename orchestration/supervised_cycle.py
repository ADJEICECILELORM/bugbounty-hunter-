"""One budget-aware, human-triggered investigation cycle. Propose, then optionally run.

``run_supervised_cycle`` is the V6 first-slice loop: a single, explicit operator
invocation that (1) *always* proposes the investigation's ready tasks through
:func:`orchestration.supervisor.plan_next_tasks` and (2) only when ``execute`` is
true, runs each proposed task once through
:func:`orchestration.task_runner.run_task`.

There is no autonomy and no ``while True``: one call is one pass over the
already-proposed list, and only the operator (or the script that calls this
module) decides whether to plan again. The library function flushes only and
never commits - the operator script owns the transaction.

Policy, stated rather than assumed:

* **Plan always, even for a dry run.** ``execute=False`` returns exactly the
  proposals an execute would have seen, and writes nothing.
* **Execute is gated.** ``execute=True`` refuses an investigation that is not
  ``running`` (:class:`ValueError`) and refuses to run while any task is stuck
  (:func:`verification.task_recovery.find_stuck_tasks`, default threshold
  ``DEFAULT_STUCK_THRESHOLD_SECONDS = 3600.0``). A stuck cycle is reported as a
  ``skipped`` result telling the operator to run
  ``scripts/recover_investigation.py`` first.
* **Budgets are never bypassed.** ``plan_next_tasks`` already slices to
  ``Investigation.max_tasks`` and ``create_task`` already enforces both the task
  and LLM-call caps, so a cycle can propose and run only what the budget allows.
  This module does not re-count or re-create tasks.
* **Stop on first failure.** Tasks run in proposal order; the first exception
  raised by ``run_task`` (including a ``TaskNotRunnable`` refusal for a
  non-dispatchable kind or a missing operator input) is recorded in the report
  and the cycle stops. This is deliberate: a failed task is often a dependency of
  the next one, so running on would produce cascading failures that are harder to
  reason about.
* **Never a hypothesis.** ``Hypothesis.status`` stays the promotion gate's
  alone; this module neither reads nor writes one, and task status changes only
  through ``run_task``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from data.models import Investigation, Task
from gateway.dns_pin import URLAuthorizer
from orchestration.supervisor import plan_next_tasks
from orchestration.task_runner import run_task
from verification.investigation_lifecycle import RUNNING
from verification.run_hypothesis_verification import VerificationTestPlan
from verification.task_recovery import find_stuck_tasks

DEFAULT_STUCK_THRESHOLD_SECONDS = 3600.0
ERROR_DETAIL_LIMIT = 500


@dataclass(frozen=True)
class ProposedTask:
    """One ready task a cycle proposes: id, kind, and title only."""

    task_id: int
    kind: str
    title: str


@dataclass(frozen=True)
class TaskResult:
    """The outcome of running one proposed task."""

    task_id: int
    kind: str
    title: str
    ok: bool
    status: str
    error_type: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Skipped:
    """Why a cycle did not execute (``stuck``, ``budget``, or ``empty``)."""

    reason: str
    detail: str


@dataclass
class CycleReport:
    """What one supervised cycle proposed, ran, and skipped."""

    investigation_id: int
    proposed: list[ProposedTask] = field(default_factory=list)
    executed: list[TaskResult] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


def run_supervised_cycle(
    investigation_id: int,
    session: Session,
    *,
    execute: bool,
    threshold_seconds: float = DEFAULT_STUCK_THRESHOLD_SECONDS,
    authorize: URLAuthorizer | None = None,
    allow_private_network: bool = False,
    verification_plan: VerificationTestPlan | None = None,
) -> CycleReport:
    """Propose one investigation's ready tasks, and with ``execute`` run them once.

    Planning is always read-only and always happens first. ``execute=False``
    returns the proposals and writes nothing. ``execute=True``:

    * raises :class:`ValueError` when the investigation is not ``running``;
    * returns without running (recording a ``stuck`` skip) while any task has
      overrun ``threshold_seconds``, telling the operator to run
      ``scripts/recover_investigation.py`` first;
    * otherwise runs each proposed task once, in order, through ``run_task`` and
      **stops on the first failure**, recording every attempt.

    ``authorize``, ``allow_private_network`` and ``verification_plan`` are passed
    straight through to ``run_task`` and never stored; a task that needs one and
    does not get it is refused by ``run_task`` and reported as a failed result,
    exactly like any other refusal. Raises :class:`LookupError` for a missing
    investigation. Flushes only; never commits, and never writes
    ``Hypothesis.status``.
    """
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")

    proposed = [
        ProposedTask(task_id=task.id, kind=task.kind, title=task.title)
        for task in plan_next_tasks(investigation_id, session)
    ]

    if not execute:
        return CycleReport(investigation_id=investigation_id, proposed=proposed)

    if investigation.status != RUNNING:
        raise ValueError(
            f"Investigation {investigation_id} is {investigation.status!r}, "
            f"not {RUNNING!r}"
        )

    stuck = find_stuck_tasks(
        investigation_id, session, running_longer_than_seconds=threshold_seconds
    )
    if stuck:
        stuck_ids = [task.id for task in stuck]
        return CycleReport(
            investigation_id=investigation_id,
            proposed=proposed,
            skipped=[
                Skipped(
                    reason="stuck",
                    detail=(
                        f"{len(stuck_ids)} running task(s) overran "
                        f"{threshold_seconds:g}s: {stuck_ids!r}; run "
                        "scripts/recover_investigation.py first"
                    ),
                )
            ],
        )

    executed: list[TaskResult] = []
    for task in proposed:
        result = _run_one(
            task,
            session,
            authorize=authorize,
            allow_private_network=allow_private_network,
            verification_plan=verification_plan,
        )
        executed.append(result)
        if not result.ok:
            break

    skipped: list[Skipped] = []
    if not proposed:
        skipped.append(
            Skipped(reason="empty", detail="no ready tasks were proposed")
        )

    return CycleReport(
        investigation_id=investigation_id,
        proposed=proposed,
        executed=executed,
        skipped=skipped,
    )


def _run_one(
    proposed: ProposedTask,
    session: Session,
    *,
    authorize: URLAuthorizer | None,
    allow_private_network: bool,
    verification_plan: VerificationTestPlan | None,
) -> TaskResult:
    """Run one proposed task via ``run_task`` and record its outcome. Flush only."""
    task = session.get(Task, proposed.task_id)
    if task is None:
        return TaskResult(
            task_id=proposed.task_id,
            kind=proposed.kind,
            title=proposed.title,
            ok=False,
            status="missing",
            error_type="LookupError",
            error=f"Task {proposed.task_id} does not exist",
        )

    try:
        run_task(
            task.id,
            session,
            authorize=authorize,
            allow_private_network=allow_private_network,
            verification_plan=verification_plan,
        )
    except Exception as error:  # noqa: BLE001 - record, then stop on first failure
        message = f"{type(error).__name__}: {error}"[:ERROR_DETAIL_LIMIT]
        return TaskResult(
            task_id=task.id,
            kind=task.kind,
            title=task.title,
            ok=False,
            status=task.status,
            error_type=type(error).__name__,
            error=message,
        )

    return TaskResult(
        task_id=task.id,
        kind=task.kind,
        title=task.title,
        ok=True,
        status=task.status,
    )
