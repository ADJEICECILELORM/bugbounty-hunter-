# V4 Checkpoint — Orchestration Foundation (Tasks A–E)

Status: **complete, uncommitted, not pushed.** Worktree is dirty on purpose; do not
commit until this file exists (it now does), and do not push.

- Baseline before changes: **402 passed** at `0a93250` (worktree clean).
- Baseline after changes: **433 passed** (see "Suite counts" below).

## What this slice did

- **Task A — append-only `TaskEvent`.** Added the `TaskEvent` model
  (`id`, `task_id`, `event_type`, `detail` JSON, `created_at`) plus a
  `before_update`/`before_delete` ORM listener that raises
  `TaskEventIsAppendOnly`. `Task` gained a `depends_on` JSON list, a `params` JSON
  dict, and an `events` relationship. `create_task`/`start_task`/`complete_task`
  now record `created`/`started`/terminal events, and `append_task_event` is the
  only insert-only writer.
- **Task B — `run_task` dispatcher.** `orchestration/task_runner.py` runs exactly
  one named task by dispatching its `kind` to an existing function; it adds no new
  network or verification logic, refuses before writing on any unmet precondition,
  records `dispatch_failed` + `failed` on exceptions (re-raising them), and uses a
  savepoint so a failure leaves no partial work. Flush only, never commits, never
  writes `Hypothesis.status`.
- **Task C — `plan_next_tasks` proposer.** `orchestration/supervisor.py` returns,
  deterministically and without any LLM, the pending tasks whose `depends_on` are
  all completed. Read-only; proposes only.
- **Task D — operator script.** `scripts/run_investigation_step.py` proposes via
  `plan_next_tasks`; without `--yes` it prints and exits 0, with `--yes` it runs
  each proposed task exactly once and stops (no loop).
- **Task E — this checkpoint.**

## Files created

| file | lines |
|---|---|
| `orchestration/__init__.py` | 6 |
| `orchestration/task_runner.py` | 179 |
| `orchestration/supervisor.py` | 55 |
| `scripts/run_investigation_step.py` | 125 |
| `tests/test_task_events.py` | 123 |
| `tests/test_task_runner.py` | 359 |
| `tests/test_supervisor.py` | 147 |

## Files modified

| file | change |
|---|---|
| `data/models.py` | +37 lines: `Task.depends_on`, `Task.params`, `Task.events`, `TaskEvent`, `TaskEventIsAppendOnly`, append-only listeners |
| `verification/investigation_tasks.py` | +190 lines: params/depends_on validation, `append_task_event`, `unmet_dependencies`, `MAX_TASKS_PER_INVESTIGATION`, events on transitions |
| `tests/test_investigation_tasks.py` | +34 lines: params-aware kind test, updated import guard, kind fixes |

(`git diff --stat`: 3 files changed, 240 insertions(+), 21 deletions(-).)

## Design decisions (justifications)

- **`depends_on` is a JSON list of task ids on `Task`, not an association table.**
  A dependency may only name tasks that already exist in the same investigation
  (enforced in `create_task`), so every edge points at an earlier task and the
  graph is acyclic by construction. A plain JSON list keeps `Task` self-contained,
  avoids a join table, and matches how `params` is already stored.
- **The task cap is a module constant, not a column.** `MAX_TASKS_PER_INVESTIGATION
  = 50` lives in `verification.investigation_tasks.py` and is enforced in
  `create_task` (refusing task #51) and defensively sliced in `plan_next_tasks`.
  Keeping it out of `Investigation`/`Program` leaves the existing
  `investigations`/`programs` tables unchanged, so older databases keep opening.
- **Operator inputs are call arguments, never stored.** `run_task` takes
  `authorize`, `allow_private_network`, and `verification_plan` as keyword
  arguments for this call only. Credentials, lab opt-in, and plans never reach a
  task row; `params` holds only ids and a base URL.
- **Supervisor proposes; the runner executes one task; the script runs one cycle.**
  Nothing schedules, loops, or re-dispatches on its own.

## Suite counts

- Before: **402 passed** (`venv/bin/python -m pytest -q` at `0a93250`).
- After: **433 passed** (`venv/bin/python -m pytest -q`).

New tests: `test_task_events.py` (7), `test_task_runner.py` (14),
`test_supervisor.py` (10) = **+31**.

## Invariant grep evidence

1. **`Hypothesis.status` is written only by `finding_promotion.py`.**
   `grep -rn --include='*.py' -E 'hypothesis\.status\s*=' . | grep -v /tests/`
   ```
   ./verification/finding_promotion.py:190:    hypothesis.status = VERIFIED_STATUS
   ```
2. **No commit in `orchestration/`.** `grep -rn '\.commit(' orchestration/`
   → no matches (exit 1). The runner flushes and uses `session.begin_nested()`.
3. **No new network paths.** `grep -rn -E 'import requests|from requests|urllib\.request|http\.client|socket' orchestration/ scripts/run_investigation_step.py`
   → no matches. Authorization stays inside the existing gateway functions.
4. **No autonomous scheduling.** `grep -rn -E 'while True|sched\.|schedule|threading|asyncio|Timer' orchestration/`
   → no matches.
5. **No direct status writes in `orchestration/`.** `tests/test_task_runner.py`
   asserts `orchestration/` contains no `task.status =`/`investigation.status =`/
   `hypothesis.status =` assignments and no `finding_promotion` or
   `from gateway.lab_mode` import.

## Full source

### orchestration/task_runner.py

```python
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
```

### orchestration/supervisor.py

```python
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
    the same state always yields the same list. Returns at most
    ``MAX_TASKS_PER_INVESTIGATION`` rows; ``create_task`` already refuses to add
    more than that, so the slice is a defensive bound rather than new policy.

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
    return ready[:MAX_TASKS_PER_INVESTIGATION]
```
### scripts/run_investigation_step.py

```python
#!/usr/bin/env python3
"""Operator-only, human-gated, one-cycle task executor.

Proposes ready tasks for one investigation with
:func:`orchestration.supervisor.plan_next_tasks`, prints them, and - only with
an explicit ``--yes`` - runs each one exactly once through
:func:`orchestration.task_runner.run_task`, then stops. There is no loop beyond
the single pass over the already-proposed list, no scheduler, and no automatic
re-dispatch.

This script is manual on purpose: nothing imports it, the automated test suite
never executes it, and no worker calls it. It is the single place an operator
turns a proposal into work, and it commits only because it is the transaction
owner (the library functions it calls only flush).

``authorize`` is rebuilt here from the program's stored scope via
:mod:`gateway.scope_policy`, so the script grants itself nothing: it reuses the
same gate every probe already goes through. The lab opt-in is a ``--lab`` flag
on this invocation only, never a stored value. Verification tasks need a plan
the operator would have to supply; without one, ``run_task`` refuses and the
task is left pending, which this script reports rather than fabricating.

Usage:
    venv/bin/python scripts/run_investigation_step.py 1
    venv/bin/python scripts/run_investigation_step.py 1 --yes
    venv/bin/python scripts/run_investigation_step.py 1 --yes --lab
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.db import init_db  # noqa: E402
from data.models import Investigation  # noqa: E402
from gateway.scope_policy import ScopePolicy  # noqa: E402
from orchestration.supervisor import plan_next_tasks  # noqa: E402
from orchestration.task_runner import run_task  # noqa: E402

DB_NAME = "lab_evidence_v3.db"


def _build_authorize(investigation: Investigation) -> Callable[[str], bool]:
    policy = ScopePolicy(investigation.program.authorized_scope, investigation.program.excluded_scope)

    def authorize(url: str) -> bool:
        hostname = urlsplit(url).hostname or ""
        return policy.is_authorized(hostname)

    return authorize


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Propose, and with --yes run once, one investigation's ready tasks."
    )
    parser.add_argument("investigation_id", type=int, help="id of the investigation to step")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="actually run each proposed task once (default: propose only, exit 0)",
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        help="allow private-network (lab) targets for this run only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    db_path = (REPO_ROOT / DB_NAME).resolve()
    engine = init_db(f"sqlite+pysqlite:///{db_path.as_posix()}")

    with Session(engine) as session:
        investigation = session.get(Investigation, args.investigation_id)
        if investigation is None:
            raise SystemExit(
                f"No Investigation #{args.investigation_id} exists in {DB_NAME}."
            )

        proposed = plan_next_tasks(args.investigation_id, session)
        print(
            f"{len(proposed)} task(s) ready for investigation "
            f"{args.investigation_id}:"
        )
        for task in proposed:
            print(f"  #{task.id} {task.kind}: {task.title}")

        if not args.yes:
            print("Dry run: nothing executed. Re-run with --yes to run these tasks once.")
            return 0

        authorize = _build_authorize(investigation)
        for task in proposed:
            try:
                run_task(
                    task.id,
                    session,
                    authorize=authorize,
                    allow_private_network=args.lab,
                )
                print(f"  #{task.id} {task.kind}: completed")
            except Exception as error:  # noqa: BLE001 - report, then continue once
                print(f"  #{task.id} {task.kind}: {type(error).__name__}: {error}")

        session.commit()
        print("Done (one pass; no re-dispatch).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Explicit statement

**Did not implement auto-scheduling loops, cost-weighted prioritization, or
dynamic worker pools.** The planner only proposes; the runner executes exactly
one explicitly named task; the script stops after a single pass over the proposed
list. There is no scheduler, no re-dispatch, no background worker, and no
autonomous grant of scope.



