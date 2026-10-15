# V5 Checkpoint — Human-Initiated Task Recovery

Status: **complete, uncommitted, not pushed.** Stop here for review.

- Baseline before changes: **433 passed** at `7f0ea8c` (worktree clean).
- Baseline after changes: **451 passed** (18 new in `tests/test_task_recovery.py`).

## Task 5.1 — Dependency acyclicity honesty

Path taken: **tightened the docstring** (no code check added). There is no real
cycle path to detect: `create_task` is the only place `depends_on` is written,
and it requires every dependency id to already exist in the same investigation,
while a task id is assigned only on `session.flush()` at create time. So a
dependency can only point at an already-flushed (earlier) id, and a forward
reference — and therefore a cycle — is impossible. This is an emergent property
of autoincrement ids plus the `_checked_depends_on` existence check, not a
separate cycle-detection pass.

Changed in `verification/investigation_tasks.py`:

- The module docstring now states the real mechanism instead of the overstated
  "acyclic by construction".
- `_checked_depends_on` gained a docstring spelling out the same mechanism.
- `EVENT_TYPES` gained `crash_recovery` and `retry_created` (the single source
  the `append_task_event` validator reads, so recovery reuses the existing audit
  path rather than inventing one).

## What this slice did

- **Task 5.2 — `find_stuck_tasks`.** `verification/task_recovery.py` returns the
  investigation's `running` tasks whose `started_at` is older than a threshold.
  Read-only; `LookupError` for a missing investigation; `ValueError` for a
  negative threshold; no side effects.
- **Task 5.3 — human recovery actions** (same module), reusing the task layer:
  - `mark_task_failed_after_crash` ends a running task as `failed` through the
    existing `complete_task` path and appends a `crash_recovery` event.
  - `create_retry_task` copies a failed/cancelled task into a new pending task
    through the existing `create_task` path, refuses pending/running/completed
    and a second retry, and links the original via a `retry_created` event.
    Flush only; it never runs the retry.
- **Task 5.4 — operator script.** `scripts/recover_investigation.py`: default
  lists stuck tasks (dry-run, no writes); `--mark-failed <task_id>` and
  `--retry <task_id>` are mutually exclusive write actions that commit (the
  script is the transaction owner). It never starts the retry.

## Files created

| file | lines |
|---|---|
| `verification/task_recovery.py` | 137 |
| `scripts/recover_investigation.py` | 142 |
| `tests/test_task_recovery.py` | 347 |

## Files modified

| file | change |
|---|---|
| `verification/investigation_tasks.py` | +19 lines: acyclicity docstrings, `crash_recovery`/`retry_created` event types |

## Design decision (retry link)

`create_retry_task` records the original link as a `retry_created` `TaskEvent`
on the original task (detail `{"retry_task_id", "retry_of"}`) rather than a
nullable `retry_of` column, because `data.db.init_db` is `Base.metadata.create_all`
only — it never alters an existing table, so a new column would break the
already-populated `lab_evidence_v3.db`. The event keeps the append-only audit
path and the "already retried" check (a query on `TaskEvent` where
`task_id == original.id and event_type == "retry_created"`) without a migration.

## Grep evidence for invariants

All run from the repo root; "(no matches)" means the command exited with no
output.

- `grep -n '\.commit(' verification/task_recovery.py` → no matches
  (the library only flushes; the operator script owns the transaction).
- `grep -nE 'task\.(status|started_at|ended_at)\s*=' verification/task_recovery.py`
  → no matches (status/timestamps are written only by the task layer).
- `grep -nE 'Hypothesis\(|hypothesis\.status|Finding\(|Verdict\(|Observation\(|import requests|llm_client|probe_endpoint|probe_lab_target' verification/task_recovery.py`
  → no matches (never touches hypotheses/findings/verdicts/observations, never
  reaches the network or a transport).
- `grep -n 'run_task\|plan_next_tasks\|from orchestration\|from gateway' verification/task_recovery.py`
  → no matches (recovery never dispatches, plans, or grants scope).
- `grep -nE 'import sched|sched\.|threading|asyncio|Timer|while True' verification/task_recovery.py scripts/recover_investigation.py`
  → no matches (no scheduler, daemon, or loop). An earlier loose `sched` grep
  matched the word "schedules" in a docstring; the precise pattern above is clean.
- `grep -n 'session.commit' scripts/recover_investigation.py` → lines 106 and 115
  only (the two write actions), i.e. the script commits exactly as the
  transaction owner, mirroring `scripts/run_investigation_step.py`.
- Directory-wide guards in the suite still pass with the new files present:
  `tests/test_investigation_tasks.py::test_only_the_task_module_writes_a_task_status_or_timestamp`
  and `...::test_only_the_lifecycle_modules_write_investigation_or_task_status`
  (which scan `verification/`, `intelligence/`, `gateway/`, `data/`, `workers/`,
  and `scripts/`) and `tests/test_finding_promotion.py::test_only_the_promotion_gate_writes_a_hypothesis_status`
  all green — recovery writes no `Hypothesis.status`, `Task.status`, or
  `Investigation.status` anywhere.

## Explicit statement

**No auto-retry loop and no background recovery.** `find_stuck_tasks` only lists;
`create_retry_task` only creates a pending copy and never runs it; the operator
script has no loop and no scheduler, and the retry is run later by the operator
with `scripts/run_investigation_step.py` exactly as before this slice. Recovery
is human-initiated on every path, and the library functions flush without ever
committing.

## Full source — verification/task_recovery.py

```python
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

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Investigation, Task, TaskEvent
from verification.investigation_tasks import (
    RUNNING,
    append_task_event,
    complete_task,
    create_task,
)

RETRYABLE_STATUSES = frozenset({"failed", "cancelled"})


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
    if not reason.strip():
        raise ValueError("reason must not be blank")

    task = complete_task(task_id, session, final_status="failed", result_summary=reason)
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
    original = session.get(Task, original_task_id)
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

    retry = create_task(
        original.investigation_id,
        session,
        kind=original.kind,
        title=original.title,
        params=original.params,
        depends_on=original.depends_on,
    )
    append_task_event(
        original.id,
        session,
        event_type="retry_created",
        detail={"retry_task_id": retry.id, "retry_of": original.id},
    )
    return retry
```

## Full source — scripts/recover_investigation.py

```python
#!/usr/bin/env python3
"""Operator-only recovery for tasks left ``running`` by a crashed run.

Three modes, all human-initiated and none of which run a task:

* default - list the investigation's stuck tasks (``running`` longer than
  ``--threshold-seconds``) and nothing else; a dry run that never writes.
* ``--mark-failed <task_id>`` - mark one task failed after a crash via
  :func:`verification.task_recovery.mark_task_failed_after_crash`.
* ``--retry <task_id>`` - create one pending retry of a failed/cancelled task
  via :func:`verification.task_recovery.create_retry_task`, and print the new
  task id.

This script is the transaction owner, so it commits after a write action (the
library functions it calls only flush). It never starts the retry: the operator
runs it later with ``scripts/run_investigation_step.py`` exactly as today, and
there is no scheduler, loop, or automatic recovery.

Usage:
    venv/bin/python scripts/recover_investigation.py 1
    venv/bin/python scripts/recover_investigation.py 1 --threshold-seconds 600
    venv/bin/python scripts/recover_investigation.py 1 --mark-failed 7 --reason "worker crashed"
    venv/bin/python scripts/recover_investigation.py 1 --retry 7
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.db import init_db  # noqa: E402
from data.models import Investigation  # noqa: E402
from verification.task_recovery import (  # noqa: E402
    create_retry_task,
    find_stuck_tasks,
    mark_task_failed_after_crash,
)

DB_NAME = "lab_evidence_v3.db"
DEFAULT_THRESHOLD_SECONDS = 3600.0
DEFAULT_REASON = "operator marked failed after crash"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List or repair one investigation's stuck (running) tasks."
    )
    parser.add_argument(
        "investigation_id", type=int, help="id of the investigation to inspect or repair"
    )
    parser.add_argument(
        "--threshold-seconds",
        type=float,
        default=DEFAULT_THRESHOLD_SECONDS,
        help="running duration beyond which a task is stuck (default: 3600)",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--mark-failed",
        type=int,
        metavar="TASK_ID",
        help="mark this running task failed after a crash (writes)",
    )
    action.add_argument(
        "--retry",
        type=int,
        metavar="TASK_ID",
        help="create a pending retry of this failed/cancelled task (writes)",
    )
    parser.add_argument(
        "--reason",
        default=DEFAULT_REASON,
        help="reason recorded when --mark-failed is used",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.threshold_seconds < 0:
        parser.error("--threshold-seconds must be >= 0")

    db_path = (REPO_ROOT / DB_NAME).resolve()
    engine = init_db(f"sqlite+pysqlite:///{db_path.as_posix()}")

    with Session(engine) as session:
        investigation = session.get(Investigation, args.investigation_id)
        if investigation is None:
            raise SystemExit(
                f"No Investigation #{args.investigation_id} exists in {DB_NAME}."
            )

        if args.mark_failed is not None:
            task = mark_task_failed_after_crash(
                args.mark_failed, session, reason=args.reason
            )
            session.commit()
            print(
                f"Task #{task.id} marked failed after crash "
                f"(reason: {args.reason!r})."
            )
            return 0

        if args.retry is not None:
            retry = create_retry_task(args.retry, session)
            session.commit()
            print(
                f"Created retry task #{retry.id} for original #{args.retry}. "
                f"Run it with scripts/run_investigation_step.py "
                f"{args.investigation_id}."
            )
            return 0

        stuck = find_stuck_tasks(
            args.investigation_id,
            session,
            running_longer_than_seconds=args.threshold_seconds,
        )
        print(
            f"{len(stuck)} task(s) running longer than "
            f"{args.threshold_seconds:g}s in investigation {args.investigation_id}:"
        )
        for task in stuck:
            print(f"  #{task.id} {task.kind}: {task.title}")
        print(
            "Dry run: nothing written. Use --mark-failed <task_id> or "
            "--retry <task_id> to act."
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
```



