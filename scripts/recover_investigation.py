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
