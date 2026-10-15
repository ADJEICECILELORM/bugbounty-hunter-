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
