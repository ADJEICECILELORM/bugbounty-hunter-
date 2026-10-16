#!/usr/bin/env python3
"""Operator-only, human-gated, budget-aware supervised investigation cycles.

This script is the V6 first-slice operator path. One invocation proposes an
investigation's ready tasks via
:func:`orchestration.supervised_cycle.run_supervised_cycle` and prints them;
only with an explicit ``--yes`` does it execute, committing once at the end
because it is the transaction owner (the library functions it calls only
flush). There is no free-running loop: with ``--yes`` it runs exactly one
supervised cycle, and ``--max-cycles N`` (1..5) caps how many cycles this one
process may run, re-planning between each and stopping early the moment a cycle
proposes nothing or hits the stop-on-first-failure policy.

It never promotes a finding, never imports the promotion gate, and never starts
a network path except through the existing ``run_task`` dispatch. ``authorize``
is rebuilt from the program's stored scope via :mod:`gateway.scope_policy` - the
same gate every probe already goes through - and the lab opt-in is a ``--lab``
flag on this invocation only, never a stored value. Verification tasks need a
plan an operator would have to supply; without one ``run_task`` refuses and the
task is left pending, which this script reports rather than fabricating.

Usage:
    venv/bin/python scripts/run_supervised_investigation.py 1
    venv/bin/python scripts/run_supervised_investigation.py 1 --yes
    venv/bin/python scripts/run_supervised_investigation.py 1 --yes --max-cycles 3
    venv/bin/python scripts/run_supervised_investigation.py 1 --yes --lab
    venv/bin/python scripts/run_supervised_investigation.py 1 --yes --threshold-seconds 1800
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
from orchestration.supervised_cycle import (  # noqa: E402
    CycleReport,
    DEFAULT_STUCK_THRESHOLD_SECONDS,
    run_supervised_cycle,
)

DB_NAME = "lab_evidence_v3.db"
MAX_CYCLES = 5


def _build_authorize(investigation: Investigation) -> Callable[[str], bool]:
    policy = ScopePolicy(
        investigation.program.authorized_scope, investigation.program.excluded_scope
    )

    def authorize(url: str) -> bool:
        hostname = urlsplit(url).hostname or ""
        return policy.is_authorized(hostname)

    return authorize


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Propose, and with --yes run, one investigation's ready tasks as "
            "budget-aware supervised cycles."
        )
    )
    parser.add_argument(
        "investigation_id", type=int, help="id of the investigation to step"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="actually run the proposed tasks (default: propose only, exit 0)",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=1,
        help=f"at most this many execute cycles in this process (1..{MAX_CYCLES})",
    )
    parser.add_argument(
        "--threshold-seconds",
        type=float,
        default=DEFAULT_STUCK_THRESHOLD_SECONDS,
        help=(
            "running duration beyond which a task is stuck "
            f"(default: {DEFAULT_STUCK_THRESHOLD_SECONDS:g})"
        ),
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        help="allow private-network (lab) targets for this run only",
    )
    return parser


def _print_report(report: CycleReport) -> None:
    print(f"Investigation {report.investigation_id}: {len(report.proposed)} task(s) proposed:")
    for task in report.proposed:
        print(f"  #{task.task_id} {task.kind}: {task.title}")
    for skip in report.skipped:
        print(f"  [skipped: {skip.reason}] {skip.detail}")
    for result in report.executed:
        mark = "ok" if result.ok else f"FAILED ({result.error_type})"
        print(f"  #{result.task_id} {result.kind}: {mark}")
        if not result.ok and result.error:
            print(f"      {result.error}")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if not 1 <= args.max_cycles <= MAX_CYCLES:
        raise SystemExit(f"--max-cycles must be between 1 and {MAX_CYCLES}")
    if args.threshold_seconds < 0:
        raise SystemExit("--threshold-seconds must be >= 0")

    db_path = (REPO_ROOT / DB_NAME).resolve()
    engine = init_db(f"sqlite+pysqlite:///{db_path.as_posix()}")

    with Session(engine) as session:
        investigation = session.get(Investigation, args.investigation_id)
        if investigation is None:
            raise SystemExit(
                f"No Investigation #{args.investigation_id} exists in {DB_NAME}."
            )

        authorize = _build_authorize(investigation)

        if not args.yes:
            report = run_supervised_cycle(
                args.investigation_id,
                session,
                execute=False,
                threshold_seconds=args.threshold_seconds,
            )
            _print_report(report)
            print("Dry run: nothing executed and nothing written. Re-run with --yes to execute.")
            return 0

        final_status = 0
        for cycle_index in range(1, args.max_cycles + 1):
            print(f"--- cycle {cycle_index}/{args.max_cycles} ---")
            try:
                report = run_supervised_cycle(
                    args.investigation_id,
                    session,
                    execute=True,
                    threshold_seconds=args.threshold_seconds,
                    authorize=authorize,
                    allow_private_network=args.lab,
                )
            except (LookupError, ValueError) as error:
                print(f"Refused: {error}")
                final_status = 1
                break

            _print_report(report)

            if any(skip.reason == "stuck" for skip in report.skipped):
                print("Blocked: run scripts/recover_investigation.py first.")
                final_status = 1
                break
            if not report.proposed:
                print("Nothing proposed; no further cycles.")
                break
            if report.executed and not report.executed[-1].ok:
                print("Stopped: a task failed (stop-on-first-failure policy).")
                final_status = 1
                break

        session.commit()
        if final_status == 0:
            print("Done.")
        else:
            print("Committed work so far; finished with a refusal or failure.")

    return final_status


if __name__ == "__main__":
    raise SystemExit(main())

