#!/usr/bin/env python3
"""Operator-only, read-only investigation status board.

Prints a human-readable summary of the investigations and tasks stored in the
existing ``lab_evidence_v3.db``, or of one investigation when
``--investigation ID`` is given. The database is opened read-only at the SQLite
level (``mode=ro&uri=true``) and the script never commits, never writes, never
imports the task dispatcher, the supervisor, the recovery writers, or the
promotion gate. All logic lives in the pure, tested
:mod:`orchestration.status_board` module; this script only formats its
dataclass return values for an operator.

Usage:
    venv/bin/python scripts/investigation_status.py
    venv/bin/python scripts/investigation_status.py --investigation 1
    venv/bin/python scripts/investigation_status.py --investigation 1 --threshold-seconds 600
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from orchestration.status_board import (  # noqa: E402
    DEFAULT_STUCK_THRESHOLD_SECONDS,
    InvestigationStatus,
    InvestigationSummary,
    TaskSummary,
    get_investigation_status,
    list_investigations,
)

DB_NAME = "lab_evidence_v3.db"
DB_PATH = REPO_ROOT / DB_NAME


def read_only_engine(db_path: Path) -> Engine:
    """Open ``db_path`` read-only; refuse to run if the file is absent."""
    if not db_path.is_file():
        raise SystemExit(
            f"{DB_NAME} does not exist. Run an investigation flow first, then "
            "re-run this script; it only reads an existing database."
        )
    uri = f"sqlite:///file:{db_path.resolve().as_posix()}?mode=ro&uri=true"
    return create_engine(uri)


def _format_timestamp(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "-"


def _print_task(task: TaskSummary) -> None:
    started = _format_timestamp(task.started_at)
    ended = _format_timestamp(task.ended_at)
    print(
        f"    #{task.task_id} {task.kind:<22} {task.status:<10} "
        f"started={started} ended={ended} {task.title}"
    )


def _print_investigations(summaries: list[InvestigationSummary]) -> None:
    print(f"{len(summaries)} investigation(s):")
    if not summaries:
        return
    for summary in summaries:
        counts = " ".join(
            f"{status}={count}" for status, count in sorted(summary.task_counts.items())
        )
        print(
            f"  #{summary.investigation_id} status={summary.status} "
            f"max_tasks={summary.max_tasks!r} max_llm_calls={summary.max_llm_calls!r} "
            f"tasks={summary.total_tasks}"
            + (f" [{counts}]" if counts else "")
        )


def _print_board(board: InvestigationStatus, threshold_seconds: float) -> None:
    print(f"Investigation #{board.investigation_id}:")
    print(f"  status: {board.status}")
    print(
        f"  budget: max_tasks={board.max_tasks!r} "
        f"max_llm_calls={board.max_llm_calls!r}"
    )
    print(
        f"  budget remaining: tasks={board.budget.tasks_remaining} "
        f"llm_calls={board.budget.llm_calls_remaining}"
    )
    print(f"  hypotheses: {board.hypothesis_counts or {}}")
    print(f"  findings: {board.findings}")
    print(f"  tasks ({len(board.tasks)}):")
    for task in board.tasks:
        _print_task(task)
    print(f"  stuck tasks ({len(board.stuck_tasks)} running > {threshold_seconds:g}s):")
    for task in board.stuck_tasks:
        _print_task(task)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Print an investigation status board, read-only."
    )
    parser.add_argument(
        "--investigation",
        type=int,
        default=None,
        help="investigation id to inspect in detail (default: list all)",
    )
    parser.add_argument(
        "--threshold-seconds",
        type=float,
        default=DEFAULT_STUCK_THRESHOLD_SECONDS,
        help="running tasks older than this many seconds count as stuck "
        f"(default: {DEFAULT_STUCK_THRESHOLD_SECONDS:g})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.investigation is not None and args.investigation < 1:
        raise SystemExit("--investigation must be a positive integer.")
    if args.threshold_seconds < 0:
        raise SystemExit("--threshold-seconds must be >= 0.")

    engine = read_only_engine(DB_PATH)
    try:
        with Session(engine) as session:
            if args.investigation is None:
                _print_investigations(list_investigations(session))
                return 0
            board = get_investigation_status(
                session,
                args.investigation,
                threshold_seconds=args.threshold_seconds,
            )
            _print_board(board, args.threshold_seconds)
            return 0
    except LookupError as error:
        raise SystemExit(str(error)) from error
    except OperationalError as error:
        raise SystemExit(f"Could not read {DB_NAME}: {error}") from error
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
