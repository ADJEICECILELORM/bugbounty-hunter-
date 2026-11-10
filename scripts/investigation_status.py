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
    venv/bin/python scripts/investigation_status.py --investigation 1 --researcher-dashboard
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
    IntelligenceDashboard,
    InvestigationStatus,
    InvestigationSummary,
    TaskSummary,
    get_investigation_status,
    get_researcher_dashboard,
    list_investigations,
)
from data.sqlite import enable_sqlite_foreign_keys  # noqa: E402

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
    return enable_sqlite_foreign_keys(create_engine(uri))


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


def _print_researcher_dashboard(board: IntelligenceDashboard) -> None:
    """Render the stored intelligence view without triggering workflow actions."""
    def count(value: int | None) -> str:
        return str(value) if value is not None else "unavailable"

    print(f"Researcher dashboard for investigation #{board.investigation_id}:")
    print(f"  status: {board.status or 'unavailable'}")
    print(
        f"  assets={count(board.assets)} observations={count(board.observations)} "
        f"hypotheses={count(board.hypotheses)} findings={count(board.findings)}"
    )
    print("  data availability:")
    for name, value in board.data_availability.items():
        print(f"    {name}: {value}")

    if board.assets == 0:
        print("  assets: none stored")
    elif board.assets is None:
        print("  assets: unavailable; asset records could not be inspected")
    asset_hostnames = board.asset_hostnames or {}
    observation_groups = board.observation_groups or {}
    hypotheses_by_asset = board.hypotheses_by_asset or {}
    for asset_id, hostname in asset_hostnames.items():
        print(f"  asset #{asset_id} {hostname}:")
        if board.observation_groups is None:
            print("    observations: unavailable in this database schema")
            continue
        observations = observation_groups.get(asset_id, [])
        if not observations:
            print("    observations: none stored for this asset")
        for observation in observations:
            collector = observation.provenance_collector or "unknown"
            captured = _format_timestamp(observation.captured_at)
            print(
                f"    observation #{observation.observation_id} "
                f"type={observation.observation_type} "
                f"recorded={_format_timestamp(observation.created_at)} "
                f"collector={collector} captured={captured}"
            )
            print(f"      {observation.summary}")
            print(f"      evidence: {observation.evidence_interpretation}")

    if board.hypotheses_by_asset is None:
        print("  hypotheses: unavailable in this database schema")
    elif board.hypotheses == 0:
        print("  hypotheses: none stored")
    for asset_id, hostname in asset_hostnames.items():
        print(f"  research hypotheses for asset #{asset_id} {hostname}:")
        if board.hypotheses_by_asset is None:
            print("    hypotheses: unavailable in this database schema")
            continue
        hypotheses = hypotheses_by_asset.get(asset_id, [])
        if not hypotheses:
            print("    hypotheses: none stored for this asset")
        for hypothesis in hypotheses:
            print(
                f"    hypothesis #{hypothesis.hypothesis_id} "
                f"category={hypothesis.category} status={hypothesis.status}"
            )
            print(f"      {hypothesis.description}")
            print(f"      evidence: {hypothesis.evidence_interpretation}")
            print(
                f"      confidence={hypothesis.confidence or 'not recorded'} "
                f"impact={hypothesis.impact or 'not recorded'} "
                f"priority={hypothesis.priority or 'not recorded'}"
            )
            if hypothesis.priority_reason:
                print(f"      priority basis: {hypothesis.priority_reason}")
            if hypothesis.supporting_observation_ids:
                ids = ", ".join(
                    f"#{observation_id}"
                    for observation_id in hypothesis.supporting_observation_ids
                )
                print(f"      supporting observation IDs (context only): {ids}")
            elif hypothesis.supporting_observation_ids is None:
                print("      supporting observation IDs: unavailable in this database schema")
            else:
                print("      supporting observation IDs: none available")
            if hypothesis.unavailable_support_count:
                print(
                    "      warning: "
                    f"{hypothesis.unavailable_support_count} linked record(s) "
                    "are missing or belong to another asset"
                )
            print(f"      additional evidence: {hypothesis.additional_evidence}")
            print(
                "      recommendation (not a verified vulnerability): "
                f"{hypothesis.recommended_next_step}"
            )


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
    parser.add_argument(
        "--researcher-dashboard",
        action="store_true",
        help="show stored observations and evidence-linked hypotheses "
        "(requires --investigation; read-only)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.investigation is not None and args.investigation < 1:
        raise SystemExit("--investigation must be a positive integer.")
    if args.threshold_seconds < 0:
        raise SystemExit("--threshold-seconds must be >= 0.")
    if args.researcher_dashboard and args.investigation is None:
        raise SystemExit("--researcher-dashboard requires --investigation.")

    engine = read_only_engine(DB_PATH)
    try:
        with Session(engine) as session:
            if args.researcher_dashboard:
                dashboard = get_researcher_dashboard(session, args.investigation)
                _print_researcher_dashboard(dashboard)
                return 0
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
