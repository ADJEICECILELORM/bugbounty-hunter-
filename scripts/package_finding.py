#!/usr/bin/env python3
"""Operator-only, read-only packaging of a promoted finding into a zip.

Complements ``scripts/render_finding_report.py``: instead of writing a bare
Markdown file, it writes a ``.zip`` that bundles the rendered report with a
``manifest.json`` of provenance (ids, digest prefixes, approver, timestamp)
produced by the pure, tested :func:`verification.report_package.build_report_package`.

Like the renderer, the database is opened read-only at the SQLite level and the
script never commits, never changes a status, and never imports the promotion
gate. A missing finding or a tampered record raises and prints the reason rather
than emitting a package.

Usage:
    venv/bin/python scripts/package_finding.py 1
    venv/bin/python scripts/package_finding.py 1 --out /tmp/finding-1.zip
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.models import Finding  # noqa: E402
from verification.finding_report import FindingReportContextError  # noqa: E402
from verification.report_package import build_report_package  # noqa: E402

V3_DB_NAME = "lab_evidence_v3.db"
V3_DB_PATH = REPO_ROOT / V3_DB_NAME


def read_only_engine(db_path: Path) -> Engine:
    """Open ``db_path`` read-only, refusing to run if the file is absent."""
    if not db_path.is_file():
        raise SystemExit(
            f"{V3_DB_NAME} does not exist. Promote a finding first, then re-run "
            "this script; it only reads an existing record, it never creates one."
        )
    uri = f"sqlite:///file:{db_path.resolve().as_posix()}?mode=ro&uri=true"
    return create_engine(uri)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Package a promoted finding into a zip, read-only."
    )
    parser.add_argument(
        "finding_id",
        type=int,
        help="id of the already-promoted Finding to package",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=None,
        help="output zip path (default: finding-<id>.zip in the repo root)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.finding_id < 1:
        raise SystemExit("finding_id must be a positive integer.")

    out_path = args.out or (REPO_ROOT / f"finding-{args.finding_id}.zip")
    out_path = out_path.expanduser().resolve()

    engine = read_only_engine(V3_DB_PATH)
    try:
        with Session(engine) as session:
            if session.get(Finding, args.finding_id) is None:
                raise SystemExit(
                    f"No Finding #{args.finding_id} exists in {V3_DB_NAME}."
                )
            written = build_report_package(session, args.finding_id, out_path)
    except FindingReportContextError as error:
        raise SystemExit(f"Refusing to package: {error}") from error
    finally:
        engine.dispose()

    print(f"Wrote {written.stat().st_size} bytes to {written}.")
    print(f"Members: report.md (rendered finding), manifest.json (provenance).")
    print("Database read-only and unchanged; nothing was promoted or committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
