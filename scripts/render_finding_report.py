#!/usr/bin/env python3
"""Operator-only, read-only renderer for a promoted finding.

This is the closing step of the controlled-verification lifecycle: after a human
has promoted a verified hypothesis to a ``Finding``
(:mod:`verification.finding_promotion`), this script opens the *existing*
evidence database **read-only**, loads that finding, and renders it through the
pure, tested :func:`verification.finding_report.render_finding_report` into a
Markdown file.

It exists so that "reported" is a real, deliberate act instead of a library call
lost in a notebook. It is *manual*: nothing imports it, the automated test suite
never executes it, and no worker calls it.

Hard guarantees, in order of strength:

* **The database is opened read-only at the SQLite level** (``mode=ro`` in the
  connection URI), not merely "we promise not to commit". Any write attempt -
  including the ``CREATE TABLE`` that :func:`data.db.init_db` performs - is
  refused by SQLite itself. This script never calls ``init_db`` and never calls
  ``session.commit()``.
* **It refuses to start unless the database already exists.** A missing file
  raises ``SystemExit``; nothing is ever created.
* **It refuses to invent anything.** A missing finding, a tampered verdict, a
  dangling observation reference, or a finding with no supported verdict raises
  :class:`verification.finding_report.FindingReportContextError` and prints the
  reason instead of emitting a report that claims evidence it does not hold.
* **It never promotes.** :mod:`verification.finding_promotion` is not imported,
  and the read-only connection could not write a ``Finding`` even if it were.
* **It prints exactly what it did** - the finding it read, the report path and
  size it wrote, and whether the database bytes are unchanged after the run.

Usage:
    venv/bin/python scripts/render_finding_report.py 1
    venv/bin/python scripts/render_finding_report.py 1 --out /tmp/finding-1.md

The default output path is ``finding-<id>.md`` in the repository root (gitignored).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.models import Finding  # noqa: E402
from verification.finding_report import (  # noqa: E402
    FindingReportContextError,
    collect_finding_context,
    render_finding_report,
)

V3_DB_NAME = "lab_evidence_v3.db"
V3_DB_PATH = REPO_ROOT / V3_DB_NAME

# A missing database is an operator error, not a request to create one: the
# script exits rather than making a file it was never asked to make.
_EXPECTED_DB_MISSING_MSG = (
    f"{V3_DB_NAME} does not exist. Promote a finding first, then re-run "
    "this script; it only reads an existing record, it never creates one."
)


def read_only_engine(db_path: Path) -> "create_engine":
    """Open ``db_path`` read-only, refusing to run if the file is absent.

    ``mode=ro`` is enforced by SQLite itself: any write - including the schema
    creation that ``init_db`` would trigger - raises ``OperationalError``. The
    script never calls ``init_db`` and never calls ``session.commit()``.
    """
    if not db_path.is_file():
        raise SystemExit(_EXPECTED_DB_MISSING_MSG)
    uri = f"sqlite:///file:{db_path.resolve().as_posix()}?mode=ro&uri=true"
    return create_engine(uri)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_finding(session: Session, finding_id: int) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise SystemExit(f"No Finding #{finding_id} exists in {V3_DB_NAME}.")
    return finding


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a promoted finding to Markdown, read-only."
    )
    parser.add_argument(
        "finding_id",
        type=int,
        help="id of the already-promoted Finding to render",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=None,
        help="output Markdown path (default: finding-<id>.md in the repo root)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.finding_id < 1:
        raise SystemExit("finding_id must be a positive integer.")

    out_path = args.out or (REPO_ROOT / f"finding-{args.finding_id}.md")
    out_path = out_path.expanduser().resolve()

    # Open (and existence-check) first: a missing database must exit with the
    # clean operator message, not a FileNotFoundError from hashing the bytes.
    engine = read_only_engine(V3_DB_PATH)
    db_before = _sha256(V3_DB_PATH)
    try:
        with Session(engine) as session:
            finding = _load_finding(session, args.finding_id)
            context = collect_finding_context(session, finding)
            report = render_finding_report(context)
            out_path.write_text(report, encoding="utf-8")
            supported = [
                verdict
                for verdict in context.verdicts
                if verdict.verdict == "supported" and not verdict.is_control
            ]
            print(f"Read {V3_DB_NAME} read-only (SQLite mode=ro).")
            print(
                f"Finding #{finding.id} {finding.title!r} "
                f"(hypothesis #{finding.hypothesis_id}, approved by "
                f"{finding.approved_by})"
            )
            print(
                f"  {len(supported)} supported verdict(s), "
                f"{len(context.verdicts)} verdict(s) total, "
                f"{len(context.audits)} promotion audit row(s); "
                "each verdict re-derived from its own stored evidence."
            )
    except FindingReportContextError as error:
        # Fail closed: a tampered or incomplete record must not become a report.
        raise SystemExit(f"Refusing to render: {error}") from error
    finally:
        engine.dispose()

    db_after = _sha256(V3_DB_PATH)
    unchanged = db_before == db_after
    print(
        f"Wrote {out_path.stat().st_size} bytes to {out_path}."
    )
    print(
        f"Database unchanged after the run: {unchanged} "
        f"(sha256 {db_after[:16]}...)."
    )
    if not unchanged:
        raise SystemExit(
            f"Refusing to finish: {V3_DB_NAME} changed during the run. "
            "The read-only connection must not have modified it."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
