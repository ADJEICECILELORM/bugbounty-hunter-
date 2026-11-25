#!/usr/bin/env python3
"""Operator-only endpoint inventory collection under an owned investigation.

This script is the deliberate live path for the previously dormant endpoint
inventory collector. It owns an ``Investigation`` *and* a ``Task``: it opens (or
starts) a running investigation, ensures an ``Asset`` for the target host,
creates an ``inventory`` task, and runs the existing
:func:`verification.endpoint_inventory_collector.collect_seed_inventory` through
the dispatcher, then commits because it is the transaction owner (the helper and
task layers only flush).

Scope is never widened here. ``authorize`` is rebuilt from the program's stored
scope via :mod:`gateway.scope_policy` - the same gate every probe already passes -
and the lab opt-in is an explicit ``--lab`` flag on this invocation only, never a
stored value. The script never promotes a hypothesis and never imports the
promotion gate.

Usage:
    venv/bin/python scripts/collect_inventory.py --program 1 --base-url https://example.test/
    venv/bin/python scripts/collect_inventory.py --investigation 3 --base-url http://127.0.0.1:3000/ --lab
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.database_options import (  # noqa: E402
    OperatorDatabaseError,
    add_database_option,
    open_operator_database,
)
from data.models import Asset, Investigation, Task  # noqa: E402
from gateway.scope_policy import ScopePolicy  # noqa: E402
from orchestration.session_helpers import (  # noqa: E402
    ensure_running_investigation,
    run_under_investigation,
)
from orchestration.task_runner import run_task  # noqa: E402
from verification.investigation_tasks import create_task  # noqa: E402

DB_NAME = "lab_evidence_v3.db"
_HTTP_SCHEMES = frozenset({"http", "https"})


def _build_authorize(investigation: Investigation) -> Callable[[str], bool]:
    policy = ScopePolicy(
        investigation.program.authorized_scope, investigation.program.excluded_scope
    )

    def authorize(url: str) -> bool:
        hostname = urlsplit(url).hostname or ""
        return policy.is_authorized(hostname)

    return authorize


def _base_hostname(base_url: str) -> str:
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        _ = parsed.port
    except (TypeError, ValueError):
        raise ValueError("base_url must be a valid absolute http(s) URL") from None
    if parsed.scheme not in _HTTP_SCHEMES or not parsed.netloc or not hostname:
        raise ValueError("base_url must be a valid absolute http(s) URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not include URL credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not include a query or fragment")
    return hostname.lower()


def _ensure_asset(
    session: Session, investigation: Investigation, base_url: str
) -> Asset:
    """Create or reuse the investigation's asset for ``base_url``'s host."""
    hostname = _base_hostname(base_url)
    asset = session.scalar(
        select(Asset).where(
            Asset.investigation_id == investigation.id,
            Asset.hostname == hostname,
        )
    )
    if asset is None:
        asset = Asset(investigation_id=investigation.id, hostname=hostname)
        session.add(asset)
        session.flush()
    return asset


def run_collect_inventory(
    session: Session,
    *,
    investigation: Investigation,
    base_url: str,
    authorize: Callable[[str], bool],
    allow_private_network: bool = False,
    commit_before_dispatch: bool = False,
) -> tuple[Investigation, Asset, Task]:
    """Own an inventory task under ``investigation`` and run the collector.

    Ensures an ``Asset`` for ``base_url``'s host, creates an ``inventory`` task,
    and dispatches
    :func:`verification.endpoint_inventory_collector.collect_seed_inventory`
    through the task runner. The caller owns the transaction unless
    ``commit_before_dispatch`` explicitly checkpoints the running task and its
    start event before collection so an interrupted CLI invocation can recover
    it. A failed collection marks the task ``failed`` and re-raises; nothing is
    promoted.
    """
    _base_hostname(base_url)
    if not authorize(base_url):
        raise ValueError("base_url is outside the investigation's authorized scope")
    task_error: Exception | None = None
    asset: Asset
    task: Task | None = None
    with session.begin_nested():
        prior_task_id = session.scalar(
            select(func.max(Task.id)).where(
                Task.investigation_id == investigation.id
            )
        ) or 0
        asset = _ensure_asset(session, investigation, base_url)
        if commit_before_dispatch:
            task = create_task(
                investigation.id,
                session,
                kind="inventory",
                title=f"Collect endpoint inventory for {base_url}",
                params={"asset_id": asset.id, "base_url": base_url},
            )
        else:
            try:
                task = run_under_investigation(
                    session,
                    investigation_id=investigation.id,
                    kind="inventory",
                    title=f"Collect endpoint inventory for {base_url}",
                    params={"asset_id": asset.id, "base_url": base_url},
                    authorize=authorize,
                    allow_private_network=allow_private_network,
                )
            except Exception as error:
                # Preserve a dispatched failure and its audit event; failures
                # before task creation roll back the speculative asset.
                failed_task = session.scalar(
                    select(Task.id).where(
                        Task.investigation_id == investigation.id,
                        Task.id > prior_task_id,
                        Task.kind == "inventory",
                        Task.status == "failed",
                    )
                )
                if failed_task is None:
                    raise
                task_error = error
    if commit_before_dispatch and task is not None:
        try:
            run_task(
                task.id,
                session,
                authorize=authorize,
                allow_private_network=allow_private_network,
                commit_before_dispatch=True,
            )
        except Exception as error:
            task_error = error
    if task_error is not None:
        raise task_error
    assert task is not None
    return investigation, asset, task


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect one asset's authorized endpoint inventory under an owned "
            "investigation."
        )
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--program",
        type=int,
        help="start a new investigation for this program id",
    )
    target.add_argument(
        "--investigation",
        type=int,
        help="reuse this existing running investigation id",
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="origin base URL to inventory (absolute http/https)",
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        help="allow private-network (lab) targets for this run only",
    )
    add_database_option(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        _base_hostname(args.base_url)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    try:
        engine, _db_path = open_operator_database(
            args.database, default_path=REPO_ROOT / DB_NAME
        )
    except OperatorDatabaseError as error:
        raise SystemExit(str(error)) from error

    with Session(engine) as session:
        try:
            investigation = ensure_running_investigation(
                session,
                program_id=args.program,
                investigation_id=args.investigation,
            )
        except (LookupError, ValueError) as error:
            raise SystemExit(str(error)) from error

        authorize = _build_authorize(investigation)
        if not authorize(args.base_url):
            raise SystemExit(
                f"base_url host {_base_hostname(args.base_url)!r} is outside the "
                f"authorized scope for investigation #{investigation.id} "
                f"(authorized={investigation.program.authorized_scope!r}, "
                f"excluded={investigation.program.excluded_scope!r})."
            )
        prior_task_id = session.scalar(
            select(func.max(Task.id)).where(
                Task.investigation_id == investigation.id
            )
        ) or 0
        try:
            investigation, asset, task = run_collect_inventory(
                session,
                investigation=investigation,
                base_url=args.base_url,
                authorize=authorize,
                allow_private_network=args.lab,
                commit_before_dispatch=True,
            )
        except Exception as error:  # noqa: BLE001 - persist the failed task, then stop
            failed_task = session.scalar(
                select(Task.id).where(
                    Task.investigation_id == investigation.id,
                    Task.id > prior_task_id,
                    Task.kind == "inventory",
                    Task.status == "failed",
                )
            )
            if failed_task is not None:
                session.commit()
            else:
                session.rollback()
            print(
                f"Investigation #{investigation.id}: inventory task failed: "
                f"{type(error).__name__}: {error}"
            )
            return 1

        session.commit()
        print(f"Investigation #{investigation.id}, asset #{asset.id}:")
        print(
            f"  task #{task.id} {task.kind} -> {task.status}: "
            f"{task.result_summary or '(no summary)'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
