"""Focused coverage for deterministic, offline endpoint inventory planning."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import create_database_engine, initialize_fresh_database
from data.models import (
    Asset,
    Investigation,
    Observation,
    Program,
    Task,
    TaskObservation,
)
from orchestration.inventory_planner import (
    plan_inventory_research_tasks,
    preview_inventory_research_tasks,
)
from verification.investigation_tasks import complete_task, create_task, start_task

REPO_ROOT = Path(__file__).resolve().parent.parent
PLANNER_PATH = REPO_ROOT / "orchestration" / "inventory_planner.py"


@pytest.fixture()
def session(tmp_path: Path):
    engine = create_database_engine(
        f"sqlite+pysqlite:///{tmp_path / 'inventory-planner.db'}"
    )
    initialize_fresh_database(engine)
    with Session(engine) as active_session:
        yield active_session
    engine.dispose()


def _investigation(session: Session, *, max_tasks=None, max_llm_calls=None):
    program = Program(
        name="Inventory planner test",
        authorized_scope=["*.example.test"],
        excluded_scope=["blocked.example.test"],
        rate_limit=2,
    )
    investigation = Investigation(
        program=program,
        status="running",
        max_tasks=max_tasks,
        max_llm_calls=max_llm_calls,
    )
    session.add(investigation)
    session.flush()
    return investigation


def _asset(session: Session, investigation: Investigation, host="api.example.test"):
    asset = Asset(investigation_id=investigation.id, hostname=host)
    session.add(asset)
    session.flush()
    return asset


def _observation(asset: Asset, *, url="https://api.example.test/account"):
    return Observation(
        asset_id=asset.id,
        observation_type="endpoint_inventory",
        data={"url": url, "status_code": 200},
    )


def test_empty_inventory_creates_no_tasks(session: Session) -> None:
    investigation = _investigation(session)
    _asset(session, investigation)

    report = plan_inventory_research_tasks(investigation.id, session)

    assert report.created_task_ids == ()
    assert report.skipped_observation_ids == ()
    assert session.scalars(select(Task)).all() == []


def test_out_of_scope_endpoint_is_skipped(session: Session) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    observation = _observation(asset, url="https://blocked.example.test/account")
    session.add(observation)
    session.flush()

    report = plan_inventory_research_tasks(investigation.id, session)

    assert report.created_task_ids == ()
    assert report.skipped_observation_ids == (observation.id,)
    assert session.scalars(select(Task)).all() == []


def test_repeated_planning_reuses_generation_and_review_tasks(session: Session) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    observations = [_observation(asset), _observation(asset, url="https://api.example.test/orders")]
    session.add_all(observations)
    session.flush()

    first = plan_inventory_research_tasks(investigation.id, session)
    second = plan_inventory_research_tasks(investigation.id, session)

    assert len(first.created_task_ids) == 4  # brief, generation, and two reviews
    assert second.created_task_ids == ()
    assert len(second.existing_task_ids) == 4
    assert len(session.scalars(select(Task)).all()) == 4


def test_duplicate_endpoint_rows_are_reported_and_reviewed_once(
    session: Session,
) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    first = _observation(asset, url="https://api.example.test/account#first")
    duplicate = _observation(asset, url="https://api.example.test/account#second")
    duplicate.data["status_code"] = 403
    session.add_all([first, duplicate])
    session.flush()

    preview = preview_inventory_research_tasks(investigation.id, session)
    report = plan_inventory_research_tasks(investigation.id, session)

    assert preview.redundant_observation_ids == (duplicate.id,)
    assert report.redundant_observation_ids == (duplicate.id,)
    reviews = [
        session.get(Task, task_id)
        for task_id in report.created_task_ids
        if session.get(Task, task_id).kind == "hypothesis_review"
    ]
    assert len(reviews) == 1
    assert f"observation #{first.id}" in reviews[0].title
    review_link = session.scalar(
        select(TaskObservation).where(TaskObservation.task_id == reviews[0].id)
    )
    assert review_link is not None
    assert (review_link.observation_id, review_link.role) == (first.id, "input")


def test_preview_explains_review_order_without_claiming_severity(
    session: Session,
) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    lower_priority = _observation(asset, url="https://api.example.test/other")
    lower_priority.data["status_code"] = 404
    higher_priority = _observation(asset)
    session.add_all([lower_priority, higher_priority])
    session.flush()

    preview = preview_inventory_research_tasks(investigation.id, session)
    reviews = [task for task in preview.proposed_tasks if task.kind == "hypothesis_review"]

    assert [task.observation_id for task in reviews] == [
        higher_priority.id,
        lower_priority.id,
    ]
    assert [task.priority_rank for task in reviews] == [0, 2]
    assert all("not proof" in task.priority_reason for task in reviews)


def test_concurrent_planning_creates_one_task_chain(
    tmp_path: Path,
) -> None:
    engine = create_database_engine(
        f"sqlite+pysqlite:///{tmp_path / 'concurrent-planning.db'}"
    )
    initialize_fresh_database(engine)
    with Session(engine) as setup:
        investigation = _investigation(setup)
        asset = _asset(setup, investigation)
        setup.add(_observation(asset))
        setup.commit()
        investigation_id = investigation.id

    barrier = Barrier(2)

    def run_planner():
        barrier.wait(timeout=10)
        with Session(engine) as active:
            report = plan_inventory_research_tasks(investigation_id, active)
            active.commit()
            return report

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            reports = list(pool.map(lambda _index: run_planner(), range(2)))
        with Session(engine) as check:
            tasks = check.scalars(
                select(Task).where(Task.investigation_id == investigation_id)
            ).all()
        assert len(tasks) == 3
        assert len({task.dedupe_key for task in tasks}) == 3
        assert sorted(len(report.created_task_ids) for report in reports) == [0, 3]
        assert sorted(len(report.existing_task_ids) for report in reports) == [0, 3]
    finally:
        engine.dispose()


def test_tasks_have_valid_inventory_and_generation_dependencies(session: Session) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    observation = _observation(asset)
    session.add(observation)
    inventory_task = create_task(
        investigation.id,
        session,
        kind="inventory",
        title="Collect endpoints",
        params={"asset_id": asset.id, "base_url": "https://api.example.test/"},
    )
    start_task(inventory_task.id, session)
    complete_task(inventory_task.id, session, final_status="completed")

    report = plan_inventory_research_tasks(investigation.id, session)
    brief, generation, review = [
        session.get(Task, task_id) for task_id in report.created_task_ids
    ]

    assert brief.kind == "research_brief"
    assert brief.depends_on == [inventory_task.id]
    assert generation.kind == "hypothesis_generation"
    assert generation.depends_on == [brief.id]
    assert review.kind == "hypothesis_review"
    assert review.depends_on == [generation.id]
    all_ids = {task.id for task in session.scalars(select(Task)).all()}
    assert set(brief.depends_on + generation.depends_on + review.depends_on) <= all_ids
    assert all(
        session.get(Task, dependency_id).investigation_id == investigation.id
        for dependency_id in brief.depends_on + generation.depends_on + review.depends_on
    )


def test_open_inventory_task_defers_planning_until_collection_finishes(
    session: Session,
) -> None:
    investigation = _investigation(session)
    asset = _asset(session, investigation)
    observation = _observation(asset)
    session.add(observation)
    inventory_task = create_task(
        investigation.id,
        session,
        kind="inventory",
        title="Collect endpoints",
        params={"asset_id": asset.id, "base_url": "https://api.example.test/"},
    )

    report = plan_inventory_research_tasks(investigation.id, session)

    assert report.created_task_ids == ()
    assert report.deferred_asset_ids == (asset.id,)
    assert report.deferred_observation_ids == (observation.id,)
    assert session.scalars(select(Task)).all() == [inventory_task]


@pytest.mark.parametrize(
    ("max_tasks", "max_llm_calls", "expected_detail"),
    [
        (1, None, "task budget"),
        (None, 0, "LLM-call budget"),
    ],
)
def test_budget_exhaustion_defers_asset_without_partial_tasks(
    session: Session,
    max_tasks: int | None,
    max_llm_calls: int | None,
    expected_detail: str,
) -> None:
    investigation = _investigation(
        session, max_tasks=max_tasks, max_llm_calls=max_llm_calls
    )
    asset = _asset(session, investigation)
    observation = _observation(asset)
    session.add(observation)
    session.flush()

    report = plan_inventory_research_tasks(investigation.id, session)

    assert report.created_task_ids == ()
    assert report.deferred_asset_ids == (asset.id,)
    assert report.deferred_observation_ids == (observation.id,)
    assert report.budget_exhausted is True
    assert expected_detail in report.budget_detail
    assert session.scalars(select(Task)).all() == []


def test_planner_has_no_network_or_verification_dispatch_imports() -> None:
    tree = ast.parse(PLANNER_PATH.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )

    assert not any(
        module.startswith(("requests", "httpx", "socket", "verification.run_"))
        or module.endswith("endpoint_inventory_collector")
        for module in imports
    )
