"""Deterministically create researcher tasks from stored endpoint inventory.

Planning is offline: this module reads database rows, checks the stored program
scope, and records pending tasks through ``create_task``. It never probes a
target, calls an LLM, runs verification, commits, or promotes a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from data.models import Asset, Investigation, Observation, Task
from gateway.scope_policy import ScopePolicy
from orchestration.task_runner import record_task_observation_links
from verification.investigation_tasks import (
    COMPLETED,
    MAX_LLM_CALLS_PER_INVESTIGATION,
    MAX_TASKS_PER_INVESTIGATION,
    create_task,
)


@dataclass(frozen=True)
class InventoryPlanningReport:
    """Tasks created/reused and inventory rows safely deferred by the planner."""

    created_task_ids: tuple[int, ...] = ()
    existing_task_ids: tuple[int, ...] = ()
    proposed_tasks: tuple["InventoryTaskProposal", ...] = ()
    skipped_observation_ids: tuple[int, ...] = ()
    redundant_observation_ids: tuple[int, ...] = ()
    deferred_observation_ids: tuple[int, ...] = ()
    deferred_asset_ids: tuple[int, ...] = ()
    budget_exhausted: bool = False
    budget_detail: str | None = None


@dataclass(frozen=True)
class InventoryTaskProposal:
    """A not-yet-persisted task description returned by the dry-run planner."""

    kind: str
    title: str
    asset_id: int
    observation_id: int | None = None
    depends_on: tuple[int | str, ...] = ()
    priority_rank: int = 0
    priority_reason: str = ""


@dataclass
class _AssetPlan:
    asset: Asset
    observations: list[Observation] = field(default_factory=list)
    inventory_task_ids: list[int] = field(default_factory=list)
    existing_brief: Task | None = None
    existing_generation: Task | None = None
    existing_reviews: dict[int, Task] = field(default_factory=dict)


def _create_or_reuse_task(
    session: Session,
    *,
    dedupe_key: str,
    investigation_id: int,
    kind: str,
    title: str,
    params: dict[str, int] | None = None,
    depends_on: list[int] | None = None,
) -> tuple[Task, bool]:
    """Create under a savepoint, reusing the DB winner after a key race."""
    try:
        with session.begin_nested():
            task = create_task(
                investigation_id,
                session,
                kind=kind,
                title=title,
                params=params,
                depends_on=depends_on,
                dedupe_key=dedupe_key,
            )
        return task, True
    except IntegrityError:
        task = session.scalar(select(Task).where(Task.dedupe_key == dedupe_key))
        if task is None or task.investigation_id != investigation_id:
            raise
        return task, False


def _eligible_inventory_observation(
    asset: Asset,
    observation: Observation,
    policy: ScopePolicy,
) -> bool:
    """Accept only well-formed HTTP inventory rows for the exact scoped asset."""
    if observation.observation_type != "endpoint_inventory":
        return False
    data = observation.data
    if not isinstance(data, dict):
        return False
    status = data.get("status_code")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return False
    url = data.get("url")
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
        # Accessing .port validates malformed port syntax.
        _ = parsed.port
        hostname = parsed.hostname
    except ValueError:
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    canonical_asset_host = asset.hostname.rstrip(".").lower()
    canonical_url_host = hostname.rstrip(".").lower()
    return (
        canonical_asset_host == canonical_url_host
        and policy.is_authorized(asset.hostname)
        and policy.is_authorized(hostname)
    )


def _endpoint_identity(observation: Observation) -> tuple[str, str, int | None, str, str]:
    """Stable endpoint key without URL fragments (which are never requested)."""
    parsed = urlsplit(observation.data["url"])
    port = parsed.port
    if port == (443 if parsed.scheme.lower() == "https" else 80):
        port = None
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").rstrip(".").lower(),
        port,
        parsed.path or "/",
        parsed.query,
    )


def _observation_priority(observation: Observation) -> tuple[int, str]:
    status = observation.data.get("status_code")
    if status in {200, 401, 403}:
        return 0, (
            f"HTTP {status} is useful context for comparing the endpoint with its "
            "intended access policy; it is not proof of a weakness."
        )
    if status in {201, 202, 204, 301, 302, 307, 308}:
        return 1, (
            f"HTTP {status} is retained as context; review after directly readable "
            "or access-denied endpoints. It is not proof of a weakness."
        )
    return 2, (
        f"HTTP {status} is retained as context; prioritize only if a researcher "
        "identifies a relevant requirement; it is not proof of a weakness."
    )


def _unique_endpoint_observations(
    observations: list[Observation],
) -> tuple[list[Observation], list[int]]:
    """Prefer the most review-relevant stored row for duplicate URLs."""
    ordered = sorted(
        observations,
        key=lambda row: (_observation_priority(row)[0], row.id),
    )
    seen: set[tuple[str, str, int | None, str, str]] = set()
    selected: list[Observation] = []
    redundant: list[int] = []
    for row in ordered:
        identity = _endpoint_identity(row)
        if identity in seen:
            redundant.append(row.id)
            continue
        seen.add(identity)
        selected.append(row)
    return selected, redundant


def _task_count(session: Session, investigation_id: int) -> int:
    return int(
        session.scalar(
            select(func.count(Task.id)).where(Task.investigation_id == investigation_id)
        )
        or 0
    )


def _acquire_planning_write_lock(session: Session) -> None:
    """Serialize SQLite planners before their duplicate and budget reads.

    SQLite's deferred transactions can otherwise let concurrent readers both
    plan from the same snapshot and then fail with ``database is locked`` while
    upgrading to writers. ``BEGIN IMMEDIATE`` is transaction-scoped and leaves
    commit/rollback ownership with the caller. Existing write transactions
    already hold the required reservation.
    """
    connection = session.connection()
    if connection.dialect.name != "sqlite":
        return
    driver_connection = connection.connection.driver_connection
    if not driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN IMMEDIATE")


def plan_inventory_research_tasks(
    investigation_id: int,
    session: Session,
) -> InventoryPlanningReport:
    """Create a deterministic, duplicate-safe research task chain from inventory.

    For each asset with eligible stored endpoint inventory, this creates one
    ``hypothesis_generation`` task (which the existing dispatcher may execute
    only when an operator chooses) and one manual ``hypothesis_review`` task per
    inventory observation. Review tasks depend on generation; generation depends
    on completed inventory tasks for the asset when such task records exist.

    Invalid, malformed, out-of-scope, or cross-host inventory rows cause that
    asset's inventory batch to be skipped. Existing tasks are reused, including
    terminal tasks, so repeated calls never silently retry or duplicate work.
    The caller owns the transaction; this function flushes through
    ``verification.investigation_tasks.create_task`` and never commits.
    """
    _acquire_planning_write_lock(session)
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")

    policy = ScopePolicy(
        investigation.program.authorized_scope,
        investigation.program.excluded_scope,
    )
    assets = session.scalars(
        select(Asset)
        .where(Asset.investigation_id == investigation_id)
        .order_by(Asset.id)
    ).all()
    observations_by_asset: dict[int, list[Observation]] = {asset.id: [] for asset in assets}
    for observation in session.scalars(
        select(Observation)
        .join(Asset, Observation.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(Observation.asset_id, Observation.id)
    ):
        observations_by_asset.setdefault(observation.asset_id, []).append(observation)

    tasks = session.scalars(
        select(Task)
        .where(Task.investigation_id == investigation_id)
        .order_by(Task.id)
    ).all()
    plans: list[_AssetPlan] = []
    skipped_ids: list[int] = []
    redundant_ids: list[int] = []
    deferred_ids: set[int] = set()
    deferred_asset_ids: set[int] = set()

    for asset in assets:
        inventory = [
            row
            for row in observations_by_asset.get(asset.id, [])
            if row.observation_type == "endpoint_inventory"
        ]
        if not inventory:
            continue
        if not policy.is_authorized(asset.hostname) or not all(
            _eligible_inventory_observation(asset, row, policy) for row in inventory
        ):
            skipped_ids.extend(row.id for row in inventory)
            continue
        inventory, redundant = _unique_endpoint_observations(inventory)
        redundant_ids.extend(redundant)

        matching_tasks = [
            task
            for task in tasks
            if task.kind == "hypothesis_generation"
            and isinstance(task.params, dict)
            and task.params.get("asset_id") == asset.id
        ]
        generation = matching_tasks[0] if matching_tasks else None
        if generation is not None and generation.status in {"failed", "cancelled"}:
            # Retrying a failed task is a recovery decision, not planning.
            deferred_ids.update(row.id for row in inventory)
            deferred_asset_ids.add(asset.id)
            continue

        asset_inventory_tasks = [
            task
            for task in tasks
            if task.kind == "inventory"
            and isinstance(task.params, dict)
            and task.params.get("asset_id") == asset.id
        ]
        if any(task.status != COMPLETED for task in asset_inventory_tasks):
            # Do not plan against a partially collected or failed inventory run.
            deferred_ids.update(row.id for row in inventory)
            deferred_asset_ids.add(asset.id)
            continue
        inventory_task_ids = [
            task.id
            for task in asset_inventory_tasks
        ]
        brief_tasks = [
            task
            for task in tasks
            if task.kind == "research_brief"
            and isinstance(task.params, dict)
            and task.params.get("asset_id") == asset.id
        ]
        brief = brief_tasks[0] if brief_tasks else None
        if brief is not None and brief.status in {"failed", "cancelled"}:
            deferred_ids.update(row.id for row in inventory)
            deferred_asset_ids.add(asset.id)
            continue
        review_tasks = {
            int(task.title.rsplit("#", 1)[1]): task
            for task in tasks
            if task.kind == "hypothesis_review"
            and task.title.startswith(
                f"Review endpoint inventory observation for asset #{asset.id}, observation #"
            )
            and task.title.rsplit("#", 1)[-1].isdigit()
        }
        plan = _AssetPlan(
            asset=asset,
            observations=inventory,
            inventory_task_ids=inventory_task_ids,
            existing_brief=brief,
            existing_generation=generation,
            existing_reviews={
                row.id: review_tasks[row.id]
                for row in inventory
                if row.id in review_tasks
            },
        )
        plans.append(plan)

    created: list[int] = []
    existing: list[int] = []
    current_count = _task_count(session, investigation_id)
    max_tasks = (
        investigation.max_tasks
        if investigation.max_tasks is not None
        else MAX_TASKS_PER_INVESTIGATION
    )
    max_llm_calls = (
        investigation.max_llm_calls
        if investigation.max_llm_calls is not None
        else MAX_LLM_CALLS_PER_INVESTIGATION
    )
    llm_count = sum(1 for task in tasks if task.kind == "hypothesis_generation")
    budget_detail: str | None = None

    for plan in plans:
        missing_reviews = [
            row for row in plan.observations if row.id not in plan.existing_reviews
        ]
        missing_reviews.sort(
            key=lambda row: (_observation_priority(row)[0], row.id)
        )
        needs_brief = plan.existing_brief is None and plan.existing_generation is None
        needs_generation = plan.existing_generation is None
        required_slots = len(missing_reviews) + int(needs_generation) + int(needs_brief)
        if required_slots == 0:
            if plan.existing_brief:
                existing.append(plan.existing_brief.id)
            if plan.existing_generation:
                existing.append(plan.existing_generation.id)
            existing.extend(task.id for task in plan.existing_reviews.values())
            continue

        if current_count + required_slots > max_tasks:
            deferred_ids.update(row.id for row in plan.observations)
            deferred_asset_ids.add(plan.asset.id)
            budget_detail = (
                f"Investigation {investigation_id} task budget exhausted: "
                f"needs {required_slots} task slot(s), has "
                f"{max(0, max_tasks - current_count)} remaining"
            )
            continue
        if needs_generation and llm_count >= max_llm_calls:
            deferred_ids.update(row.id for row in plan.observations)
            deferred_asset_ids.add(plan.asset.id)
            budget_detail = (
                f"Investigation {investigation_id} LLM-call budget exhausted: "
                f"{llm_count} of {max_llm_calls} hypothesis_generation tasks recorded"
            )
            continue

        generation = plan.existing_generation
        brief = plan.existing_brief
        if needs_brief:
            brief, was_created = _create_or_reuse_task(
                session,
                dedupe_key=f"inventory_research:v1:brief:{plan.asset.id}",
                investigation_id=investigation_id,
                kind="research_brief",
                title=f"Build offline researcher brief for asset #{plan.asset.id}",
                params={"asset_id": plan.asset.id},
                depends_on=plan.inventory_task_ids,
            )
            (created if was_created else existing).append(brief.id)
            current_count += int(was_created)
        elif brief is not None:
            existing.append(brief.id)

        if generation is None:
            generation, was_created = _create_or_reuse_task(
                session,
                dedupe_key=f"inventory_research:v1:generation:{plan.asset.id}",
                investigation_id=investigation_id,
                kind="hypothesis_generation",
                title=f"Generate hypotheses from endpoint inventory for asset #{plan.asset.id}",
                params={"asset_id": plan.asset.id},
                depends_on=([brief.id] if brief is not None else plan.inventory_task_ids),
            )
            (created if was_created else existing).append(generation.id)
            current_count += int(was_created)
            llm_count += int(was_created)
        else:
            existing.append(generation.id)

        for observation in missing_reviews:
            review, was_created = _create_or_reuse_task(
                session,
                dedupe_key=(
                    f"inventory_research:v1:review:{plan.asset.id}:{observation.id}"
                ),
                investigation_id=investigation_id,
                kind="hypothesis_review",
                title=(
                    "Review endpoint inventory observation for "
                    f"asset #{plan.asset.id}, observation #{observation.id}"
                ),
                depends_on=[generation.id],
            )
            (created if was_created else existing).append(review.id)
            current_count += int(was_created)
            if was_created:
                record_task_observation_links(
                    review,
                    session,
                    observation_ids=[observation.id],
                    role="input",
                )
        existing.extend(task.id for task in plan.existing_reviews.values())

    return InventoryPlanningReport(
        created_task_ids=tuple(created),
        existing_task_ids=tuple(existing),
        skipped_observation_ids=tuple(sorted(set(skipped_ids))),
        redundant_observation_ids=tuple(sorted(set(redundant_ids))),
        deferred_observation_ids=tuple(sorted(deferred_ids)),
        deferred_asset_ids=tuple(sorted(deferred_asset_ids)),
        budget_exhausted=budget_detail is not None,
        budget_detail=budget_detail,
    )


def preview_inventory_research_tasks(
    investigation_id: int,
    session: Session,
) -> InventoryPlanningReport:
    """Return the inventory task plan without flushing or changing session state."""
    with session.no_autoflush:
        investigation = session.get(Investigation, investigation_id)
        if investigation is None:
            raise LookupError(f"Investigation {investigation_id} does not exist")
        policy = ScopePolicy(
            investigation.program.authorized_scope,
            investigation.program.excluded_scope,
        )
        assets = session.scalars(
            select(Asset)
            .where(Asset.investigation_id == investigation_id)
            .order_by(Asset.id)
        ).all()
        observations = session.scalars(
            select(Observation)
            .join(Asset, Observation.asset_id == Asset.id)
            .where(
                Asset.investigation_id == investigation_id,
                Observation.observation_type == "endpoint_inventory",
            )
            .order_by(Observation.asset_id, Observation.id)
        ).all()
        tasks = session.scalars(
            select(Task)
            .where(Task.investigation_id == investigation_id)
            .order_by(Task.id)
        ).all()

    rows_by_asset: dict[int, list[Observation]] = {}
    for row in observations:
        rows_by_asset.setdefault(row.asset_id, []).append(row)

    current_count = len(tasks)
    llm_count = sum(task.kind == "hypothesis_generation" for task in tasks)
    max_tasks = (
        investigation.max_tasks
        if investigation.max_tasks is not None
        else MAX_TASKS_PER_INVESTIGATION
    )
    max_llm_calls = (
        investigation.max_llm_calls
        if investigation.max_llm_calls is not None
        else MAX_LLM_CALLS_PER_INVESTIGATION
    )
    proposals: list[InventoryTaskProposal] = []
    skipped: list[int] = []
    redundant: list[int] = []
    deferred: set[int] = set()
    deferred_assets: set[int] = set()
    budget_detail: str | None = None

    for asset in assets:
        rows = rows_by_asset.get(asset.id, [])
        if not rows:
            continue
        if not policy.is_authorized(asset.hostname) or not all(
            _eligible_inventory_observation(asset, row, policy) for row in rows
        ):
            skipped.extend(row.id for row in rows)
            continue
        rows, duplicate_ids = _unique_endpoint_observations(rows)
        redundant.extend(duplicate_ids)

        inventory_tasks = [
            task
            for task in tasks
            if task.kind == "inventory"
            and isinstance(task.params, dict)
            and task.params.get("asset_id") == asset.id
        ]
        if any(task.status != COMPLETED for task in inventory_tasks):
            deferred.update(row.id for row in rows)
            deferred_assets.add(asset.id)
            continue
        generation = next(
            (
                task
                for task in tasks
                if task.kind == "hypothesis_generation"
                and isinstance(task.params, dict)
                and task.params.get("asset_id") == asset.id
            ),
            None,
        )
        brief = next(
            (
                task
                for task in tasks
                if task.kind == "research_brief"
                and isinstance(task.params, dict)
                and task.params.get("asset_id") == asset.id
            ),
            None,
        )
        if (generation and generation.status in {"failed", "cancelled"}) or (
            brief and brief.status in {"failed", "cancelled"}
        ):
            deferred.update(row.id for row in rows)
            deferred_assets.add(asset.id)
            continue

        review_prefix = (
            f"Review endpoint inventory observation for asset #{asset.id}, observation #"
        )
        review_ids = {
            int(task.title.rsplit("#", 1)[-1])
            for task in tasks
            if task.kind == "hypothesis_review"
            and task.title.startswith(review_prefix)
            and task.title.rsplit("#", 1)[-1].isdigit()
        }
        missing_reviews = [row for row in rows if row.id not in review_ids]
        missing_reviews.sort(
            key=lambda row: (_observation_priority(row)[0], row.id)
        )
        needs_brief = brief is None and generation is None
        needs_generation = generation is None
        required_slots = len(missing_reviews) + int(needs_generation) + int(needs_brief)
        if current_count + required_slots > max_tasks:
            deferred.update(row.id for row in rows)
            deferred_assets.add(asset.id)
            budget_detail = (
                f"Investigation {investigation_id} task budget exhausted: "
                f"needs {required_slots} task slot(s), has "
                f"{max(0, max_tasks - current_count)} remaining"
            )
            continue
        if needs_generation and llm_count >= max_llm_calls:
            deferred.update(row.id for row in rows)
            deferred_assets.add(asset.id)
            budget_detail = (
                f"Investigation {investigation_id} LLM-call budget exhausted: "
                f"{llm_count} of {max_llm_calls} hypothesis_generation tasks recorded"
            )
            continue

        inventory_deps = tuple(task.id for task in inventory_tasks)
        if needs_brief:
            brief_title = f"Build offline researcher brief for asset #{asset.id}"
            proposals.append(
                InventoryTaskProposal(
                    "research_brief", brief_title, asset.id, depends_on=inventory_deps
                )
            )
            brief_dependency: tuple[int | str, ...] = ("research_brief",)
        elif brief is not None:
            brief_dependency = (brief.id,)
        else:
            brief_dependency = inventory_deps

        if needs_generation:
            generation_title = (
                f"Generate hypotheses from endpoint inventory for asset #{asset.id}"
            )
            proposals.append(
                InventoryTaskProposal(
                    "hypothesis_generation",
                    generation_title,
                    asset.id,
                    depends_on=brief_dependency,
                )
            )
            generation_dependency: tuple[int | str, ...] = ("hypothesis_generation",)
        else:
            generation_dependency = (generation.id,)

        proposals.extend(
            InventoryTaskProposal(
                "hypothesis_review",
                (
                    "Review endpoint inventory observation for "
                    f"asset #{asset.id}, observation #{row.id}"
                ),
                asset.id,
                observation_id=row.id,
                depends_on=generation_dependency,
                priority_rank=_observation_priority(row)[0],
                priority_reason=_observation_priority(row)[1],
            )
            for row in missing_reviews
        )
        current_count += required_slots
        llm_count += int(needs_generation)

    return InventoryPlanningReport(
        proposed_tasks=tuple(proposals),
        skipped_observation_ids=tuple(sorted(set(skipped))),
        redundant_observation_ids=tuple(sorted(set(redundant))),
        deferred_observation_ids=tuple(sorted(deferred)),
        deferred_asset_ids=tuple(sorted(deferred_assets)),
        budget_exhausted=budget_detail is not None,
        budget_detail=budget_detail,
    )
