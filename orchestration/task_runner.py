"""Run exactly one operator-named task by dispatching on its kind.

``run_task`` is the only place a ``Task`` turns into work, and it adds no work of
its own: each dispatchable kind maps to one existing, already-tested function,
called with the task's stored target ids plus the inputs the operator passes in.

* ``recon`` -> :func:`workers.recon.passive_discover`
* ``inventory`` -> :func:`verification.endpoint_inventory_collector.collect_seed_inventory`
* ``research_brief`` -> :func:`intelligence.research_workflow.build_researcher_brief`
* ``hypothesis_generation`` -> :func:`intelligence.hypothesis_generation.generate_hypotheses`
* ``verification`` -> :func:`verification.run_hypothesis_verification.run_hypothesis_verification`

The rules this module does not bend:

* **No scope of its own.** ``authorize`` is a required operator input for every
  kind that can make a request, and it is handed unchanged to the existing
  function, which pins through the gateway. Nothing here builds, widens, or
  stores an authorizer.
* **The lab opt-in is never stored.** ``allow_private_network`` comes only from
  the caller, on every call, and is passed straight through; the existing
  functions decide which transport that selects.
* **No stored credentials.** A verification plan (which may carry request
  headers) is an operator input for this call only and never reaches a row.
* **Refuse before starting.** A task that is not pending, has an unmet
  dependency, has no dispatcher, or lacks a required input raises
  :class:`TaskNotRunnable` and is left exactly as it was.
* **A failure leaves no partial work.** The dispatch runs inside a savepoint
  (``begin_nested``, not a commit): if it raises, everything it wrote is rolled
  back, the task is marked ``failed`` with a ``dispatch_failed`` event carrying
  the error, and the exception is re-raised.
* **Never a status outside the task.** ``Hypothesis.status`` stays the promotion
  gate's alone, and task status changes only through ``start_task`` and
  ``complete_task``. Flush only; the caller owns the transaction.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Asset, Investigation, Observation, Program, Task, TaskObservation
from gateway.dns_pin import URLAuthorizer
from gateway.rate_limiter import RateLimiter
from gateway.scope_policy import ScopePolicy
from intelligence.hypothesis_generation import generate_hypotheses
from intelligence.research_workflow import build_researcher_brief
from verification.endpoint_inventory_collector import collect_seed_inventory
from verification.investigation_tasks import (
    PENDING,
    append_task_event,
    complete_task,
    start_task,
    unmet_dependencies,
)
from verification.run_hypothesis_verification import (
    VerificationTestPlan,
    run_hypothesis_verification,
)
from workers.recon import passive_discover
from workers.storage import store_observations

DISPATCH_TARGETS = {
    "recon": "passive_discover",
    "inventory": "collect_seed_inventory",
    "research_brief": "build_researcher_brief",
    "hypothesis_generation": "generate_hypotheses",
    "verification": "run_hypothesis_verification",
}
NEEDS_AUTHORIZE = frozenset({"recon", "inventory", "verification"})
ERROR_DETAIL_LIMIT = 500


class TaskNotRunnable(ValueError):
    """Raised, with nothing changed, when a task cannot be dispatched now."""


def record_task_observation_links(
    task: Task,
    session: Session,
    *,
    observation_ids: list[int],
    role: str = "output",
) -> None:
    """Append links only after verifying the task and evidence share ownership."""
    if role not in {"input", "output"}:
        raise ValueError("task observation role must be 'input' or 'output'")
    if not observation_ids:
        return

    unique_ids = set(observation_ids)
    observations_by_id = {
        observation_id: investigation_id
        for observation_id, investigation_id in session.execute(
            select(Observation.id, Asset.investigation_id)
            .join(Asset, Asset.id == Observation.asset_id)
            .where(Observation.id.in_(unique_ids))
        )
    }
    if set(observations_by_id) != unique_ids:
        missing_ids = sorted(unique_ids - set(observations_by_id))
        raise ValueError(
            f"Cannot link missing observations to task {task.id}: {missing_ids!r}"
        )
    wrong_investigation_ids = sorted(
        observation_id
        for observation_id, investigation_id in observations_by_id.items()
        if investigation_id != task.investigation_id
    )
    if wrong_investigation_ids:
        raise ValueError(
            f"Task {task.id} cannot link observations from another investigation: "
            f"{wrong_investigation_ids!r}"
        )

    for observation_id in sorted(unique_ids):
        existing = session.scalar(
            select(TaskObservation).where(
                TaskObservation.task_id == task.id,
                TaskObservation.observation_id == observation_id,
                TaskObservation.role == role,
            )
        )
        if existing is not None:
            continue
        session.add(
            TaskObservation(
                task_id=task.id,
                observation_id=observation_id,
                role=role,
            )
        )
    session.flush()


def run_task(
    task_id: int,
    session: Session,
    *,
    authorize: URLAuthorizer | None = None,
    allow_private_network: bool = False,
    verification_plan: VerificationTestPlan | None = None,
    approve_verification: bool = False,
    commit_before_dispatch: bool = False,
) -> None:
    """Dispatch one pending task to its existing function and record the outcome.

    Raises :class:`LookupError` for a missing task and :class:`TaskNotRunnable`
    when it cannot run now (both before anything is written). Anything the
    dispatched function raises is recorded as a ``failed`` task and re-raised.
    Does not commit unless ``commit_before_dispatch=True``. That explicit mode
    commits the running status and its start event before any network-facing
    dispatch, allowing operator recovery to detect interruption. It also commits
    all other pending work in the caller's session.
    """
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError(f"Task {task_id} does not exist")
    _refuse_unless_runnable(
        task,
        session,
        authorize,
        verification_plan,
        approve_verification,
        allow_private_network,
    )

    effective_authorize = authorize
    if task.kind in NEEDS_AUTHORIZE:
        effective_authorize = _current_scope_authorizer(task, session, authorize)
        _refuse_if_current_scope_denies(
            task, session, effective_authorize, verification_plan
        )

    start_task(task.id, session)
    append_task_event(
        task.id,
        session,
        event_type="dispatched",
        detail={
            "target": DISPATCH_TARGETS[task.kind],
            "allow_private_network": allow_private_network,
        },
    )
    if commit_before_dispatch:
        session.commit()

    try:
        if task.kind in NEEDS_AUTHORIZE:
            effective_authorize = _current_scope_authorizer(
                task, session, authorize
            )
            _refuse_if_current_scope_denies(
                task, session, effective_authorize, verification_plan
            )
        with session.begin_nested():
            summary = _dispatch(
                task, session, effective_authorize, allow_private_network,
                verification_plan
            )
    except Exception as error:  # noqa: BLE001 - record anything the target raised
        if task.kind == "verification":
            message = "Verification dispatch failed; sensitive request details suppressed"
        else:
            message = f"{type(error).__name__}: {error}"[:ERROR_DETAIL_LIMIT]
        append_task_event(
            task.id,
            session,
            event_type="dispatch_failed",
            detail={"error_type": type(error).__name__, "error": message},
        )
        complete_task(task.id, session, final_status="failed", result_summary=message)
        if task.kind == "verification":
            raise RuntimeError(message) from None
        raise

    complete_task(task.id, session, final_status="completed", result_summary=summary)


def _refuse_unless_runnable(
    task: Task,
    session: Session,
    authorize: URLAuthorizer | None,
    verification_plan: VerificationTestPlan | None,
    approve_verification: bool,
    allow_private_network: bool,
) -> None:
    if task.status != PENDING:
        raise TaskNotRunnable(f"Task {task.id} is {task.status!r}, not {PENDING!r}")
    unmet = unmet_dependencies(task, session)
    if unmet:
        raise TaskNotRunnable(f"Task {task.id} depends on unfinished tasks {unmet!r}")
    if task.kind not in DISPATCH_TARGETS:
        raise TaskNotRunnable(
            f"Task {task.id} is a {task.kind!r} task, which has no dispatcher; "
            "the operator does it and records the outcome with complete_task"
        )
    if task.kind in NEEDS_AUTHORIZE and authorize is None:
        raise TaskNotRunnable(f"Task {task.id} needs an operator-supplied authorize")
    if task.kind == "verification" and verification_plan is None:
        raise TaskNotRunnable(
            f"Task {task.id} needs an operator-supplied verification_plan"
        )
    if task.kind == "verification" and (
        getattr(verification_plan, "hypothesis_id", None)
        != task.params.get("hypothesis_id")
    ):
        raise TaskNotRunnable(
            f"Task {task.id} needs a verification plan bound to its hypothesis"
        )
    if task.kind == "verification" and not approve_verification:
        raise TaskNotRunnable(
            f"Task {task.id} needs explicit approve_verification=True before network access"
        )
    if task.kind == "verification" and not allow_private_network:
        raise TaskNotRunnable(
            f"Task {task.id} requires explicit --lab approval for the lab-only verifier"
        )


def _current_scope_authorizer(
    task: Task,
    session: Session,
    operator_authorize: URLAuthorizer | None,
) -> URLAuthorizer:
    """Intersect the call-scoped authorizer with freshly loaded program scope."""
    if operator_authorize is None:
        raise TaskNotRunnable(f"Task {task.id} needs an operator-supplied authorize")
    program = session.scalar(
        select(Program)
        .join(Investigation, Investigation.program_id == Program.id)
        .where(Investigation.id == task.investigation_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if program is None:
        raise TaskNotRunnable(f"Task {task.id} has no current program scope")
    policy = ScopePolicy(program.authorized_scope, program.excluded_scope)

    def authorize(url: str) -> bool:
        hostname = urlsplit(url).hostname or ""
        return policy.is_authorized(hostname) and operator_authorize(url)

    return authorize


def _refuse_if_current_scope_denies(
    task: Task,
    session: Session,
    authorize: URLAuthorizer,
    verification_plan: VerificationTestPlan | None,
) -> None:
    """Refuse a now-unauthorized task before marking it running or probing."""
    if task.kind == "inventory":
        if not authorize(task.params["base_url"]):
            raise TaskNotRunnable(
                f"Task {task.id} inventory target is no longer authorized"
            )
    elif task.kind == "recon":
        assets = session.scalars(
            select(Asset)
            .where(Asset.investigation_id == task.investigation_id)
            .order_by(Asset.id)
        ).all()
        if not any(authorize(f"https://{asset.hostname}/") for asset in assets):
            raise TaskNotRunnable(
                f"Task {task.id} has no asset currently authorized for recon"
            )
    elif task.kind == "verification" and verification_plan is not None:
        if any(
            not authorize(url)
            for pair in getattr(verification_plan, "pairs", ())
            for url in (pair.url_a, pair.url_b)
        ):
            raise TaskNotRunnable(
                f"Task {task.id} verification plan contains a target no longer authorized"
            )


def _dispatch(
    task: Task,
    session: Session,
    authorize: URLAuthorizer | None,
    allow_private_network: bool,
    verification_plan: VerificationTestPlan | None,
) -> str:
    params = task.params

    if task.kind == "inventory":
        observations = collect_seed_inventory(
            params["base_url"],
            authorize,
            session=session,
            asset_id=params["asset_id"],
            allow_private_network=allow_private_network,
        )
        ids = [observation.id for observation in observations]
        record_task_observation_links(task, session, observation_ids=ids)
        return f"stored {len(ids)} endpoint_inventory observations: {ids}"

    if task.kind == "recon":
        investigation = task.investigation
        program = investigation.program
        policy = ScopePolicy(program.authorized_scope, program.excluded_scope)
        assets = session.scalars(
            select(Asset)
            .where(Asset.investigation_id == investigation.id)
            .order_by(Asset.id)
        ).all()
        limiter = RateLimiter(program.rate_limit)
        stored = 0
        output_ids: list[int] = []
        for asset in assets:
            hostname_url = f"https://{asset.hostname}/"
            if not policy.is_authorized(asset.hostname) or not authorize(hostname_url):
                continue
            existing_ids = set(
                session.scalars(
                    select(Observation.id).where(Observation.asset_id == asset.id)
                )
            )
            discovered = passive_discover(asset.hostname, policy, limiter)
            store_observations(
                investigation.id,
                asset.hostname,
                list(discovered),
                session,
            )
            output_ids.extend(
                session.scalars(
                    select(Observation.id)
                    .where(Observation.asset_id == asset.id)
                    .where(Observation.id.not_in(existing_ids))
                )
            )
            stored += len(discovered)
        record_task_observation_links(task, session, observation_ids=output_ids)
        return f"stored {stored} passive DNS observation(s) across {len(assets)} asset(s)"

    if task.kind == "research_brief":
        brief = build_researcher_brief(params["asset_id"], session)
        record_task_observation_links(
            task,
            session,
            observation_ids=[
                observation.observation_id for observation in brief.observations
            ],
            role="input",
        )
        hypothesis_ids = sorted({candidate.hypothesis_id for candidate in brief.candidates})
        return (
            f"built offline brief for asset #{brief.asset_id}: "
            f"{len(brief.observations)} observation(s), "
            f"{len(hypothesis_ids)} unverified candidate hypothesis(es) {hypothesis_ids}"
        )

    if task.kind == "hypothesis_generation":
        input_observation_ids = list(
            session.scalars(
                select(Observation.id)
                .where(Observation.asset_id == params["asset_id"])
                .order_by(Observation.id)
            )
        )
        hypotheses = generate_hypotheses(params["asset_id"], session)
        record_task_observation_links(
            task,
            session,
            observation_ids=input_observation_ids,
            role="input",
        )
        ids = [hypothesis.id for hypothesis in hypotheses]
        return f"added {len(ids)} unverified hypotheses: {ids}"

    result = run_hypothesis_verification(
        params["hypothesis_id"],
        verification_plan,
        allow_private_network=allow_private_network,
        authorize=authorize,
        session=session,
    )
    output_observation_ids = [
        outcome.observation.id
        for outcome in result.outcomes
        if isinstance(getattr(outcome, "observation", None), Observation)
    ]
    record_task_observation_links(
        task,
        session,
        observation_ids=output_observation_ids,
        role="output",
    )
    ids = [outcome.verdict.id for outcome in result.outcomes]
    return (
        f"stored {len(ids)} verdicts: {ids} "
        f"({len(result.control_outcomes)} control, "
        f"{len(result.primary_outcomes)} claim)"
    )
