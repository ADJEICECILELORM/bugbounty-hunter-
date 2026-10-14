"""Tests for the live seed-inventory collector.

The collector is the only place in this slice that turns the pure candidate list
into requests, so the tests are about routing, not about the wire: the guarded
transports are injected as doubles, and the two cases that do call the real
public transport use a loopback literal, which ``gateway.dns_pin`` rejects before
any socket can exist. What is asserted is which transport runs, with what, in
what order - plus that nothing is ever committed, that no credential can reach
evidence, and that the module has no second network path to route through.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Investigation, Observation, Program
from gateway.dns_pin import TargetRejected
from gateway.lab_mode import pin_lab_url as real_pin_lab_url
from verification import endpoint_inventory_collector as collector
from verification.endpoint_inventory import SEED_PATHS, seed_paths
from verification.endpoint_inventory_collector import collect_seed_inventory
from verification.evidence import INVENTORY_OBSERVATION_TYPE
from verification.http_probe import ProbeResult

REPO_ROOT = Path(__file__).parents[1]
MODULE_PATH = REPO_ROOT / "verification" / "endpoint_inventory_collector.py"

# A loopback literal: never a public address, so the public transport refuses it
# without resolving anything and without opening a socket.
BASE = "http://127.0.0.1:3000"


@pytest.fixture()
def session() -> Any:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as active_session:
        yield active_session


def seed_asset(session: Session) -> Asset:
    program = Program(
        name="Local lab",
        authorized_scope=["127.0.0.1"],
        excluded_scope=[],
        rate_limit=30,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="127.0.0.1")
    session.add(asset)
    session.flush()
    return asset


def probe_result(url: str) -> ProbeResult:
    return ProbeResult(
        url=url,
        status_code=200,
        headers={"content-type": "application/json"},
        response_time_ms=3.0,
        content_length=42,
        body_sha256="c" * 64,
    )


class RecordingTransport:
    """A transport double that records the URLs it was asked to probe."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, url: str) -> ProbeResult:
        self.calls.append(url)
        return probe_result(url)


class RecordingAuthorizer:
    """Approve exactly ``approved`` and record every URL offered."""

    def __init__(self, approved: set[str] | None = None) -> None:
        self.approved = approved if approved is not None else set()
        self.seen: list[str] = []

    def __call__(self, url: str) -> bool:
        self.seen.append(url)
        return url in self.approved


# --- the fail-closed and public paths ----------------------------------------


def test_an_authorizer_that_rejects_everything_makes_no_request(
    session: Session,
) -> None:
    asset = seed_asset(session)
    transport = RecordingTransport()
    authorize = RecordingAuthorizer()

    stored = collect_seed_inventory(
        BASE, authorize, session=session, asset_id=asset.id, transport=transport
    )

    assert stored == []
    assert transport.calls == []
    assert authorize.seen == seed_paths(BASE)
    assert session.scalars(select(Observation)).all() == []


def test_an_empty_result_is_an_empty_inventory_not_a_swallowed_error(
    session: Session,
) -> None:
    """``[]`` means "policy authorized nothing" - never "the run failed quietly".

    A run that failed and a run that found nothing are different outcomes, and a
    caller cannot tell them apart from an empty list, so every failure has to
    reach it instead of being reported as "no endpoints".
    """
    asset = seed_asset(session)
    candidates = seed_paths(BASE)

    def explode(url: str) -> ProbeResult:
        raise TargetRejected("the transport gave up")

    # An authorized candidate whose probe fails raises; it is not an empty list.
    with pytest.raises(TargetRejected, match="gave up"):
        collect_seed_inventory(
            BASE,
            RecordingAuthorizer(set(candidates)),
            session=session,
            asset_id=asset.id,
            transport=explode,
        )
    assert session.scalars(select(Observation)).all() == []

    # A malformed base and an unknown asset are errors too, not empty inventories.
    with pytest.raises(ValueError, match="must be http or https"):
        collect_seed_inventory(
            "ftp://127.0.0.1",
            RecordingAuthorizer(set(candidates)),
            session=session,
            asset_id=asset.id,
        )
    with pytest.raises(LookupError, match="Asset 999 does not exist"):
        collect_seed_inventory(
            BASE,
            RecordingAuthorizer(set(candidates)),
            session=session,
            asset_id=999,
            transport=RecordingTransport(),
        )
    assert session.scalars(select(Observation)).all() == []

    # The one way to get [] is for the authorizer to approve none of the nine.
    authorize = RecordingAuthorizer()
    assert (
        collect_seed_inventory(
            BASE,
            authorize,
            session=session,
            asset_id=asset.id,
            transport=RecordingTransport(),
        )
        == []
    )
    assert authorize.seen == candidates


def test_the_collector_has_no_exception_handler_to_swallow_a_failure() -> None:
    """The structural half of that guarantee: nothing here can catch anything.

    With no ``try``/``except``/``finally`` in the module there is no code path
    that could turn an exception into an empty list or a partial result, which is
    what makes the behavioural test above hold for every future failure mode
    rather than only for the ones already invented.
    """
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert [node for node in ast.walk(tree) if isinstance(node, ast.Try)] == []
    assert "contextlib" not in source
    # Exactly one empty return, and it is the empty-candidate guard.
    assert source.count("return []") == 1


def test_only_approved_candidates_are_probed_in_seed_order(session: Session) -> None:
    asset = seed_asset(session)
    candidates = seed_paths(BASE)
    approved = [candidates[1], candidates[6]]
    transport = RecordingTransport()
    authorize = RecordingAuthorizer(set(approved))

    stored = collect_seed_inventory(
        BASE, authorize, session=session, asset_id=asset.id, transport=transport
    )

    assert transport.calls == approved
    assert authorize.seen == candidates
    assert [observation.data["url"] for observation in stored] == approved


def test_a_probe_is_stored_as_asset_level_inventory_context(session: Session) -> None:
    asset = seed_asset(session)
    candidates = seed_paths(BASE)

    stored = collect_seed_inventory(
        BASE,
        RecordingAuthorizer({candidates[1]}),
        session=session,
        asset_id=asset.id,
        transport=RecordingTransport(),
    )

    assert len(stored) == 1
    observation = session.scalars(select(Observation)).all()[0]
    assert observation is stored[0]
    assert observation.observation_type == INVENTORY_OBSERVATION_TYPE
    assert observation.asset_id == asset.id
    assert observation.hypothesis_id is None
    assert observation.data["url"] == candidates[1]
    assert set(observation.data) == {
        "url",
        "status_code",
        "headers",
        "response_time_ms",
        "content_length",
        "body_sha256",
    }


def test_the_collector_never_commits_the_session(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session)
    candidates = seed_paths(BASE)

    def refuse() -> None:
        raise AssertionError("the collector must not commit")

    monkeypatch.setattr(session, "commit", refuse)

    stored = collect_seed_inventory(
        BASE,
        RecordingAuthorizer({candidates[1]}),
        session=session,
        asset_id=asset.id,
        transport=RecordingTransport(),
    )

    # The row is visible because it was flushed ...
    assert session.scalars(select(Observation)).all() == stored

    # ... and it disappears on rollback, because it was never committed.
    session.rollback()
    assert session.scalars(select(Observation)).all() == []


def test_a_partial_run_is_left_to_the_caller_to_roll_back(session: Session) -> None:
    asset = seed_asset(session)
    candidates = seed_paths(BASE)
    calls: list[str] = []

    def failing(url: str) -> ProbeResult:
        calls.append(url)
        if len(calls) == 2:
            raise TargetRejected("the transport gave up")
        return probe_result(url)

    with pytest.raises(TargetRejected, match="gave up"):
        collect_seed_inventory(
            BASE,
            RecordingAuthorizer(set(candidates)),
            session=session,
            asset_id=asset.id,
            transport=failing,
        )

    assert calls == candidates[:2]
    assert len(session.scalars(select(Observation)).all()) == 1

    session.rollback()
    assert session.scalars(select(Observation)).all() == []


def test_the_public_path_refuses_a_private_target_before_any_request(
    session: Session,
) -> None:
    asset = seed_asset(session)

    with pytest.raises(TargetRejected, match="non-public"):
        collect_seed_inventory(
            BASE,
            RecordingAuthorizer(set(seed_paths(BASE))),
            session=session,
            asset_id=asset.id,
        )

    assert session.scalars(select(Observation)).all() == []


# --- the lab path ------------------------------------------------------------


def test_the_lab_path_pins_every_candidate_before_the_first_probe(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session)
    candidates = seed_paths(BASE)
    order: list[str] = []
    pinned: list[Any] = []

    def spy_pin(
        url: str,
        *,
        allow_private_network: bool,
        authorize: Any,
        resolver: Any = None,
    ) -> Any:
        order.append(f"pin:{url}")
        return real_pin_lab_url(
            url,
            allow_private_network=allow_private_network,
            authorize=authorize,
            resolver=resolver,
        )

    def spy_probe(target: Any, **kwargs: Any) -> ProbeResult:
        assert kwargs["allow_private_network"] is True
        order.append("probe")
        pinned.append(target)
        return probe_result(target.url)

    def refuse_public(url: str, **kwargs: Any) -> ProbeResult:
        raise AssertionError("the public transport must not run in lab mode")

    monkeypatch.setattr(collector, "pin_lab_url", spy_pin)
    monkeypatch.setattr(collector, "probe_lab_target", spy_probe)
    monkeypatch.setattr(collector, "probe_endpoint", refuse_public)

    stored = collect_seed_inventory(
        BASE,
        RecordingAuthorizer(set(candidates)),
        session=session,
        asset_id=asset.id,
        allow_private_network=True,
    )

    # Every candidate is pinned before the first request is sent.
    assert order == [f"pin:{url}" for url in candidates] + ["probe"] * len(candidates)
    assert len(pinned) == len(candidates)
    assert all(target.is_lab_target is True for target in pinned)
    assert [observation.data["url"] for observation in stored] == [
        target.url for target in pinned
    ]


def test_the_lab_transport_is_unreachable_without_the_explicit_opt_in(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = seed_asset(session)

    def refuse_lab(target: Any, **kwargs: Any) -> ProbeResult:
        raise AssertionError("the lab transport must require the opt-in")

    monkeypatch.setattr(collector, "probe_lab_target", refuse_lab)

    with pytest.raises(TargetRejected):
        collect_seed_inventory(
            BASE,
            RecordingAuthorizer(set(seed_paths(BASE))),
            session=session,
            asset_id=asset.id,
        )

    assert session.scalars(select(Observation)).all() == []


# --- the static guarantees ---------------------------------------------------

ALLOWED_IMPORTS = {
    "__future__",
    "collections.abc",
    "sqlalchemy.orm",
    "data.models",
    "gateway.dns_pin",
    "gateway.lab_mode",
    "verification.endpoint_inventory",
    "verification.evidence",
    "verification.http_probe",
}


def test_the_collector_has_no_second_network_path_and_never_commits() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    # The allowlist is the real guarantee: no HTTP client, socket, subprocess or
    # shell is imported, so the module has nothing else to send a request with.
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert imported - ALLOWED_IMPORTS == set()

    for forbidden in (
        "import requests",
        ".commit(",
        "allow_redirects",
        "extra_headers",
        "Authorization",
        "Cookie",
        "os.environ",
    ):
        assert forbidden not in source, forbidden

    assert "def collect_seed_inventory(" in source


def test_the_collector_exposes_exactly_this_entry_point() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    functions = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    assert functions == [
        "_public_transport",
        "_lab_transport",
        "collect_seed_inventory",
    ]
    assert len(SEED_PATHS) == 9

