import ipaddress

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Hypothesis, Investigation, Observation, Program
from verification.diff_check import DiffResult, build_diff_result
from verification.evidence import (
    INVENTORY_OBSERVATION_TYPE,
    diff_data,
    store_diff_evidence,
    store_inventory_evidence,
)
from verification.http_probe import ProbeResult


def test_store_diff_evidence_links_hypothesis_and_allowlists_data() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe_a = ProbeResult(
        url="https://api.example.test/account",
        status_code=200,
        headers={"content-type": "application/json"},
        response_time_ms=12.5,
        content_length=27,
        body_sha256="a" * 64,
    )
    probe_b = ProbeResult(
        url="https://api.example.test/account",
        status_code=200,
        headers={"content-type": "application/json"},
        response_time_ms=11.0,
        content_length=35,
        body_sha256="b" * 64,
    )
    diff_result = DiffResult(
        url_a=probe_a.url,
        url_b=probe_b.url,
        status_match=True,
        status_a=200,
        status_b=200,
        body_match=False,
        content_length_delta=8,
        header_differences={"x-result": ("first", "second")},
        probe_a=probe_a,
        probe_b=probe_b,
    )

    with Session(engine) as session:
        program = Program(
            name="Example Program",
            authorized_scope=["api.example.test"],
            excluded_scope=[],
            rate_limit=30,
        )
        investigation = Investigation(program=program, status="running")
        asset = Asset(investigation=investigation, hostname="api.example.test")
        hypothesis = Hypothesis(
            asset=asset,
            category="access_control",
            description="Responses may vary by account authorization.",
        )
        session.add(hypothesis)
        session.flush()

        observation = store_diff_evidence(hypothesis.id, diff_result, session)
        loaded_observation = session.scalar(
            select(Observation).where(Observation.id == observation.id)
        )

        assert loaded_observation is not None
        assert loaded_observation.observation_type == "diff_check"
        assert loaded_observation.hypothesis_id == hypothesis.id
        assert loaded_observation.asset_id == hypothesis.asset_id == asset.id
        assert loaded_observation.hypothesis is hypothesis
        assert loaded_observation in hypothesis.observations
        assert loaded_observation in asset.observations
        assert hypothesis.status == "unverified"
        assert set(loaded_observation.data) == {
            "status_match",
            "status_a",
            "status_b",
            "body_match",
            "content_length_delta",
            "header_differences",
            "probe_a",
            "probe_b",
        }
        assert loaded_observation.data["header_differences"] == {
            "x-result": ["first", "second"]
        }
        assert set(loaded_observation.data["probe_a"]) == {
            "url",
            "status_code",
            "headers",
            "response_time_ms",
            "content_length",
            "body_sha256",
        }
        assert loaded_observation.data["probe_a"]["body_sha256"] == "a" * 64
        assert session.in_transaction()

    engine.dispose()


def test_observation_without_hypothesis_remains_supported() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")

    with Session(engine) as session:
        program = Program(
            name="Example Program",
            authorized_scope=["api.example.test"],
            excluded_scope=[],
            rate_limit=30,
        )
        investigation = Investigation(program=program)
        asset = Asset(investigation=investigation, hostname="api.example.test")
        observation = Observation(
            asset=asset,
            observation_type="dns_record",
            data={"record_type": "A", "value": "93.184.216.34"},
        )
        session.add(observation)
        session.flush()

        loaded_observation = session.scalar(select(Observation))
        assert loaded_observation is not None
        assert loaded_observation.hypothesis_id is None
        assert loaded_observation.hypothesis is None

    engine.dispose()


def test_store_inventory_evidence_links_the_asset_and_allowlists_the_probe() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe = ProbeResult(
        url="http://127.0.0.1:3000/robots.txt",
        status_code=200,
        headers={"content-type": "text/plain"},
        response_time_ms=2.5,
        content_length=42,
        body_sha256="c" * 64,
    )

    with Session(engine) as session:
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

        observation = store_inventory_evidence(asset.id, probe, session)
        loaded_observation = session.scalar(select(Observation))
        reference = build_diff_result(probe.url, probe.url, probe, probe)

        assert loaded_observation is not None
        assert loaded_observation is observation
        assert loaded_observation.observation_type == INVENTORY_OBSERVATION_TYPE
        assert loaded_observation.asset_id == asset.id
        assert loaded_observation.hypothesis_id is None
        assert loaded_observation.hypothesis is None
        assert loaded_observation in asset.observations
        # The stored mapping is exactly what a comparison stores for one probe,
        # so an inventory row reuses the audited allowlist instead of a new one.
        assert loaded_observation.data == diff_data(reference)["probe_a"]
        assert set(loaded_observation.data) == {
            "url",
            "status_code",
            "headers",
            "response_time_ms",
            "content_length",
            "body_sha256",
        }
        assert loaded_observation.data["body_sha256"] == "c" * 64
        assert session.in_transaction()

    engine.dispose()


def test_store_inventory_evidence_requires_an_existing_asset() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe = ProbeResult(
        url="http://127.0.0.1:3000/robots.txt",
        status_code=200,
        headers={},
        response_time_ms=1.0,
        content_length=0,
        body_sha256="d" * 64,
    )

    with Session(engine) as session:
        with pytest.raises(LookupError, match="Asset 4242 does not exist"):
            store_inventory_evidence(4242, probe, session)

        assert session.scalars(select(Observation)).all() == []

    engine.dispose()