"""Focused tests for the V8.1 grounding and provenance tables.

These cover only the two new models and the constraint that existing tables
keep their exact column sets. They use the same in-memory SQLite bootstrap as
the rest of the test suite and make no network or model calls.
"""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import (
    Asset,
    Hypothesis,
    HypothesisSupportingObservation,
    Investigation,
    Observation,
    ObservationProvenance,
    Program,
)


def _seed_asset(session: Session) -> tuple[Asset, Hypothesis, Observation]:
    program = Program(
        name="Example Program",
        authorized_scope=["*.example.test"],
        excluded_scope=[],
        rate_limit=30,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="api.example.test")
    hypothesis = Hypothesis(
        asset=asset,
        category="access_control",
        description="review /admin for missing auth",
    )
    observation = Observation(
        asset=asset,
        observation_type="dns_record",
        data={"record_type": "A", "value": "93.184.216.34"},
    )
    session.add(program)
    session.flush()
    return asset, hypothesis, observation


def test_new_tables_can_be_created_and_populated() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")

    with Session(engine) as session:
        asset, hypothesis, observation = _seed_asset(session)

        link = HypothesisSupportingObservation(
            hypothesis=hypothesis, observation=observation
        )
        provenance = ObservationProvenance(
            observation=observation,
            collector="recon.passive_discover",
            authorization_snapshot={
                "target": "api.example.test",
                "authorized_scope": ["*.example.test"],
                "excluded_scope": [],
            },
        )
        session.add_all([link, provenance])
        session.commit()

        loaded_link = session.scalar(select(HypothesisSupportingObservation))
        loaded_provenance = session.scalar(select(ObservationProvenance))

        assert loaded_link is not None
        assert loaded_link.hypothesis_id == hypothesis.id
        assert loaded_link.observation_id == observation.id

        assert loaded_provenance is not None
        assert loaded_provenance.observation_id == observation.id
        assert loaded_provenance.collector == "recon.passive_discover"
        assert loaded_provenance.captured_at is None

        # Relationship wiring in both directions, with no deletion cascade.
        assert hypothesis.supporting_observations == [loaded_link]
        assert observation.supporting_hypotheses == [loaded_link]
        assert observation.provenance is loaded_provenance
        assert loaded_provenance.observation is observation

    engine.dispose()


def test_duplicate_hypothesis_observation_link_is_rejected() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")

    with Session(engine) as session:
        _, hypothesis, observation = _seed_asset(session)
        session.add(
            HypothesisSupportingObservation(
                hypothesis=hypothesis, observation=observation
            )
        )
        session.flush()
        session.add(
            HypothesisSupportingObservation(
                hypothesis=hypothesis, observation=observation
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()

    engine.dispose()


def test_existing_hypothesis_and_observation_columns_unchanged() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    columns = inspect(engine)

    hypothesis_columns = {c["name"] for c in columns.get_columns("hypotheses")}
    observation_columns = {c["name"] for c in columns.get_columns("observations")}

    assert hypothesis_columns == {
        "id",
        "asset_id",
        "category",
        "description",
        "status",
        "created_at",
    }
    assert observation_columns == {
        "id",
        "asset_id",
        "hypothesis_id",
        "observation_type",
        "data",
        "created_at",
    }

    engine.dispose()


def test_new_relationships_have_no_delete_orphan_cascade() -> None:
    cascades = (
        Hypothesis.supporting_observations.property.cascade,
        Observation.supporting_hypotheses.property.cascade,
        Observation.provenance.property.cascade,
    )
    for cascade in cascades:
        assert "delete" not in cascade
        assert "delete-orphan" not in cascade
