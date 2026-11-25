import ipaddress

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import (
    Asset,
    Hypothesis,
    Investigation,
    Observation,
    ObservationFingerprint,
    Program,
)
from verification.diff_check import DiffResult, build_diff_result
from verification.evidence import (
    INVENTORY_OBSERVATION_TYPE,
    canonical_observation_fingerprint,
    diff_data,
    exact_duplicate_observation_ids,
    store_diff_evidence,
    store_inventory_evidence,
)
from verification.http_probe import ProbeResult


def test_store_diff_evidence_links_hypothesis_and_allowlists_data() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe_a = ProbeResult(
        url="https://operator:url-secret@api.example.test/account?token=query-secret",
        status_code=200,
        headers={
            "content-type": "application/json",
            "Authorization": "Bearer header-secret",
            "X-API-Key": "api-key-secret",
            "x-sensitive-value": "token=header-value-secret",
            "x-result": "first",
        },
        response_time_ms=12.5,
        content_length=27,
        body_sha256="a" * 64,
    )
    probe_b = ProbeResult(
        url="https://operator:url-secret@api.example.test/account?token=query-secret",
        status_code=200,
        headers={"content-type": "application/json", "Authorization": "Bearer second-secret"},
        response_time_ms=11.0,
        content_length=35,
        body_sha256="b" * 64,
    )
    probe_b.headers["x-result"] = "second"
    probe_b.headers["x-sensitive-value"] = "token=second-secret"
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
        serialized = str(loaded_observation.data)
        for secret in (
            "url-secret", "query-secret", "header-secret", "second-secret",
            "api-key-secret", "header-value-secret",
        ):
            assert secret not in serialized
        assert loaded_observation.data["probe_a"]["url"] == (
            "https://api.example.test/account?[REDACTED]"
        )
        assert loaded_observation.data["probe_a"]["headers"] == {
            "content-type": "application/json",
            "x-result": "first",
        }
        assert session.in_transaction()

    engine.dispose()


def test_canonical_observation_fingerprint_is_stable_and_preserves_rows() -> None:
    shared_data = {"url": "https://api.example.test/account", "status_code": 200}
    fingerprint_a = canonical_observation_fingerprint(
        observation_type="endpoint_inventory",
        asset_id=1,
        hypothesis_id=None,
        data=shared_data,
    )
    fingerprint_b = canonical_observation_fingerprint(
        observation_type="endpoint_inventory",
        asset_id=1,
        hypothesis_id=None,
        data={"status_code": 200, "url": "https://api.example.test/account"},
    )
    assert fingerprint_a == fingerprint_b
    assert fingerprint_a != canonical_observation_fingerprint(
        observation_type="endpoint_inventory",
        asset_id=2,
        hypothesis_id=None,
        data=shared_data,
    )
    assert fingerprint_a != canonical_observation_fingerprint(
        observation_type="dns_record",
        asset_id=1,
        hypothesis_id=None,
        data=shared_data,
    )
    assert fingerprint_a != canonical_observation_fingerprint(
        observation_type="endpoint_inventory",
        asset_id=1,
        hypothesis_id=7,
        data=shared_data,
    )

    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        program = Program(
            name="Example Program",
            authorized_scope=["api.example.test"],
            excluded_scope=[],
            rate_limit=30,
        )
        investigation = Investigation(program=program, status="running")
        asset = Asset(investigation=investigation, hostname="api.example.test")
        session.add_all([program, investigation, asset])
        session.flush()

        first = Observation(
            asset_id=asset.id,
            observation_type="endpoint_inventory",
            data=shared_data,
        )
        second = Observation(
            asset_id=asset.id,
            observation_type="endpoint_inventory",
            data=dict(shared_data),
        )
        session.add_all([first, second])
        session.flush()
        assert session.scalar(select(func.count(Observation.id))) == 2
        first_fingerprint = session.get(ObservationFingerprint, first.id)
        second_fingerprint = session.get(ObservationFingerprint, second.id)
        assert first_fingerprint is not None
        assert second_fingerprint is not None
        assert first_fingerprint.fingerprint == second_fingerprint.fingerprint
        assert second_fingerprint.duplicate_of_observation_id == first.id
        assert exact_duplicate_observation_ids(second, session) == (first.id,)
        assert canonical_observation_fingerprint(
            observation_type=first.observation_type,
            asset_id=first.asset_id,
            hypothesis_id=first.hypothesis_id,
            data=first.data,
        ) == canonical_observation_fingerprint(
            observation_type=second.observation_type,
            asset_id=second.asset_id,
            hypothesis_id=second.hypothesis_id,
            data=second.data,
        )

    engine.dispose()


def test_fingerprint_collision_requires_canonical_payload_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        program = Program(
            name="Collision Test",
            authorized_scope=["api.example.test"],
            excluded_scope=[],
            rate_limit=1,
        )
        investigation = Investigation(program=program, status="running")
        asset = Asset(investigation=investigation, hostname="api.example.test")
        first = Observation(
            asset=asset,
            observation_type="endpoint_inventory",
            data={"url": "https://api.example.test/first", "status_code": 200},
        )
        second = Observation(
            asset=asset,
            observation_type="endpoint_inventory",
            data={"url": "https://api.example.test/second", "status_code": 200},
        )
        session.add_all([first, second])
        session.flush()
        second_fingerprint = session.get(ObservationFingerprint, second.id)
        assert second_fingerprint is not None
        first_fingerprint = session.get(ObservationFingerprint, first.id)
        assert first_fingerprint is not None
        connection = session.connection()
        connection.exec_driver_sql("DROP TRIGGER immutable_observation_fingerprints")
        connection.execute(
            ObservationFingerprint.__table__.update()
            .where(ObservationFingerprint.observation_id == second.id)
            .values(fingerprint=first_fingerprint.fingerprint)
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER immutable_observation_fingerprints "
            "BEFORE UPDATE ON observation_fingerprints "
            "BEGIN SELECT RAISE(ABORT, "
            "'historical record immutability: updates are prohibited'); END"
        )
        monkeypatch.setattr(
            "verification.evidence.observation_identity_fingerprint",
            lambda **_kwargs: first_fingerprint.fingerprint,
        )

        assert exact_duplicate_observation_ids(second, session) == ()

    engine.dispose()


def test_diff_data_redacts_query_values_and_fragments() -> None:
    probe_a = ProbeResult(
        url="https://api.example.test/private?token=secret-a#sensitive-fragment",
        status_code=200,
        headers={},
        response_time_ms=1.0,
        content_length=4,
        body_sha256="a" * 64,
    )
    probe_b = ProbeResult(
        url="https://api.example.test/private?token=secret-b#other-fragment",
        status_code=200,
        headers={},
        response_time_ms=1.0,
        content_length=4,
        body_sha256="a" * 64,
    )
    diff = DiffResult(
        url_a=probe_a.url,
        url_b=probe_b.url,
        status_match=True,
        status_a=200,
        status_b=200,
        body_match=True,
        content_length_delta=0,
        header_differences={},
        probe_a=probe_a,
        probe_b=probe_b,
    )

    serialized = str(diff_data(diff))
    assert "secret-a" not in serialized
    assert "secret-b" not in serialized
    assert "sensitive-fragment" not in serialized
    assert "other-fragment" not in serialized
    assert diff_data(diff)["probe_a"]["url"] == (
        "https://api.example.test/private?[REDACTED]"
    )


@pytest.mark.parametrize(
    "probe",
    [
        ProbeResult(
            url="https://api.example.test/account",
            status_code=200,
            headers={},
            response_time_ms=1.0,
            content_length=-1,
            body_sha256="a" * 64,
        ),
        ProbeResult(
            url="https://api.example.test/account",
            status_code=200,
            headers={},
            response_time_ms=float("nan"),
            content_length=10,
            body_sha256="a" * 64,
        ),
        ProbeResult(
            url="https://api.example.test/account",
            status_code=200,
            headers={},
            response_time_ms=1.0,
            content_length=10,
            body_sha256="not-a-sha256",
        ),
        ProbeResult(
            url="https://api.example.test/account",
            status_code=True,
            headers={},
            response_time_ms=1.0,
            content_length=10,
            body_sha256="a" * 64,
        ),
    ],
)
def test_invalid_probe_metadata_is_rejected_before_observation_persistence(
    probe: ProbeResult,
) -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        program = Program(
            name="Example Program",
            authorized_scope=["api.example.test"],
            excluded_scope=[],
            rate_limit=30,
        )
        investigation = Investigation(program=program, status="running")
        asset = Asset(investigation=investigation, hostname="api.example.test")
        session.add(asset)
        session.flush()
        with pytest.raises(ValueError, match="evidence"):
            store_inventory_evidence(asset.id, probe, session)

        assert session.scalars(select(Observation)).all() == []
    engine.dispose()


def test_unsupported_authorization_snapshot_fields_are_rejected_before_persistence() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe = ProbeResult(
        url="https://api.example.test/account",
        status_code=200,
        headers={},
        response_time_ms=1.0,
        content_length=10,
        body_sha256="a" * 64,
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
        session.add(asset)
        session.flush()

        with pytest.raises(ValueError, match="unsupported fields"):
            store_inventory_evidence(
                asset.id,
                probe,
                session,
                provenance_collector="endpoint-inventory",
                authorization_snapshot={
                    "target": "api.example.test",
                    "token": "secret-value",
                },
            )

        assert session.scalars(select(Observation)).all() == []
    engine.dispose()


def test_authorization_snapshot_must_match_current_scope_before_persistence() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    probe = ProbeResult(
        url="https://api.example.test/account",
        status_code=200,
        headers={},
        response_time_ms=1.0,
        content_length=10,
        body_sha256="a" * 64,
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
        session.add(asset)
        session.flush()

        with pytest.raises(ValueError, match="does not match the program"):
            store_inventory_evidence(
                asset.id,
                probe,
                session,
                provenance_collector="endpoint-inventory",
                authorization_snapshot={
                    "target": "api.example.test",
                    "authorized_scope": ["*.test"],
                    "excluded_scope": [],
                    "caller_authorizer_approved": True,
                },
            )
        assert session.scalars(select(Observation)).all() == []
    engine.dispose()


def test_diff_summary_flags_are_derived_from_validated_probe_records() -> None:
    probe_a = ProbeResult(
        url="https://api.example.test/a",
        status_code=200,
        headers={},
        response_time_ms=1.0,
        content_length=10,
        body_sha256="a" * 64,
    )
    probe_b = ProbeResult(
        url="https://api.example.test/b",
        status_code=403,
        headers={},
        response_time_ms=1.0,
        content_length=6,
        body_sha256="b" * 64,
    )
    inconsistent = DiffResult(
        url_a=probe_a.url,
        url_b=probe_b.url,
        status_match=True,
        status_a=200,
        status_b=200,
        body_match=True,
        content_length_delta=0,
        header_differences={},
        probe_a=probe_a,
        probe_b=probe_b,
    )

    data = diff_data(inconsistent)

    assert data["status_match"] is False
    assert (data["status_a"], data["status_b"]) == (200, 403)
    assert data["body_match"] is False
    assert data["content_length_delta"] == 4


def test_secret_shaped_response_headers_are_excluded_from_evidence() -> None:
    probe_a = ProbeResult(
        url="https://api.example.test/account",
        status_code=200,
        headers={
            "content-type": "application/json",
            "x-session-info": "session=session-secret",
            "x-csrf-token": "csrf-secret",
        },
        response_time_ms=1.0,
        content_length=10,
        body_sha256="a" * 64,
    )
    probe_b = ProbeResult(
        url="https://api.example.test/account",
        status_code=200,
        headers={"content-type": "application/json"},
        response_time_ms=1.0,
        content_length=10,
        body_sha256="a" * 64,
    )
    diff = DiffResult(
        url_a=probe_a.url,
        url_b=probe_b.url,
        status_match=True,
        status_a=200,
        status_b=200,
        body_match=True,
        content_length_delta=0,
        header_differences={},
        probe_a=probe_a,
        probe_b=probe_b,
    )

    evidence = str(diff_data(diff))

    assert "session-secret" not in evidence
    assert "csrf-secret" not in evidence
    assert "x-session-info" not in evidence
    assert "x-csrf-token" not in evidence


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
