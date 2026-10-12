import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import dns.resolver
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Investigation, Observation, Program
from gateway import dns_pin
from gateway.dns_pin import PinnedTarget
from gateway.program_config import load_program
from gateway.resolver import UnauthorizedTargetError
from gateway.scope_policy import ScopePolicy
from workers import recon, storage


def _load_example_program() -> dict[str, object]:
    config_path = Path(__file__).parents[1] / "programs" / "example_program.yaml"
    return load_program(str(config_path))


def _create_investigation(session: Session, config: dict[str, object]) -> Investigation:
    program = Program(
        name=str(config["name"]),
        authorized_scope=list(config["authorized_scope"]),
        excluded_scope=list(config["excluded_scope"]),
        rate_limit=int(config["rate_limit_per_minute"]),
    )
    investigation = Investigation(program=program, status="running")
    session.add(investigation)
    session.commit()
    return investigation


def _fake_pin_url(url: str, *, authorize: object) -> PinnedTarget:
    hostname = urlsplit(url).hostname
    assert hostname is not None
    assert callable(authorize) and authorize(url)
    return PinnedTarget(
        url,
        hostname,
        443,
        (ipaddress.ip_address("93.184.216.34"),),
    )


def test_v1_authorized_recon_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _load_example_program()
    policy = ScopePolicy(config["authorized_scope"], config["excluded_scope"])
    engine = init_db("sqlite+pysqlite:///:memory:")
    dns_calls: list[str] = []

    def fake_dns_resolve(
        hostname: str,
        record_type: str,
        *,
        lifetime: float,
    ) -> list[str]:
        assert hostname == "api.example.test"
        assert lifetime == 2.0
        dns_calls.append(record_type)
        return {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "TXT": []}[record_type]

    monkeypatch.setattr(dns_pin, "pin_url", _fake_pin_url)
    monkeypatch.setattr(dns.resolver, "resolve", fake_dns_resolve)

    with Session(engine) as session:
        investigation = _create_investigation(session, config)
        observations = recon.passive_discover("api.example.test", policy)
        storage.store_observations(
            investigation.id,
            "api.example.test",
            observations,
            session,
        )
        session.commit()

        asset = session.scalar(select(Asset))
        stored_observations = session.scalars(select(Observation)).all()

        assert asset is not None
        assert asset.hostname == "api.example.test"
        assert asset.investigation.program.name == config["name"]
        assert len(stored_observations) == 1
        assert stored_observations[0].data == {
            "record_type": "A",
            "value": "93.184.216.34",
        }
        assert dns_calls == ["A", "AAAA", "MX", "TXT"]

    engine.dispose()


def test_v1_excluded_target_never_reaches_dns_or_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _load_example_program()
    policy = ScopePolicy(config["authorized_scope"], config["excluded_scope"])
    engine = init_db("sqlite+pysqlite:///:memory:")
    calls: list[str] = []

    monkeypatch.setattr(dns_pin, "pin_url", lambda *_args, **_kwargs: calls.append("pin"))
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        lambda *_args, **_kwargs: calls.append("dns"),
    )
    original_store = storage.store_observations

    def track_storage(*args: object, **kwargs: object) -> Asset:
        calls.append("storage")
        return original_store(*args, **kwargs)

    monkeypatch.setattr(storage, "store_observations", track_storage)

    with Session(engine) as session:
        investigation = _create_investigation(session, config)
        with pytest.raises(UnauthorizedTargetError):
            observations = recon.passive_discover("admin.example.test", policy)
            storage.store_observations(
                investigation.id,
                "admin.example.test",
                observations,
                session,
            )

        assert calls == []
        assert session.scalar(select(Asset)) is None
        assert session.scalar(select(Observation)) is None

    engine.dispose()