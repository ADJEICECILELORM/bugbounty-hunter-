from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Investigation, Observation, Program
from workers.storage import store_observations


def test_store_observations_reuses_asset_and_persists_records() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")

    with Session(engine) as session:
        program = Program(
            name="Example Program",
            authorized_scope=["*.example.test"],
            excluded_scope=[],
            rate_limit=30,
        )
        investigation = Investigation(program=program, status="running")
        session.add(investigation)
        session.commit()

        observations = [
            {"type": "dns_record", "record_type": "A", "value": "93.184.216.34"},
            {"type": "dns_record", "record_type": "MX", "value": "10 mail.example.test."},
        ]
        asset = store_observations(investigation.id, "api.example.test", observations, session)
        same_asset = store_observations(
            investigation.id,
            "api.example.test",
            [{"type": "dns_record", "record_type": "TXT", "value": "v=spf1 -all"}],
            session,
        )
        session.commit()

        assets = session.scalars(select(Asset)).all()
        stored_observations = session.scalars(
            select(Observation).order_by(Observation.id)
        ).all()

        assert same_asset.id == asset.id
        assert len(assets) == 1
        assert len(stored_observations) == 3
        assert all(item.asset_id == asset.id for item in stored_observations)
        assert stored_observations[0].data == {
            "record_type": "A",
            "value": "93.184.216.34",
        }
        assert stored_observations[2].data["record_type"] == "TXT"

    engine.dispose()