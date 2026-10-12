from sqlalchemy import select
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Investigation, Observation, Program


def test_database_models_persist_related_records() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")

    with Session(engine) as session:
        program = Program(
            name="Example Program",
            authorized_scope=["*.example.test"],
            excluded_scope=["private.example.test"],
            rate_limit=30,
        )
        investigation = Investigation(program=program, status="running")
        asset = Asset(investigation=investigation, hostname="api.example.test")
        observation = Observation(
            asset=asset,
            observation_type="dns_record",
            data={"record_type": "A", "value": "93.184.216.34"},
        )
        session.add(program)
        session.commit()

        loaded_program = session.scalar(select(Program))
        loaded_investigation = session.scalar(select(Investigation))
        loaded_asset = session.scalar(select(Asset))
        loaded_observation = session.scalar(select(Observation))

        assert loaded_program is not None
        assert loaded_investigation is not None
        assert loaded_asset is not None
        assert loaded_observation is not None
        assert loaded_investigation.program_id == loaded_program.id
        assert loaded_investigation.program.name == "Example Program"
        assert loaded_asset.investigation_id == loaded_investigation.id
        assert loaded_observation.asset_id == loaded_asset.id
        assert loaded_observation.hypothesis_id is None
        assert loaded_asset.observations[0].data["record_type"] == "A"

    engine.dispose()