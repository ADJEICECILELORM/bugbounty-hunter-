"""Persist discovered assets and observations into an existing session."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Asset, Observation


def store_observations(
    investigation_id: int,
    asset_hostname: str,
    observations: list[dict[str, Any]],
    session: Session,
) -> Asset:
    """Create or reuse an investigation asset and add its observations.

    The caller owns the transaction and decides when to commit or roll back.
    """
    normalized: list[tuple[str, dict[str, Any]]] = []
    for observation in observations:
        observation_type = observation.get("type", observation.get("observation_type"))
        if not isinstance(observation_type, str) or not observation_type:
            raise ValueError("Each observation must include a non-empty type")

        if "data" in observation:
            data = observation["data"]
            if not isinstance(data, Mapping):
                raise ValueError("Observation data must be a mapping")
            observation_data = dict(data)
        else:
            observation_data = {
                key: value
                for key, value in observation.items()
                if key not in {"type", "observation_type"}
            }
        normalized.append((observation_type, observation_data))

    asset = session.scalar(
        select(Asset).where(
            Asset.investigation_id == investigation_id,
            Asset.hostname == asset_hostname,
        )
    )
    if asset is None:
        asset = Asset(investigation_id=investigation_id, hostname=asset_hostname)
        session.add(asset)
        session.flush()

    session.add_all(
        Observation(
            asset=asset,
            observation_type=observation_type,
            data=data,
        )
        for observation_type, data in normalized
    )
    session.flush()
    return asset