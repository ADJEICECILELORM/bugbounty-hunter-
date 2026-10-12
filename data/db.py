"""Database engine creation and schema initialization."""

from sqlalchemy import Engine, create_engine

from data.models import Base


def init_db(connection_string: str) -> Engine:
    """Create all application tables and return the configured engine."""
    engine = create_engine(connection_string)
    Base.metadata.create_all(engine)
    return engine