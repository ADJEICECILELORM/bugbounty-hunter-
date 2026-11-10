"""SQLite connection configuration."""

from sqlalchemy import Engine, event


def enable_sqlite_foreign_keys(engine: Engine) -> Engine:
    """Enable SQLite foreign-key enforcement on every newly opened connection."""
    if engine.dialect.name != "sqlite":
        return engine

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return engine
