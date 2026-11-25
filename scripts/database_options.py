"""Shared database path handling for operator CLI entry points."""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.engine import Engine

from data.db import open_ready_database
from data.sqlite import enable_sqlite_foreign_keys


class OperatorDatabaseError(ValueError):
    """Raised when an operator database path cannot safely be opened."""


def add_database_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database",
        type=Path,
        metavar="PATH",
        default=None,
        help=(
            "existing SQLite database to use (default: this command's "
            "lab_evidence_v3.db)"
        ),
    )


def resolve_database_path(database: Path | None, default_path: Path) -> Path:
    """Resolve and validate an existing database file without creating it."""
    candidate = default_path if database is None else database.expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise OperatorDatabaseError(
            f"Database path {str(candidate)!r} does not exist or cannot be resolved"
        ) from error
    if not resolved.is_file():
        raise OperatorDatabaseError(f"Database path {str(resolved)!r} is not a file")
    return resolved


def _sqlite_uri(path: Path, *, mode: str) -> URL:
    encoded_path = quote(path.as_posix(), safe="/")
    return URL.create(
        "sqlite+pysqlite",
        database=f"file:{encoded_path}",
        query={"mode": mode, "uri": "true"},
    )


def open_operator_database(
    database: Path | None,
    *,
    default_path: Path,
) -> tuple[Engine, Path]:
    """Open a ready existing SQLite DB read/write without implicit creation."""
    path = resolve_database_path(database, default_path)
    try:
        engine = open_ready_database(str(_sqlite_uri(path, mode="rw")))
    except Exception as error:
        raise OperatorDatabaseError(
            f"Cannot open ready SQLite database {str(path)!r}: {error}"
        ) from error
    return engine, path


def open_operator_database_readonly(
    database: Path | None,
    *,
    default_path: Path,
) -> tuple[Engine, Path]:
    """Open an existing SQLite DB in read-only mode for reporting commands."""
    path = resolve_database_path(database, default_path)
    try:
        engine = create_engine(_sqlite_uri(path, mode="ro"))
        enable_sqlite_foreign_keys(engine)
        return engine, path
    except Exception as error:
        raise OperatorDatabaseError(
            f"Cannot open SQLite database {str(path)!r} read-only: {error}"
        ) from error
