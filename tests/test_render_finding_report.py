"""The render script is a read-only, fail-closed operator tool.

The renderer it calls (:mod:`verification.finding_report`) is already tested;
these tests pin the *script's own* guarantees instead: it refuses a missing
database, it refuses a missing finding, it opens SQLite read-only so no write
can ever persist, and it has no promotion or commit path of its own.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import scripts.render_finding_report as renderer


def _imported_modules(source: str) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def _called_attributes(source: str) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def test_the_script_has_no_promotion_or_commit_path() -> None:
    source = Path(renderer.__file__).read_text(encoding="utf-8")

    # Rendering must not be able to create or approve a Finding, nor to create
    # the schema the way init_db() does.
    imported = _imported_modules(source)
    assert "verification.finding_promotion" not in imported
    assert "data.db" not in imported

    # And it must never commit: the only write is the Markdown file on disk,
    # never the database.
    assert "commit" not in _called_attributes(source)


def test_read_only_engine_refuses_a_missing_database(tmp_path: Path) -> None:
    missing = tmp_path / "nope.db"
    with pytest.raises(SystemExit, match="does not exist"):
        renderer.read_only_engine(missing)


def test_read_only_engine_opens_an_existing_database_read_only(
    tmp_path: Path,
) -> None:
    db = tmp_path / "existing.db"
    seed = create_engine(f"sqlite+pysqlite:///{db}")
    with Session(seed) as session:
        session.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY)"))
        session.commit()
    seed.dispose()

    engine = renderer.read_only_engine(db)
    with Session(engine) as session:
        # Reads succeed ...
        assert session.execute(text("SELECT 1")).scalar() == 1
        # ... and every write is refused by SQLite itself, not by the script.
        with pytest.raises(OperationalError, match="readonly"):
            session.execute(text("INSERT INTO t (id) VALUES (2)"))
    engine.dispose()


def test_load_finding_fails_closed_on_an_absent_id(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    engine = create_engine(f"sqlite+pysqlite:///{db}")
    from data.models import Base

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        with pytest.raises(SystemExit, match="No Finding #7"):
            renderer._load_finding(session, 7)
    engine.dispose()
