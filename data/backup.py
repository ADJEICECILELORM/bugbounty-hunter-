"""Verified, non-overwriting SQLite online backups for explicit migrations."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote


class SQLiteBackupError(RuntimeError):
    """Raised when an SQLite backup cannot be safely created and verified."""


@dataclass(frozen=True)
class SQLiteBackup:
    path: Path
    checksum_path: Path
    sha256: str


def _reserve(path: Path) -> int:
    try:
        return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise SQLiteBackupError(f"Refusing to overwrite existing file: {path}") from error
    except OSError as error:
        raise SQLiteBackupError(
            f"Cannot reserve backup destination {path}: {error}. Check that the "
            "directory exists and is writable."
        ) from error


def _remove_if_owned(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.stat()
        if (current.st_dev, current.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as backup:
        for chunk in iter(lambda: backup.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_verified_sqlite_backup(
    database_path: Path, backup_path: Path | None = None
) -> SQLiteBackup:
    """Take a consistent SQLite online backup and record its SHA-256 checksum.

    The source is opened in read-only mode and copied with SQLite's backup API,
    which includes a consistent view of databases using WAL. Neither the source
    nor an existing backup is overwritten.
    """
    source_path = database_path.expanduser().resolve()
    if not source_path.is_file():
        raise SQLiteBackupError(f"Database file does not exist: {source_path}")

    if backup_path is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        backup_path = source_path.with_name(
            f"{source_path.name}.pre-migration-{stamp}.sqlite3"
        )
    else:
        backup_path = backup_path.expanduser().resolve()
    checksum_path = Path(f"{backup_path}.sha256")

    if checksum_path.exists():
        raise SQLiteBackupError(
            f"Refusing to overwrite existing checksum file: {checksum_path}"
        )
    backup_fd = _reserve(backup_path)
    backup_stat = os.fstat(backup_fd)
    backup_identity = (backup_stat.st_dev, backup_stat.st_ino)
    checksum_fd = None
    checksum_identity = None
    try:
        checksum_fd = _reserve(checksum_path)
        checksum_stat = os.fstat(checksum_fd)
        checksum_identity = (checksum_stat.st_dev, checksum_stat.st_ino)
        os.close(backup_fd)
        backup_fd = -1
        source_uri = f"file:{quote(source_path.as_posix(), safe='/')}?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source, sqlite3.connect(
            backup_path
        ) as destination:
            source.backup(destination)
            quick_check = destination.execute("PRAGMA integrity_check").fetchone()
            if quick_check != ("ok",):
                raise SQLiteBackupError(
                    f"Backup integrity check failed: {quick_check!r}"
                )
            destination.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()

        checksum = _sha256(backup_path)
        with os.fdopen(checksum_fd, "w", encoding="ascii") as checksum_file:
            checksum_fd = -1
            checksum_file.write(f"{checksum}  {backup_path.name}\n")
            checksum_file.flush()
            os.fsync(checksum_file.fileno())
        with sqlite3.connect(
            f"file:{quote(backup_path.as_posix(), safe='/')}?mode=ro", uri=True
        ) as verified:
            if verified.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise SQLiteBackupError(
                    "Backup failed its final read-only integrity verification"
                )
            verified.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        return SQLiteBackup(backup_path, checksum_path, checksum)
    except Exception as error:
        if backup_fd >= 0:
            os.close(backup_fd)
        if checksum_fd is not None and checksum_fd >= 0:
            os.close(checksum_fd)
        _remove_if_owned(checksum_path, checksum_identity)
        _remove_if_owned(backup_path, backup_identity)
        if isinstance(error, SQLiteBackupError):
            raise
        raise SQLiteBackupError(
            f"SQLite backup was not verified; migration must not proceed: "
            f"{error}. Check source/destination permissions and available space."
        ) from error
