"""Persistent investigation lifecycle: open and close one ``Investigation`` row.

This is the deliberately smallest slice of V4: exactly two session functions that
start and close a single investigation, and nothing else. Both write with
``session.add()``/``session.flush()`` and never commit - the caller owns the
transaction, exactly like every other writer in the project.

Neither function touches a ``Hypothesis``, ``Finding``, ``Verdict``, or
``Observation``, and this module imports nothing from the gateway, makes no
network request, and cannot promote or verify anything. Investigation ownership
of hypotheses and endpoint-inventory rows is already expressed in
:mod:`data.models` (an investigation owns its assets, and each asset owns its
hypotheses and observations), so no schema change is required for this slice.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from data.models import Investigation, Program

RUNNING = "running"
CLOSED_STATUSES = frozenset({"completed", "cancelled"})


def start_investigation(program_id: int, session: Session) -> Investigation:
    """Create an ``Investigation`` row with ``status='running'`` and flush it.

    Rejects a program id that does not resolve with :class:`LookupError`, so a
    run can never be opened against an unknown program. Does not commit; the
    caller owns the transaction.
    """
    if session.get(Program, program_id) is None:
        raise LookupError(f"Program {program_id} does not exist")

    investigation = Investigation(program_id=program_id, status=RUNNING)
    session.add(investigation)
    session.flush()
    return investigation


def close_investigation(
    investigation_id: int,
    session: Session,
    *,
    final_status: str,
) -> Investigation:
    """Set a final ``status`` and ``ended_at`` on an ``Investigation`` row.

    ``final_status`` must be one of ``CLOSED_STATUSES``; anything else raises
    :class:`ValueError`. A missing investigation raises :class:`LookupError`.
    Does not commit, and does not touch any ``Hypothesis`` or ``Finding``.
    """
    if final_status not in CLOSED_STATUSES:
        raise ValueError(
            f"final_status must be one of {sorted(CLOSED_STATUSES)!r}, "
            f"got {final_status!r}"
        )

    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise LookupError(f"Investigation {investigation_id} does not exist")

    investigation.status = final_status
    investigation.ended_at = datetime.now(UTC)
    session.flush()
    return investigation
