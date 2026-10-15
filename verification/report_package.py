"""Package a promoted finding's report and provenance into a zip, read-only.

This is a pure export: it takes a ``finding_id`` and a session, loads the finding
through the existing, integrity-verifying report loader, renders the Markdown
report, and writes a ``.zip`` with two members - ``report.md`` and
``manifest.json``. It never writes to the database, never changes a status, never
promotes, and never commits: the session is used for reads only.

``manifest.json`` carries provenance only - finding/hypothesis/investigation ids,
evidence observation ids, verdict ids, integrity-digest prefixes, the approver
name, and the promotion timestamp. It never contains credentials: no token or
header value is stored anywhere in the first place, so none can be exported.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from data.models import Finding
from verification.finding_report import collect_finding_context, render_finding_report
from verification.verdict_integrity import DIGEST_PREFIX_LENGTH

REPORT_MEMBER = "report.md"
MANIFEST_MEMBER = "manifest.json"


def build_report_package(session: Session, finding_id: int, out_path: Path) -> Path:
    """Write ``report.md`` and ``manifest.json`` for ``finding_id`` into a zip.

    Raises :class:`LookupError` for a missing finding and lets
    :class:`verification.finding_report.FindingReportContextError` propagate for a
    tampered or incomplete record, so a package is never produced from evidence
    that does not verify. Read-only toward the database: nothing is added,
    changed, promoted, or committed. Returns the resolved output path.
    """
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise LookupError(f"Finding {finding_id} does not exist")

    context = collect_finding_context(session, finding)
    report = render_finding_report(context)

    asset = context.hypothesis.asset
    manifest = {
        "finding_id": finding.id,
        "hypothesis_id": context.hypothesis.id,
        "investigation_id": asset.investigation_id if asset is not None else None,
        "approved_by": finding.approved_by,
        "promoted_at": finding.created_at.isoformat(),
        "evidence_observation_ids": [obs.id for obs in context.observations],
        "control_observation_ids": [obs.id for obs in context.control_observations],
        "verdict_ids": [verdict.id for verdict in context.verdicts],
        "integrity_digest_prefixes": [
            verdict.integrity_digest[:DIGEST_PREFIX_LENGTH]
            for verdict in context.verdicts
        ],
    }

    resolved = out_path.expanduser().resolve()
    with zipfile.ZipFile(resolved, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(REPORT_MEMBER, report)
        archive.writestr(
            MANIFEST_MEMBER, json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
    return resolved
