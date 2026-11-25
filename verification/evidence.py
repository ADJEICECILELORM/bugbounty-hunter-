"""Persist sanitized verification results as hypothesis-linked observations."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import (
    Asset,
    Hypothesis,
    Observation,
    ObservationFingerprint,
    ObservationProvenance,
    Verdict,
    canonical_observation_identity,
    observation_identity_fingerprint,
)
from verification.diff_check import DiffResult
from verification.http_probe import ProbeResult
from verification.verdict_checker import VerdictResult
from verification.verdict_integrity import digest_for, verify_verdict

# Asset-level observation context, never a judgement input: no verdict rule reads
# these rows, and ``verify_verdict()`` accepts ``diff_check`` evidence only, so a
# row stored with this type cannot be cited as a verdict's evidence.
INVENTORY_OBSERVATION_TYPE = "endpoint_inventory"
_SENSITIVE_HEADER = re.compile(
    r"(?i)(?:auth|cookie|token|secret|password|credential|"
    r"api[-_]?key|session|csrf|xsrf|private[-_]?key|access[-_]?key)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:\b(?:bearer|basic)\s+\S+|\b(?:auth|token|secret|password|"
    r"credential|session|csrf|xsrf|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|api[_-]?key)\s*[:=])"
)
_SHA256 = re.compile(r"\A[0-9a-fA-F]{64}\Z")
_PROVENANCE_COLLECTOR = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")
_AUTHORIZATION_SNAPSHOT_KEYS = frozenset(
    {
        "target",
        "authorized_scope",
        "excluded_scope",
        "caller_authorizer_approved",
        "lab_mode",
    }
)


def canonical_observation_fingerprint(
    *,
    observation_type: str,
    asset_id: int | None,
    hypothesis_id: int | None,
    data: Mapping[str, Any],
) -> str:
    """Stable fingerprint for exact duplicate detection.

    The hash includes ownership context (asset and hypothesis) and the canonical
    stored JSON so a duplicate is recognized only when both the evidence and its
    subject match. Distinct observations are left intact; the fingerprint is used
    for auditing and duplicate triage, never for silent suppression.
    """
    if asset_id is None:
        raise ValueError("an observation fingerprint requires an asset id")
    return observation_identity_fingerprint(
        observation_type=observation_type,
        asset_id=asset_id,
        hypothesis_id=hypothesis_id,
        data=dict(data),
    )


def exact_duplicate_observation_ids(
    observation: Observation,
    session: Session,
) -> tuple[int, ...]:
    """Return exact duplicate rows after verifying canonical payload equality.

    The stored SHA-256 index narrows candidates only. Each matching hash is
    checked against canonical ownership/type/data bytes before the row is
    reported, so a hash collision cannot conflate distinct evidence.
    """
    if observation.id is None or observation.asset_id is None:
        raise ValueError("duplicate lookup requires a persisted observation")
    persisted_observation = session.get(Observation, observation.id)
    if persisted_observation is None:
        raise ValueError("duplicate lookup requires an existing observation row")
    observation = persisted_observation
    identity = canonical_observation_identity(
        observation_type=observation.observation_type,
        asset_id=observation.asset_id,
        hypothesis_id=observation.hypothesis_id,
        data=observation.data,
    )
    fingerprint = observation_identity_fingerprint(
        observation_type=observation.observation_type,
        asset_id=observation.asset_id,
        hypothesis_id=observation.hypothesis_id,
        data=observation.data,
    )
    candidate_ids = session.scalars(
        select(ObservationFingerprint.observation_id)
        .where(
            ObservationFingerprint.fingerprint == fingerprint,
            ObservationFingerprint.observation_id != observation.id,
        )
        .order_by(ObservationFingerprint.observation_id)
    )
    matches: list[int] = []
    for candidate_id in candidate_ids:
        candidate = session.get(Observation, candidate_id)
        if candidate is None or candidate.asset_id is None:
            continue
        candidate_identity = canonical_observation_identity(
            observation_type=candidate.observation_type,
            asset_id=candidate.asset_id,
            hypothesis_id=candidate.hypothesis_id,
            data=candidate.data,
        )
        if candidate_identity == identity:
            matches.append(candidate_id)
    return tuple(matches)


def _validate_probe(probe: ProbeResult) -> None:
    if not isinstance(probe.status_code, int) or isinstance(probe.status_code, bool):
        raise ValueError("evidence status code must be an integer")
    if not 100 <= probe.status_code <= 599:
        raise ValueError("evidence status code must be between 100 and 599")
    if (
        not isinstance(probe.content_length, int)
        or isinstance(probe.content_length, bool)
        or probe.content_length < 0
    ):
        raise ValueError("evidence content length must be a non-negative integer")
    if (
        not isinstance(probe.response_time_ms, (int, float))
        or isinstance(probe.response_time_ms, bool)
        or not math.isfinite(probe.response_time_ms)
        or probe.response_time_ms < 0
    ):
        raise ValueError("evidence response time must be finite and non-negative")
    if not isinstance(probe.body_sha256, str) or not _SHA256.fullmatch(
        probe.body_sha256
    ):
        raise ValueError("evidence body digest must be a 64-character SHA-256 hex value")
    if not isinstance(probe.headers, Mapping) or any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in probe.headers.items()
    ):
        raise ValueError("evidence headers must be a string-to-string mapping")


def _prepare_provenance(
    *,
    collector: str | None,
    authorization_program_id: int | None,
    authorization_snapshot: Mapping[str, Any] | None,
    expected_target: str,
    expected_authorized_scope: list[str],
    expected_excluded_scope: list[str],
) -> dict[str, Any] | None:
    if collector is None:
        if authorization_snapshot is not None:
            raise ValueError("authorization provenance requires a collector")
        return None
    if not isinstance(collector, str) or not _PROVENANCE_COLLECTOR.fullmatch(collector):
        raise ValueError("provenance collector must be a short identifier")
    if authorization_snapshot is None:
        return {
            "collector": collector,
            "authorization_program_id": authorization_program_id,
            "authorization_snapshot": None,
        }
    if not isinstance(authorization_snapshot, Mapping):
        raise ValueError("authorization snapshot must be a mapping")
    if any(
        not isinstance(key, str) or key not in _AUTHORIZATION_SNAPSHOT_KEYS
        for key in authorization_snapshot
    ):
        raise ValueError("authorization snapshot contains unsupported fields")

    snapshot: dict[str, Any] = {}
    target = authorization_snapshot.get("target")
    if (
        not isinstance(target, str)
        or target.strip().lower().rstrip(".") != expected_target.lower().rstrip(".")
    ):
        raise ValueError("authorization snapshot target does not match the evidence asset")
    snapshot["target"] = expected_target

    for field in ("authorized_scope", "excluded_scope"):
        scope = authorization_snapshot.get(field)
        if not isinstance(scope, (list, tuple)) or any(
            not isinstance(item, str)
            or not item.strip()
            or len(item) > 255
            or _SECRET_VALUE.search(item)
            or any(character in item for character in ("@", "?", "#", "://"))
            for item in scope
        ):
            raise ValueError(f"authorization snapshot {field} is invalid")
        normalized_scope = [item.strip() for item in scope]
        expected_scope = (
            expected_authorized_scope
            if field == "authorized_scope"
            else expected_excluded_scope
        )
        if normalized_scope != expected_scope:
            raise ValueError(
                f"authorization snapshot {field} does not match the program"
            )
        snapshot[field] = normalized_scope

    if authorization_snapshot.get("caller_authorizer_approved") is not True:
        raise ValueError("authorization snapshot does not record approval")
    for field in ("caller_authorizer_approved", "lab_mode"):
        value = authorization_snapshot.get(field)
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError(f"authorization snapshot {field} must be boolean")
            if field == "caller_authorizer_approved" and value is not True:
                raise ValueError("authorization snapshot does not record approval")
            snapshot[field] = value
    return {
        "collector": collector,
        "authorization_program_id": authorization_program_id,
        "authorization_snapshot": snapshot,
    }


def _probe_evidence(probe: ProbeResult) -> dict[str, object]:
    _validate_probe(probe)
    return {
        "url": _url_for_evidence(probe.url),
        "status_code": probe.status_code,
        "headers": _safe_headers(probe.headers),
        "response_time_ms": probe.response_time_ms,
        "content_length": probe.content_length,
        "body_sha256": probe.body_sha256.lower(),
    }


def _url_for_evidence(url: str) -> str:
    """Keep credentials, query parameters, and fragments out of evidence."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("evidence URL is malformed") from None
    hostname = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("evidence URL must be absolute HTTP(S)")
    safe_host = hostname.lower()
    if ":" in safe_host and not safe_host.startswith("["):
        safe_host = f"[{safe_host}]"
    safe_netloc = f"{safe_host}:{port}" if port is not None else safe_host
    return urlunsplit(
        (
            parsed.scheme.lower(),
            safe_netloc,
            parsed.path,
            "[REDACTED]" if parsed.query else "",
            "",
        )
    )


def _safe_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        return {}
    safe: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if _SENSITIVE_HEADER.search(name) or _SECRET_VALUE.search(value):
            continue
        safe[name.lower()[:256]] = value[:2000]
    return safe


def diff_data(diff_result: DiffResult) -> dict[str, Any]:
    """The allowlisted evidence mapping, exactly as it is stored.

    The verdict checker reads this same mapping, so a verdict is always derived
    from the bytes that were actually persisted rather than from a parallel
    interpretation of the probe objects.
    """
    probe_a = _probe_evidence(diff_result.probe_a)
    probe_b = _probe_evidence(diff_result.probe_b)
    return {
        "status_match": probe_a["status_code"] == probe_b["status_code"],
        "status_a": probe_a["status_code"],
        "status_b": probe_b["status_code"],
        "body_match": probe_a["body_sha256"] == probe_b["body_sha256"],
        "content_length_delta": abs(
            probe_a["content_length"] - probe_b["content_length"]
        ),
        "header_differences": _header_differences(
            probe_a["headers"], probe_b["headers"]
        ),
        "probe_a": probe_a,
        "probe_b": probe_b,
    }


def _header_differences(
    headers_a: object, headers_b: object
) -> dict[str, list[str | None]]:
    if not isinstance(headers_a, Mapping) or not isinstance(headers_b, Mapping):
        raise ValueError("evidence headers must be mappings")
    safe: dict[str, list[str | None]] = {}
    names = headers_a.keys() | headers_b.keys()
    for name in sorted(names):
        value_a = headers_a.get(name)
        value_b = headers_b.get(name)
        if value_a == value_b:
            continue
        safe[name] = [
            value_a if isinstance(value_a, str) else None,
            value_b if isinstance(value_b, str) else None,
        ]
    return safe


def store_diff_evidence(
    hypothesis_id: int,
    diff_result: DiffResult,
    session: Session,
    *,
    provenance_collector: str | None = None,
    authorization_snapshot: Mapping[str, Any] | None = None,
) -> Observation:
    """Store sanitized diff evidence and optional collection provenance.

    Callers without verified collection context may omit provenance; consumers
    then report it as unrecorded rather than inventing collection metadata.
    """
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise LookupError(f"Hypothesis {hypothesis_id} does not exist")

    data = diff_data(diff_result)
    asset_hostname = hypothesis.asset.hostname.rstrip(".").lower()
    target_hosts = {
        (urlsplit(probe["url"]).hostname or "").rstrip(".").lower()
        for probe in (data["probe_a"], data["probe_b"])
    }
    if target_hosts != {asset_hostname}:
        raise ValueError("verification evidence targets do not match the hypothesis asset")

    provenance = _prepare_provenance(
        collector=provenance_collector,
        authorization_program_id=hypothesis.asset.investigation.program_id,
        authorization_snapshot=authorization_snapshot,
        expected_target=hypothesis.asset.hostname,
        expected_authorized_scope=hypothesis.asset.investigation.program.authorized_scope,
        expected_excluded_scope=hypothesis.asset.investigation.program.excluded_scope,
    )
    observation = Observation(
        asset_id=hypothesis.asset_id,
        hypothesis_id=hypothesis.id,
        observation_type="diff_check",
        data=data,
    )
    session.add(observation)
    session.flush()
    _store_provenance(observation, session, provenance)
    return observation


def inventory_data(probe: ProbeResult) -> dict[str, object]:
    """The allowlisted evidence mapping for one inventory probe.

    Deliberately the same mapping a comparison records for one probe: an
    integrity digest binds whatever is stored here for as long as the row exists,
    so this reuses the audited allowlist instead of inventing a second field set
    that older readers would not know, and no collector can add a field to it.
    """
    return _probe_evidence(probe)


def store_inventory_evidence(
    asset_id: int,
    probe: ProbeResult,
    session: Session,
    *,
    provenance_collector: str | None = None,
    authorization_snapshot: Mapping[str, Any] | None = None,
) -> Observation:
    """Store one authorized inventory probe as asset-level context.

    The row carries no ``hypothesis_id``: an inventory is not evidence for any
    claim, so nothing here judges it, promotes it, or binds it to a hypothesis.
    ``verification.verdict_integrity.verify_verdict()`` accepts ``diff_check``
    evidence only, which is what keeps that true even if a caller later tries to
    cite the row. Flush only, never commit - the caller owns the transaction.
    """
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"Asset {asset_id} does not exist")

    data = inventory_data(probe)
    target_host = (urlsplit(data["url"]).hostname or "").rstrip(".").lower()
    if target_host != asset.hostname.rstrip(".").lower():
        raise ValueError("inventory evidence target does not match the asset host")

    provenance = _prepare_provenance(
        collector=provenance_collector,
        authorization_program_id=asset.investigation.program_id,
        authorization_snapshot=authorization_snapshot,
        expected_target=asset.hostname,
        expected_authorized_scope=asset.investigation.program.authorized_scope,
        expected_excluded_scope=asset.investigation.program.excluded_scope,
    )
    observation = Observation(
        asset_id=asset.id,
        hypothesis_id=None,
        observation_type=INVENTORY_OBSERVATION_TYPE,
        data=data,
    )
    session.add(observation)
    session.flush()
    _store_provenance(observation, session, provenance)
    return observation


def _store_provenance(
    observation: Observation,
    session: Session,
    provenance: dict[str, Any] | None,
) -> None:
    if provenance is None:
        return
    session.add(
        ObservationProvenance(
            observation_id=observation.id,
            collector=provenance["collector"],
            collector_version="1",
            authorization_program_id=provenance["authorization_program_id"],
            authorization_snapshot=provenance["authorization_snapshot"],
            captured_at=datetime.now(UTC),
        )
    )
    session.flush()


def store_verdict(
    hypothesis_id: int,
    observation: Observation,
    result: VerdictResult,
    session: Session,
) -> Verdict:
    """Store one deterministic verdict for one stored observation.

    A verdict is derived data - it can be recomputed from the observation at any
    time - so it is never allowed to float free of the evidence it judges: the
    observation must already belong to the same hypothesis, and the row carries
    an integrity digest binding the judgement to that observation, this
    hypothesis, and the recorded target URLs. Nothing is written unless the row
    passes the same check its consumers will later apply, so the writer and the
    verifier cannot drift apart.

    Nothing here writes a hypothesis status; only ``promote_to_finding`` may do
    that.
    """
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise LookupError(f"Hypothesis {hypothesis_id} does not exist")
    if observation.hypothesis_id != hypothesis.id:
        raise ValueError(
            f"Observation {observation.id} belongs to hypothesis "
            f"{observation.hypothesis_id}, not {hypothesis.id}"
        )

    verdict = Verdict(
        hypothesis_id=hypothesis.id,
        observation_id=observation.id,
        claim_type=result.claim_type,
        is_control=result.is_control,
        verdict=result.verdict,
        rationale=result.rationale,
        integrity_digest="",
    )
    digest = digest_for(verdict, observation)
    if digest is None:
        raise ValueError(
            f"Observation {observation.id} cannot be bound to a verdict: its "
            "evidence is not a recordable mapping"
        )
    verdict.integrity_digest = digest

    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
    if not check.ok:
        raise RuntimeError(
            "Refusing to store a verdict that fails its own integrity check "
            f"({check.reason}): {check.detail}"
        )

    session.add(verdict)
    session.flush()
    return verdict
