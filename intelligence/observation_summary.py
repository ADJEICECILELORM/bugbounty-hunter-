"""Summarize one asset's observations for LLM context, keeping target text untrusted.

This is a deterministic data transformation: it never calls a model and it never
interprets the security meaning of an observation. To keep the untrusted-input
boundary in :mod:`intelligence.llm_client` intact, the result is split in two:

``ObservationSummary.text``
    Trusted framing only: the observation types, container sizes, and scalar
    fields this system derived or was configured with (status codes, byte counts,
    elapsed times, content hashes, DNS record types, and the operator-requested
    URLs). No string that originated from the scanned target is interpolated into
    this text.

``ObservationSummary.untrusted``
    Every string that originated from the target - DNS record values, HTTP
    response header names and values, and ``diff_check`` header differences - as
    labeled :class:`~intelligence.llm_client.UntrustedText` items.

Untrusted handling rules, in full:

* A string value is trusted only when its field name is in
  :data:`_TRUSTED_STRING_FIELDS`; every other string is returned as an
  ``UntrustedText`` item instead of being written into ``text``.
* A mapping key is used verbatim only when it is in :data:`_KNOWN_FIELDS`. Any
  other key (for example a response header name, which the target chooses) is
  treated as external text: it is folded into an untrusted item and referred to
  by position in the generated source label. Nothing is dropped - entries of an
  unrecognized observation type simply arrive as untrusted items rather than as
  trusted scalar lines - so the rule stays conservative as new types are added.
* Source labels are therefore assembled only from this module's fixed vocabulary
  plus numeric positions, so target-controlled text can never reach a label.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from data.models import Observation
from intelligence.llm_client import UntrustedText

# Field names whose string values are produced or configured by this system.
_TRUSTED_STRING_FIELDS = frozenset(
    {
        "url",
        "body_sha256",
        "record_type",
        "observation_type",
        "type",
    }
)

# Field names this module recognizes as its own schema. Anything else is external.
_KNOWN_FIELDS = frozenset(
    {
        "url",
        "status_code",
        "headers",
        "response_time_ms",
        "content_length",
        "body_sha256",
        "status_match",
        "status_a",
        "status_b",
        "body_match",
        "content_length_delta",
        "header_differences",
        "probe_a",
        "probe_b",
        "record_type",
        "value",
        "type",
        "observation_type",
    }
)

_ABSENT = "(absent)"


@dataclass(frozen=True)
class ObservationSummary:
    """Deterministic, LLM-ready digest of a single asset's observations."""

    asset_id: int | None
    observation_count: int
    text: str
    untrusted: list[UntrustedText]


def _render_text(value: Any) -> str:
    """Render a target-originated value as plain text for an untrusted block."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " vs ".join(
            _ABSENT if item is None else _render_text(item) for item in value
        )
    if isinstance(value, Mapping):
        return json.dumps(
            {str(key): value[key] for key in sorted(value, key=str)},
            ensure_ascii=True,
            sort_keys=True,
            default=str,
        )
    if value is None:
        return _ABSENT
    return json.dumps(value, ensure_ascii=True, default=str)


def _walk(
    *,
    value: Any,
    path: tuple[str, ...],
    observation_id: int | None,
    lines: list[str],
    untrusted: list[UntrustedText],
) -> None:
    """Split one data value into trusted scalar lines and untrusted text items."""
    joined = "_".join(path) if path else "data"

    if isinstance(value, Mapping):
        lines.append(f"{joined}_entries={len(value)}")
        for index, field in enumerate(sorted(value, key=str)):
            name = str(field)
            if name in _KNOWN_FIELDS:
                _walk(
                    value=value[field],
                    path=path + (name,),
                    observation_id=observation_id,
                    lines=lines,
                    untrusted=untrusted,
                )
                continue
            # The key itself came from the target (e.g. a response header name),
            # so it stays inside the untrusted item and out of the source label.
            untrusted.append(
                UntrustedText(
                    source=f"observation_{observation_id}_{joined}_field_{index}",
                    content=f"{field}: {_render_text(value[field])}",
                )
            )
        return

    if isinstance(value, (list, tuple)):
        lines.append(f"{joined}_items={len(value)}")
        for index, item in enumerate(value):
            _walk(
                value=item,
                path=path + (f"item_{index}",),
                observation_id=observation_id,
                lines=lines,
                untrusted=untrusted,
            )
        return

    if isinstance(value, str):
        if path and path[-1] not in _TRUSTED_STRING_FIELDS:
            untrusted.append(
                UntrustedText(
                    source=f"observation_{observation_id}_{joined}",
                    content=value,
                )
            )
            return
        lines.append(f"{joined}={value}")
        return

    if value is None:
        lines.append(f"{joined}={_ABSENT}")
        return

    lines.append(f"{joined}={json.dumps(value, ensure_ascii=True, default=str)}")


def _summarize_observation(
    observation: Observation,
    *,
    lines: list[str],
    untrusted: list[UntrustedText],
) -> None:
    """Append one observation's trusted lines and untrusted items."""
    detail: list[str] = []
    data = observation.data

    if isinstance(data, Mapping):
        _walk(
            value=data,
            path=(),
            observation_id=observation.id,
            lines=detail,
            untrusted=untrusted,
        )
    else:
        # Not a mapping: keep the whole rendering out of the trusted text.
        detail.append("data_entries=0")
        untrusted.append(
            UntrustedText(
                source=f"observation_{observation.id}_data",
                content=_render_text(data),
            )
        )

    lines.append(f"observation[{observation.id}] type={observation.observation_type}")
    lines.extend(f"  {line}" for line in detail)


def summarize_observations(
    observations: Sequence[Observation],
    *,
    asset_id: int | None = None,
    hostname: str | None = None,
) -> ObservationSummary:
    """Return a deterministic summary of one asset's observations.

    ``asset_id`` and ``hostname`` are optional identity context and are the only
    inputs used by the empty case; when ``asset_id`` is omitted the first
    observation's asset ID is used. Observations are expected to belong to a
    single asset, and their given order is preserved.
    """
    rows = list(observations)
    resolved_asset_id = asset_id
    if resolved_asset_id is None and rows:
        resolved_asset_id = rows[0].asset_id

    lines: list[str] = ["Asset observation summary"]
    if resolved_asset_id is not None:
        lines.append(f"asset_id={resolved_asset_id}")
    if hostname is not None:
        lines.append(f"hostname={hostname}")
    lines.append(f"observation_count={len(rows)}")

    untrusted: list[UntrustedText] = []
    if not rows:
        lines.append(
            "No observations are available for this asset; there is no "
            "target-derived data to summarize."
        )

    for observation in rows:
        _summarize_observation(observation, lines=lines, untrusted=untrusted)

    lines.append(f"untrusted_target_text_items={len(untrusted)}")
    return ObservationSummary(
        asset_id=resolved_asset_id,
        observation_count=len(rows),
        text="\n".join(lines) + "\n",
        untrusted=untrusted,
    )
