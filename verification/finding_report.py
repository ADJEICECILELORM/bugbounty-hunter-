"""Render a promoted finding as a plain-Markdown report.

The renderer is a pure function: it takes rows that were already loaded and
returns a string. There is no model, no network, no clock, and no environment
lookup, so the same evidence always produces byte-identical Markdown and a
report can never claim something the stored evidence does not contain.

Every value in the output is either a stored field or a phrase built from stored
fields - notably, request credentials are never stored in the first place, so
they cannot leak into a report.

The rows a report renders are loaded *and verified* by
:func:`collect_finding_context`: every verdict must carry an integrity digest
that binds it to its evidence, hypothesis and target (see
:mod:`verification.verdict_integrity`), so an edited or hand-written verdict
cannot be presented as though a human had approved the evidence behind it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from data.models import Finding, Hypothesis, Observation, PromotionAudit, Verdict
from verification.verdict_checker import SUPPORTED
from verification.verdict_integrity import DIGEST_SCHEMA, verify_verdict

LAB_BANNER = (
    "> **Local lab evidence.** Every request behind this report was sent to a "
    "deliberately vulnerable target on the operator's own machine. Nothing here "
    "has been reproduced against a program's production system, and no program "
    "has reviewed or accepted it."
)

_DIGEST_PREFIX_LENGTH = 12


class FindingReportContextError(Exception):
    """Raised when a finding cannot be rendered from the stored evidence."""


@dataclass(frozen=True)
class FindingReportContext:
    finding: Finding
    hypothesis: Hypothesis
    verdicts: tuple[Verdict, ...]
    observations: tuple[Observation, ...]
    control_observations: tuple[Observation, ...]
    audits: tuple[PromotionAudit, ...]


def collect_finding_context(session: Session, finding: Finding) -> FindingReportContext:
    """Load everything a report needs, in a fixed order, verifying each verdict.

    This is the report's consumption gate: a verdict must be bound to its
    evidence, hypothesis and target before it can appear in a report, so a
    tampered row cannot be rendered as approved evidence.
    """
    hypothesis = session.get(Hypothesis, finding.hypothesis_id)
    if hypothesis is None:
        raise FindingReportContextError(
            f"Finding {finding.id} references hypothesis {finding.hypothesis_id}, "
            "which does not exist"
        )

    verdicts = tuple(
        session.scalars(
            select(Verdict)
            .where(Verdict.hypothesis_id == hypothesis.id)
            .order_by(Verdict.id)
        )
    )
    observations: list[Observation] = []
    control_observations: list[Observation] = []
    for verdict in verdicts:
        observation = session.get(Observation, verdict.observation_id)
        if observation is None:
            raise FindingReportContextError(
                f"Verdict {verdict.id} references observation "
                f"{verdict.observation_id}, which does not exist"
            )
        check = verify_verdict(verdict, observation, hypothesis_id=hypothesis.id)
        if not check.ok:
            raise FindingReportContextError(
                f"Verdict {verdict.id} is not bound to the evidence it cites "
                f"({check.reason}): {check.detail}"
            )
        if verdict.verdict == SUPPORTED and not verdict.is_control:
            observations.append(observation)
        elif verdict.is_control:
            control_observations.append(observation)

    audits = tuple(
        session.scalars(
            select(PromotionAudit)
            .where(PromotionAudit.hypothesis_id == hypothesis.id)
            .order_by(PromotionAudit.id)
        )
    )
    return FindingReportContext(
        finding=finding,
        hypothesis=hypothesis,
        verdicts=verdicts,
        observations=tuple(observations),
        control_observations=tuple(control_observations),
        audits=audits,
    )


def _cell(value: Any) -> str:
    """Flatten one value into a single safe Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip() or "-"


def _probe(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    probe = data.get(key)
    return probe if isinstance(probe, Mapping) else {}


def _recorded_probe_values(probe: Mapping[str, Any]) -> str:
    """Describe a probe using only the values it actually recorded."""
    parts: list[str] = []
    status_code = probe.get("status_code")
    if isinstance(status_code, int) and not isinstance(status_code, bool):
        parts.append(f"HTTP {status_code}")
    content_length = probe.get("content_length")
    if isinstance(content_length, int) and not isinstance(content_length, bool):
        parts.append(f"{content_length} bytes")
    digest = probe.get("body_sha256")
    if isinstance(digest, str) and digest:
        parts.append(f"sha256 `{digest[:_DIGEST_PREFIX_LENGTH]}...`")
    return ", ".join(parts) or "no recorded values"


def _comparison(probe_a: Mapping[str, Any], probe_b: Mapping[str, Any]) -> str:
    status_match = probe_a.get("status_code") == probe_b.get("status_code")
    body_match = probe_a.get("body_sha256") == probe_b.get("body_sha256")
    if status_match and body_match:
        return "identical"
    if not status_match and not body_match:
        return "status and body differ"
    if not status_match:
        return "status differs"
    return "body differs"


def _comparison_table(observations: Sequence[Observation]) -> list[str]:
    lines = [
        "| Evidence | URL A | URL B | Status A / B | Bytes A / B | sha256 A / B | Comparison |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for observation in observations:
        data = observation.data if isinstance(observation.data, Mapping) else {}
        probe_a = _probe(data, "probe_a")
        probe_b = _probe(data, "probe_b")
        lines.append(
            "| #{id} | `{url_a}` | `{url_b}` | {status_a} / {status_b} | "
            "{bytes_a} / {bytes_b} | `{digest_a}` / `{digest_b}` | {comparison} |".format(
                id=observation.id,
                url_a=_cell(probe_a.get("url")),
                url_b=_cell(probe_b.get("url")),
                status_a=_cell(probe_a.get("status_code")),
                status_b=_cell(probe_b.get("status_code")),
                bytes_a=_cell(probe_a.get("content_length")),
                bytes_b=_cell(probe_b.get("content_length")),
                digest_a=_cell(
                    str(probe_a.get("body_sha256", ""))[:_DIGEST_PREFIX_LENGTH]
                ),
                digest_b=_cell(
                    str(probe_b.get("body_sha256", ""))[:_DIGEST_PREFIX_LENGTH]
                ),
                comparison=_comparison(probe_a, probe_b),
            )
        )
    return lines


def _verdict_table(verdicts: Sequence[Verdict]) -> list[str]:
    lines = [
        "| Verdict | Claim | Control pair | Judgement | Rationale |",
        "| --- | --- | --- | --- | --- |",
    ]
    for verdict in verdicts:
        lines.append(
            f"| #{verdict.id} | `{_cell(verdict.claim_type)}` | "
            f"{'yes' if verdict.is_control else 'no'} | `{_cell(verdict.verdict)}` | "
            f"{_cell(verdict.rationale)} |"
        )
    return lines


def _shows_difference(observation: Observation) -> bool:
    """Whether a stored comparison recorded any difference at all."""
    data = observation.data if isinstance(observation.data, Mapping) else {}
    probe_a = _probe(data, "probe_a")
    probe_b = _probe(data, "probe_b")
    if not probe_a or not probe_b:
        return False
    return (
        probe_a.get("status_code") != probe_b.get("status_code")
        or probe_a.get("body_sha256") != probe_b.get("body_sha256")
    )


def render_finding_report(context: FindingReportContext) -> str:
    """Render a promoted finding as deterministic Markdown.

    Raises :class:`FindingReportContextError` when there is nothing to report,
    rather than emitting a report with empty sections.
    """
    finding = context.finding
    hypothesis = context.hypothesis
    supporting = [
        verdict
        for verdict in context.verdicts
        if verdict.verdict == SUPPORTED and not verdict.is_control
    ]
    if not supporting:
        raise FindingReportContextError(
            f"Finding {finding.id} has no supported verdict, so there is no report"
        )
    if not context.observations:
        raise FindingReportContextError(
            f"Finding {finding.id} has no stored evidence, so there is no report"
        )

    first = context.observations[0]
    first_data = first.data if isinstance(first.data, Mapping) else {}
    probe_a = _probe(first_data, "probe_a")
    probe_b = _probe(first_data, "probe_b")
    url = probe_a.get("url")
    endpoint = urlsplit(url).path if isinstance(url, str) and url else "-"
    hostname = "-"
    if hypothesis.asset is not None and hypothesis.asset.hostname:
        hostname = hypothesis.asset.hostname

    sections: list[str] = [
        f"# {finding.title}",
        LAB_BANNER,
        "\n".join(
            (
                f"- **Finding:** #{finding.id}",
                f"- **Hypothesis:** #{hypothesis.id} (`{finding.category}`)",
                f"- **Asset:** `{hostname}`",
                f"- **Endpoint:** `{endpoint}`",
                f"- **Approved by:** {finding.approved_by}",
                f"- **Promoted at:** {finding.created_at.isoformat()}",
            )
        ),
        "\n".join(
            (
                "## Affected asset",
                f"- **Host:** `{hostname}`",
                f"- **Endpoint:** `{endpoint}`",
                f"- **URL observed:** `{url if isinstance(url, str) else '-'}`",
                f"- **Hypothesis description:** {hypothesis.description}",
            )
        ),
    ]

    steps: list[str] = [
        "## Reproduction",
        "Two differently authenticated requests were compared. Credential values are "
        "deliberately never stored, so the operator must supply the same two "
        "identities again:",
    ]
    for observation in context.observations:
        data = observation.data if isinstance(observation.data, Mapping) else {}
        this_a = _probe(data, "probe_a")
        this_b = _probe(data, "probe_b")
        if len(context.observations) > 1:
            steps.append(f"**Evidence #{observation.id}**")
        steps.append(
            f"1. Send `GET {this_a.get('url', '-')}` with the first identity's "
            "credentials."
        )
        steps.append(
            f"2. Send `GET {this_b.get('url', '-')}` with the second identity's "
            "credentials."
        )
        steps.append(
            "3. Compare the HTTP status codes and the sha256 digests of the two bodies."
        )
        steps.append("")
    sections.append("\n".join(steps).rstrip())

    sections.append(
        "\n".join(["## Observed comparison", *_comparison_table(context.observations)])
    )
    sections.append(
        "\n".join(
            [
                "## Verdicts",
                *_verdict_table(context.verdicts),
                "",
                f"- **Verdict integrity:** each of the {len(context.verdicts)} "
                "verdict(s) above was re-derived from its stored evidence and its "
                f"bound `sha256` digest recomputed (`{DIGEST_SCHEMA}`) before this "
                "report was rendered.",
            ]
        )
    )

    impact: list[str] = [
        "## Demonstrated impact",
        f"Two requests to `{url if isinstance(url, str) else endpoint}` returned "
        f"{_recorded_probe_values(probe_a)} and {_recorded_probe_values(probe_b)}: "
        "byte-identical responses carrying two different sets of credentials, in "
        f"{len(supporting)} of {len(context.verdicts)} stored comparisons.",
    ]
    if any(_shows_difference(observation) for observation in context.control_observations):
        impact.append(
            "On the same run, the control comparison returned different bodies, so the "
            "setup was able to detect a difference; the identical responses above are "
            "therefore not an artifact of every response being identical."
        )
    impact.append(
        "This states only what the stored evidence shows - the same status and the same "
        "body bytes from one endpoint under two identities. It is not a severity "
        "assessment, and no further impact is claimed."
    )
    sections.append("\n".join(impact))

    timestamps = ", ".join(
        observation.created_at.isoformat() for observation in context.observations
    )
    sections.append(
        "\n".join(
            (
                "## Limitations",
                f"- **Local lab only.** `{hostname}` is a deliberately vulnerable build "
                "on the operator's machine, not a program's production asset, and no "
                "program asset was contacted.",
                f"- **Single run.** {len(context.observations)} comparison(s) recorded "
                f"at {timestamps}.",
                "- **Credentials are not stored**, so reproduction requires the operator "
                "to supply the same two identities again.",
                f"- **Narrow coverage.** {len(context.observations)} endpoint "
                "observation(s), with no variation of parameters, headers, or timing.",
                "- **Machine-checked, not human-confirmed.** The verdicts are "
                "deterministic rules over stored bytes; human approval records that the "
                "evidence supported the hypothesis, not an impact assessment.",
                "- No model was involved in judging this evidence, and no program has "
                "reviewed this report.",
            )
        )
    )

    audit_lines = ["## Approval trail"]
    for audit in context.audits:
        audit_lines.append(
            f"- `#{audit.id}` {audit.action} by **{audit.actor}** at "
            f"{audit.created_at.isoformat()} (evidence {audit.evidence_ids}, "
            f"verdicts {audit.verdict_ids})"
        )
    if len(audit_lines) == 1:
        audit_lines.append("- No promotion audit row is recorded for this hypothesis.")
    sections.append("\n".join(audit_lines))

    return "\n\n".join(sections) + "\n"
