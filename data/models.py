"""SQLAlchemy models for programs, investigations, tasks, assets, and observations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Program(Base):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    authorized_scope: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    excluded_scope: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    rate_limit: Mapped[int] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    investigations: Mapped[list[Investigation]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    program: Mapped[Program] = relationship(back_populates="investigations")
    assets: Mapped[list[Asset]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    tasks: Mapped[list[Task]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="Task.id",
    )


class Task(Base):
    """One operator-tracked unit of work inside an investigation.

    A task is a record, not a job: nothing executes it. Its ``status`` is
    written only by :mod:`verification.investigation_tasks`, and only when an
    operator calls one of its functions.
    """

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_summary: Mapped[str | None] = mapped_column(String(2000))

    investigation: Mapped[Investigation] = relationship(back_populates="tasks")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    investigation: Mapped[Investigation] = relationship(back_populates="assets")
    observations: Mapped[list[Observation]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    hypotheses: Mapped[list[Hypothesis]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="unverified", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    asset: Mapped[Asset] = relationship(back_populates="hypotheses")
    observations: Mapped[list[Observation]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan"
    )
    verdicts: Mapped[list[Verdict]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan"
    )
    finding: Mapped[Finding | None] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan", uselist=False
    )


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    hypothesis_id: Mapped[int | None] = mapped_column(
        ForeignKey("hypotheses.id"), nullable=True
    )
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    asset: Mapped[Asset] = relationship(back_populates="observations")
    hypothesis: Mapped[Hypothesis | None] = relationship(back_populates="observations")


class Verdict(Base):
    """A deterministic judgement of one observation, never of a hypothesis.

    A verdict records what stored evidence does or does not show. It is written
    by the offline checker and carries no authority of its own: only
    ``promote_to_finding`` may turn supporting verdicts into a finding, and it
    requires an explicit human approver.

    ``integrity_digest`` binds the stored judgement to the evidence row it
    judged, the hypothesis, and the target URLs, plus the canonical digest of
    the stored evidence. :mod:`verification.verdict_integrity` recomputes it, and
    every consumer of a verdict verifies it before use, so an edited or
    hand-written row is rejected rather than trusted.
    """

    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(primary_key=True)
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("hypotheses.id"), nullable=False
    )
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("observations.id"), nullable=False
    )
    claim_type: Mapped[str] = mapped_column(String(64), nullable=False)
    is_control: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[str] = mapped_column(String(1000), nullable=False)
    integrity_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    hypothesis: Mapped[Hypothesis] = relationship(back_populates="verdicts")
    observation: Mapped[Observation] = relationship()


class Finding(Base):
    """The only record that claims a human verified a hypothesis."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("hypotheses.id"), nullable=False, unique=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    hypothesis: Mapped[Hypothesis] = relationship(back_populates="finding")


class PromotionAudit(Base):
    """Append-only record of who promoted what, when, and from which evidence."""

    __tablename__ = "promotion_audit"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("hypotheses.id"), nullable=False
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True
    )
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    verdict_ids: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )