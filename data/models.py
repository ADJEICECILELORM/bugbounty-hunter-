"""SQLAlchemy models for programs, investigations, assets, and observations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, JSON, String
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