from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    platform: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="UNKNOWN",
        nullable=False,
    )

    findings: Mapped[str] = mapped_column(
        Text,
        default="[]",
        nullable=False,
    )

    evidence: Mapped[str] = mapped_column(
        Text,
        default="{}",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )