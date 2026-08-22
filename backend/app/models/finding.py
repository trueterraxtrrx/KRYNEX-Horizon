from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.asset import gen_uuid, utcnow


class Finding(Base):
    """A single recon result: an open port, a detected technology, a DNS
    record, a certificate transparency entry, or an imported Nmap/Burp
    result — anything a connector or import surfaces about an asset."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    subdomain: Mapped[str | None] = mapped_column(String(255), index=True)
    finding_type: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", back_populates="findings")
