import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Asset(Base):
    """A root domain (or IP range, in future) that Horizon watches."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    root_domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    label: Mapped[str | None] = mapped_column(String(255))
    # Gates active/intrusive connectors (nmap live scan, content discovery,
    # nikto, sqlmap). Passive recon (crt.sh, DNS, WHOIS, TLS inspection,
    # header audit, tech fingerprinting) never needs this — it only ever
    # touches information already public or a standard unauthenticated GET,
    # same as any browser visit. Active scanning against a domain someone
    # doesn't control is a different risk class entirely, so it needs an
    # explicit, logged confirmation at asset-creation time.
    authorized_for_active_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    subdomains: Mapped[list["Subdomain"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    resolved_ip: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="subdomains")
