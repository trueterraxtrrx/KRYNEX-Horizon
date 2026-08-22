from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    root_domain: str = Field(min_length=3, max_length=255)
    label: str | None = Field(default=None, max_length=255)
    authorized_for_active_testing: bool = Field(
        default=False,
        description="Confirms you have permission to actively scan this target (nmap, content discovery, nikto, sqlmap). Passive recon (crt.sh, DNS, WHOIS, TLS, headers) never requires this.",
    )


class AssetResponse(BaseModel):
    id: str
    root_domain: str
    label: str | None
    authorized_for_active_testing: bool
    created_at: datetime
    subdomain_count: int = 0
    finding_count: int = 0

    model_config = {"from_attributes": True}


class SubdomainResponse(BaseModel):
    id: str
    hostname: str
    resolved_ip: str | None
    source: str
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: str
    subdomain: str | None
    finding_type: str
    source: str
    title: str
    severity: str
    detail: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    connectors: list[str] = Field(
        default_factory=lambda: ["crtsh", "dns", "wappalyzer", "tls_audit", "whois", "security_headers"],
        description=(
            "Passive (no authorization flag needed): crtsh, dns, wappalyzer, shodan, tls_audit, whois, "
            "security_headers. Active (asset must have authorized_for_active_testing=true): nmap, "
            "content_discovery, nikto, sqlmap."
        ),
    )


class ScanResponse(BaseModel):
    id: str
    asset_id: str
    status: str
    connectors_requested: list[str]
    connectors_run: list[str]
    error: str | None
    summary: dict[str, Any]
    started_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class NmapImportResult(BaseModel):
    findings_created: int


class BurpImportResult(BaseModel):
    findings_created: int


class PlatformStats(BaseModel):
    total_assets: int
    total_subdomains: int
    total_findings: int
    findings_by_severity: dict[str, int]
    connectors_available: dict[str, bool]
