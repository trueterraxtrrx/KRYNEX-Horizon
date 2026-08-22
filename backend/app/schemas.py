from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    root_domain: str = Field(min_length=3, max_length=255)
    label: str | None = Field(default=None, max_length=255)


class AssetResponse(BaseModel):
    id: str
    root_domain: str
    label: str | None
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
        default_factory=lambda: ["crtsh", "dns", "wappalyzer"],
        description="Any of: crtsh, dns, wappalyzer, shodan, nmap",
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
