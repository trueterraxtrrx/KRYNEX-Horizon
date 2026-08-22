"""Scan orchestration: runs the requested connectors against an asset and
records subdomains/findings. Runs inside a FastAPI BackgroundTask with its
own DB session, since it can take longer than a single request (crt.sh,
per-subdomain fingerprinting, an optional nmap pass).
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.connectors import crtsh, dns_probe, nmap_scan, shodan_lookup, techfingerprint
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.asset import Asset, Subdomain, utcnow
from app.models.finding import Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)

# Bounds how many subdomains get the expensive per-host connectors
# (fingerprinting, Shodan, nmap) so a scan against a domain with hundreds
# of CT-log subdomains stays fast and doesn't hammer the target.
MAX_HOSTS_FOR_DEEP_CONNECTORS = 25


def start_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        _run_scan(db, scan_id)
    finally:
        db.close()


def _run_scan(db: Session, scan_id: str) -> None:
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    asset = db.get(Asset, scan.asset_id)
    if not asset:
        scan.status = "failed"
        scan.error = "Asset no longer exists"
        scan.completed_at = utcnow()
        db.commit()
        return

    scan.status = "running"
    db.commit()

    connectors_run: list[str] = []
    findings_created = 0
    error: str | None = None

    try:
        if "crtsh" in scan.connectors_requested:
            hostnames = crtsh.enumerate_subdomains(asset.root_domain)
            for hostname in hostnames:
                _upsert_subdomain(db, asset, hostname, source="crtsh")
            connectors_run.append("crtsh")
            db.commit()

        if "dns" in scan.connectors_requested:
            records = dns_probe.root_domain_records(asset.root_domain)
            for record_type, values in records.items():
                if values:
                    _add_finding(
                        db,
                        asset,
                        None,
                        scan,
                        finding_type="dns_record",
                        source="dns",
                        title=f"{record_type} records for {asset.root_domain}",
                        severity="info",
                        detail={"record_type": record_type, "values": values},
                    )
                    findings_created += 1

            for subdomain in _deep_scan_targets(db, asset):
                ip = dns_probe.resolve_a_record(subdomain.hostname)
                if ip:
                    subdomain.resolved_ip = ip
            connectors_run.append("dns")
            db.commit()

        if "wappalyzer" in scan.connectors_requested:
            for subdomain in _deep_scan_targets(db, asset):
                matches = techfingerprint.fingerprint(f"https://{subdomain.hostname}")
                for match in matches:
                    _add_finding(
                        db,
                        asset,
                        subdomain.hostname,
                        scan,
                        finding_type="technology",
                        source="wappalyzer",
                        title=f"{match['technology']} detected on {subdomain.hostname}",
                        severity="info",
                        detail=match,
                    )
                    findings_created += 1
            connectors_run.append("wappalyzer")
            db.commit()

        if "shodan" in scan.connectors_requested:
            settings = get_settings()
            if settings.shodan_enabled:
                for subdomain in _deep_scan_targets(db, asset):
                    if not subdomain.resolved_ip:
                        continue
                    result = shodan_lookup.host_lookup(subdomain.resolved_ip)
                    if result:
                        _add_finding(
                            db,
                            asset,
                            subdomain.hostname,
                            scan,
                            finding_type="shodan_host",
                            source="shodan",
                            title=f"Shodan data for {subdomain.resolved_ip}",
                            severity="medium" if result.get("vulns") else "info",
                            detail=result,
                        )
                        findings_created += 1
                connectors_run.append("shodan")
            db.commit()

        if "nmap" in scan.connectors_requested and nmap_scan.nmap_available():
            xml_output = nmap_scan.run_live_scan(asset.root_domain)
            if xml_output:
                for port_finding in nmap_scan.parse_nmap_xml(xml_output):
                    _add_finding(
                        db,
                        asset,
                        port_finding.get("host"),
                        scan,
                        finding_type="open_port",
                        source="nmap",
                        title=f"Port {port_finding['port']}/{port_finding['protocol']} open ({port_finding['service']})",
                        severity="medium" if port_finding["port"] in {22, 3389, 3306, 5432, 6379, 27017} else "low",
                        detail=port_finding,
                    )
                    findings_created += 1
            connectors_run.append("nmap")
            db.commit()

    except Exception as exc:  # noqa: BLE001 - scan orchestration must never crash the worker
        logger.exception("Scan %s failed", scan_id)
        error = str(exc)

    scan.status = "failed" if error else "completed"
    scan.error = error
    scan.connectors_run = connectors_run
    scan.completed_at = utcnow()
    scan.summary = {
        "subdomains_seen": len(asset.subdomains),
        "findings_created": findings_created,
    }
    db.commit()


def _deep_scan_targets(db: Session, asset: Asset) -> list[Subdomain]:
    db.refresh(asset)
    return asset.subdomains[:MAX_HOSTS_FOR_DEEP_CONNECTORS]


def _upsert_subdomain(db: Session, asset: Asset, hostname: str, source: str) -> Subdomain:
    existing = next((s for s in asset.subdomains if s.hostname == hostname), None)
    if existing:
        existing.last_seen_at = utcnow()
        return existing
    subdomain = Subdomain(asset_id=asset.id, hostname=hostname, source=source)
    db.add(subdomain)
    db.flush()
    asset.subdomains.append(subdomain)
    return subdomain


def _add_finding(
    db: Session,
    asset: Asset,
    subdomain: str | None,
    scan: Scan,
    *,
    finding_type: str,
    source: str,
    title: str,
    severity: str,
    detail: dict,
) -> Finding:
    finding = Finding(
        asset_id=asset.id,
        scan_id=scan.id,
        subdomain=subdomain,
        finding_type=finding_type,
        source=source,
        title=title,
        severity=severity,
        detail=detail,
    )
    db.add(finding)
    return finding
