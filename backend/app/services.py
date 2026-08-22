"""Scan orchestration: runs the requested connectors against an asset and
records subdomains/findings. Runs inside a FastAPI BackgroundTask with its
own DB session, since it can take longer than a single request (crt.sh,
per-subdomain fingerprinting, an optional nmap pass).
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.connectors import (
    content_discovery,
    crtsh,
    dns_probe,
    nikto_scan,
    nmap_scan,
    security_headers,
    shodan_lookup,
    sqlmap_scan,
    techfingerprint,
    tls_audit,
    whois_lookup,
)
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

# These connectors send more than a single passive lookup/GET at the
# target - port scanning, path brute-forcing, vuln probing, injection
# testing - and require Asset.authorized_for_active_testing before they
# run. Everything else (crtsh, dns, wappalyzer, shodan, tls_audit, whois,
# security_headers) only ever reads publicly-available information or
# performs a single standard request, the same as visiting the site in a
# browser.
ACTIVE_CONNECTORS = {"nmap", "content_discovery", "nikto", "sqlmap"}


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
    connectors_skipped_unauthorized: list[str] = []
    findings_created = 0
    error: str | None = None

    requested = set(scan.connectors_requested)
    if not asset.authorized_for_active_testing:
        blocked = requested & ACTIVE_CONNECTORS
        if blocked:
            connectors_skipped_unauthorized = sorted(blocked)
            requested -= ACTIVE_CONNECTORS
            logger.info(
                "Scan %s: skipping active connectors %s for %s (not authorized_for_active_testing)",
                scan_id,
                connectors_skipped_unauthorized,
                asset.root_domain,
            )

    try:
        if "crtsh" in requested:
            hostnames = crtsh.enumerate_subdomains(asset.root_domain)
            for hostname in hostnames:
                _upsert_subdomain(db, asset, hostname, source="crtsh")
            connectors_run.append("crtsh")
            db.commit()

        if "dns" in requested:
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

        if "wappalyzer" in requested:
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

        if "shodan" in requested:
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

        if "nmap" in requested and nmap_scan.nmap_available():
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

        if "tls_audit" in requested:
            for subdomain in _deep_scan_targets(db, asset):
                result = tls_audit.inspect(subdomain.hostname)
                if result:
                    severity = "high" if result["expired"] else "medium" if (result["expiring_soon"] or result["weak_protocol"]) else "info"
                    _add_finding(
                        db,
                        asset,
                        subdomain.hostname,
                        scan,
                        finding_type="tls_certificate",
                        source="tls_audit",
                        title=f"TLS {result['protocol']} on {subdomain.hostname} (cert expires in {result['days_until_expiry']}d)"
                        if result["days_until_expiry"] is not None
                        else f"TLS {result['protocol']} on {subdomain.hostname}",
                        severity=severity,
                        detail=result,
                    )
                    findings_created += 1
            connectors_run.append("tls_audit")
            db.commit()

        if "whois" in requested:
            result = whois_lookup.lookup(asset.root_domain)
            if result:
                _add_finding(
                    db,
                    asset,
                    None,
                    scan,
                    finding_type="whois_record",
                    source="whois",
                    title=f"WHOIS record for {asset.root_domain}",
                    severity="info",
                    detail=result,
                )
                findings_created += 1
            connectors_run.append("whois")
            db.commit()

        if "security_headers" in requested:
            for subdomain in _deep_scan_targets(db, asset):
                result = security_headers.audit(f"https://{subdomain.hostname}")
                if result and result["missing"]:
                    _add_finding(
                        db,
                        asset,
                        subdomain.hostname,
                        scan,
                        finding_type="missing_security_headers",
                        source="security_headers",
                        title=f"{len(result['missing'])} missing security header(s) on {subdomain.hostname}",
                        severity="low",
                        detail=result,
                    )
                    findings_created += 1
            connectors_run.append("security_headers")
            db.commit()

        if "content_discovery" in requested:
            for subdomain in _deep_scan_targets(db, asset):
                hits = content_discovery.discover(f"https://{subdomain.hostname}")
                for hit in hits:
                    _add_finding(
                        db,
                        asset,
                        subdomain.hostname,
                        scan,
                        finding_type="exposed_path",
                        source="content_discovery",
                        title=f"{hit['path']} responded {hit['status_code']} on {subdomain.hostname}",
                        severity="medium" if hit["status_code"] in (200, 201) else "low",
                        detail=hit,
                    )
                    findings_created += 1
            connectors_run.append("content_discovery")
            db.commit()

        if "nikto" in requested and nikto_scan.nikto_available():
            for subdomain in _deep_scan_targets(db, asset)[:5]:  # nikto is slow; cap deeply
                for vuln in nikto_scan.run_scan(f"https://{subdomain.hostname}"):
                    _add_finding(
                        db,
                        asset,
                        subdomain.hostname,
                        scan,
                        finding_type="web_vulnerability",
                        source="nikto",
                        title=vuln.get("message") or f"Nikto finding on {subdomain.hostname}",
                        severity="medium",
                        detail=vuln,
                    )
                    findings_created += 1
            connectors_run.append("nikto")
            db.commit()

        if "sqlmap" in requested and sqlmap_scan.sqlmap_available():
            for subdomain in _deep_scan_targets(db, asset)[:3]:  # sqlmap is the slowest connector by far
                for injection in sqlmap_scan.run_scan(f"https://{subdomain.hostname}"):
                    _add_finding(
                        db,
                        asset,
                        subdomain.hostname,
                        scan,
                        finding_type="sql_injection",
                        source="sqlmap",
                        title=f"Possible SQL injection: {injection.get('parameter')} on {subdomain.hostname}",
                        severity="high",
                        detail=injection,
                    )
                    findings_created += 1
            connectors_run.append("sqlmap")
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
        "skipped_unauthorized": connectors_skipped_unauthorized,
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
