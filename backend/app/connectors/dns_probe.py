"""Basic DNS reconnaissance: resolve hostnames to IPs, pull MX/TXT/NS
records for the root domain. No API key or external service required
beyond the system's own resolver.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def resolve_a_record(hostname: str) -> str | None:
    settings = get_settings()
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = settings.connector_timeout_seconds
        answer = resolver.resolve(hostname, "A")
        return str(answer[0])
    except (dns.exception.DNSException, IndexError):
        return None


def root_domain_records(root_domain: str) -> dict[str, list[str]]:
    settings = get_settings()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.connector_timeout_seconds
    records: dict[str, list[str]] = {}
    for record_type in ("MX", "TXT", "NS"):
        try:
            answer = resolver.resolve(root_domain, record_type)
            records[record_type] = sorted(str(item).strip('"') for item in answer)
        except dns.exception.DNSException as exc:
            logger.debug("DNS %s lookup failed for %s: %s", record_type, root_domain, exc)
            records[record_type] = []
    return records
