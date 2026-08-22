"""TLS/certificate inspection. Pure stdlib (ssl + socket) — no external
binary, no extra dependency, works everywhere Python does. Performs the
same TLS handshake any browser does; this is passive recon, not an attack.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl

logger = logging.getLogger(__name__)

WEAK_PROTOCOLS = ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")


def inspect(hostname: str, port: int = 443) -> dict | None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
                cipher_name, cipher_protocol, cipher_bits = tls_sock.cipher()
    except (socket.error, ssl.SSLError, OSError) as exc:
        logger.info("TLS inspection failed for %s:%s: %s", hostname, port, exc)
        return None

    not_after = _parse_cert_date(cert.get("notAfter"))
    days_until_expiry = None
    if not_after:
        days_until_expiry = (not_after - datetime.datetime.now(datetime.timezone.utc)).days

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))

    return {
        "hostname": hostname,
        "protocol": protocol,
        "weak_protocol": protocol in WEAK_PROTOCOLS,
        "cipher": cipher_name,
        "cipher_bits": cipher_bits,
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "subject_cn": subject.get("commonName"),
        "not_after": cert.get("notAfter"),
        "days_until_expiry": days_until_expiry,
        "expiring_soon": days_until_expiry is not None and days_until_expiry < 30,
        "expired": days_until_expiry is not None and days_until_expiry < 0,
        "san": [entry[1] for entry in cert.get("subjectAltName", ())],
    }


def _parse_cert_date(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    try:
        return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
