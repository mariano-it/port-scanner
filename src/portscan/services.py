"""Identificación de servicios por puerto y por banner."""

from __future__ import annotations

import re
import socket

PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    631: "ipp", 993: "imaps", 995: "pop3s", 1433: "ms-sql", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443}
HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9200}

_BANNER_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^SSH-\d"), "ssh"),
    (re.compile(r"^HTTP/\d"), "http"),
    (re.compile(r"^220[ -].*(ftp)", re.I), "ftp"),
    (re.compile(r"^220[ -].*(smtp|esmtp|postfix|exim)", re.I), "smtp"),
    (re.compile(r"^\+OK"), "pop3"),
    (re.compile(r"^\* OK"), "imap"),
    (re.compile(r"^-(ERR|NOAUTH|DENIED)"), "redis"),
    (re.compile(r"mysql|mariadb", re.I), "mysql"),
    (re.compile(r"^RFB \d"), "vnc"),
    (re.compile(r"(?i)^\W*(login|username):\s*$"), "telnet"),
]


def name_for_port(port: int) -> str:
    if port in PORT_NAMES:
        return PORT_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def identify(port: int, banner: str) -> str:
    """Prefiere lo que el servicio dice de sí mismo sobre el nombre por puerto."""
    for pattern, name in _BANNER_SIGNATURES:
        if pattern.search(banner):
            return name
    return name_for_port(port)
