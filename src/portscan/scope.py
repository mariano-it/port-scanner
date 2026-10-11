"""Alcance obligatorio: solo se escanea lo que el archivo de scope lista."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MIN_PREFIX_V4 = 16
MIN_PREFIX_V6 = 48


class ScopeError(Exception):
    """El objetivo no está autorizado (o el archivo de alcance es inválido)."""


@dataclass
class Scope:
    networks: list[IPNetwork]
    path: str = ""
    sha256: str = ""
    entries: list[str] = field(default_factory=list)

    def contains(self, ip: IPAddress) -> bool:
        return any(ip.version == n.version and ip in n for n in self.networks)


def _resolve(name: str) -> list[IPAddress]:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"no se pudo resolver {name!r}: {exc}") from exc
    seen: dict[str, IPAddress] = {}
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        seen[str(addr)] = addr
    return list(seen.values())


def parse_scope(text: str, path: str = "") -> Scope:
    networks: list[IPNetwork] = []
    entries: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        entries.append(line)
        try:
            net = ipaddress.ip_network(line, strict=False)
            nets = [net]
        except ValueError:
            nets = [ipaddress.ip_network(a) for a in _resolve(line)]
        for net in nets:
            floor = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
            if net.prefixlen < floor:
                raise ScopeError(
                    f"línea {lineno}: {line!r} es demasiado amplio "
                    f"(mínimo /{floor}); define rangos concretos"
                )
            networks.append(net)
    if not networks:
        raise ScopeError("el archivo de alcance está vacío")
    return Scope(
        networks=networks,
        path=path,
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        entries=entries,
    )


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    try:
        text = p.read_text()
    except OSError as exc:
        raise ScopeError(f"no se pudo leer el alcance {str(p)!r}: {exc}") from exc
    return parse_scope(text, str(p))


def _parse_spec(spec: str) -> IPNetwork | list[IPAddress]:
    """IP/CIDR -> red (sin expandir); hostname -> lista de IPs resueltas."""
    try:
        return ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return _resolve(spec)


def _covered(net: IPNetwork, scope: Scope) -> bool:
    return any(net.version == n.version and net.subnet_of(n) for n in scope.networks)


def resolve_targets(
    specs: list[str],
    scope: Scope,
    allow_public: bool = False,
    max_hosts: int = 1024,
) -> list[str]:
    """Valida alcance y tamaño ANTES de expandir; lanza ScopeError si algo no cuadra.

    Un /8 o un IPv6 /64 fuera de alcance se rechaza en O(1): nunca se enumera.
    """
    hosts: dict[str, IPAddress] = {}
    outside: list[str] = []
    total = 0
    for spec in specs:
        parsed = _parse_spec(spec)
        if isinstance(parsed, list):
            candidates: list[IPAddress] = parsed
            size = len(parsed)
            covered = False
        else:
            size = parsed.num_addresses
            covered = _covered(parsed, scope)
            if not covered and size > max_hosts:
                outside.append(str(parsed))  # demasiado grande para enumerar
                continue
            if size > max_hosts:
                raise ScopeError(
                    f"{spec} contiene {size} direcciones y supera --max-hosts={max_hosts}; "
                    "reduce el rango"
                )
            candidates = [parsed.network_address] if size == 1 else list(parsed.hosts())
        total += size
        if total > max_hosts:
            raise ScopeError(f"los objetivos superan --max-hosts={max_hosts}; reduce el rango")
        for ip in candidates:
            if not covered and not scope.contains(ip):
                outside.append(str(ip))
            hosts[str(ip)] = ip
    if outside:
        shown = ", ".join(outside[:5]) + (" ..." if len(outside) > 5 else "")
        raise ScopeError(f"fuera de alcance: {shown} (no listado en el scope)")
    if not hosts:
        raise ScopeError("ningún objetivo resuelto")
    bad = [h for h, ip in hosts.items() if ip.is_multicast or ip.is_unspecified]
    if bad:
        raise ScopeError(f"dirección no escaneable: {bad[0]}")
    public = [h for h, ip in hosts.items() if ip.is_global]
    if public and not allow_public:
        raise ScopeError(
            f"{public[0]} es una IP pública; requiere --allow-public "
            "(solo con autorización por escrito)"
        )
    return list(hosts)
