"""Parseo de especificaciones de puertos y lista de puertos más comunes."""

from __future__ import annotations

from pathlib import Path

# Respaldo si no existe /usr/share/nmap/nmap-services (frecuencia de nmap, TCP).
_FALLBACK_TOP = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
    111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
    514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515,
    8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800,
    106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144,
    7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13,
    1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
]

_NMAP_SERVICES = Path("/usr/share/nmap/nmap-services")


class PortSpecError(ValueError):
    pass


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8100' -> lista ordenada sin duplicados. '-' = 1-65535."""
    spec = spec.strip()
    if spec in ("-", "all"):
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
            else:
                lo = hi = int(part)
        except ValueError as exc:
            raise PortSpecError(f"puerto inválido: {part!r}") from exc
        if not (1 <= lo <= hi <= 65535):
            raise PortSpecError(f"rango fuera de 1-65535: {part!r}")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise PortSpecError("especificación de puertos vacía")
    return sorted(ports)


def top_ports(n: int, services_file: Path = _NMAP_SERVICES) -> list[int]:
    """Los n puertos TCP más frecuentes, usando la base de nmap si existe."""
    if n < 1:
        raise PortSpecError("--top-ports debe ser >= 1")
    ranked: list[tuple[float, int]] = []
    try:
        for line in services_file.read_text(errors="replace").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            fields = line.split()
            if len(fields) < 3 or not fields[1].endswith("/tcp"):
                continue
            try:
                ranked.append((float(fields[2]), int(fields[1].split("/")[0])))
            except ValueError:
                continue
    except OSError:
        pass
    if ranked:
        ranked.sort(key=lambda t: (-t[0], t[1]))
        seen: list[int] = []
        for _, port in ranked:
            if port not in seen:
                seen.append(port)
        return seen[:n]
    return _FALLBACK_TOP[:n]
