"""Parsers de logs a eventos de conexión: iptables/UFW (kernel) y Suricata eve.json."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator

_KV = re.compile(r"\b(SRC|DST|PROTO|DPT)=(\S+)")
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass(frozen=True)
class Event:
    ts: float
    src: str
    dst: str
    dport: int
    proto: str = "TCP"


def _parse_iso(text: str) -> float | None:
    try:
        dt = datetime.fromisoformat(text.replace(",", ".").replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()  # hora local del sistema
    return dt.timestamp()


def _parse_kernel_ts(line: str, year: int) -> float | None:
    m = _ISO_TS.match(line)
    if m:
        return _parse_iso(m.group(1))
    m = _SYSLOG_TS.match(line)
    if m and m.group(1) in _MONTHS:
        h, mi, s = (int(x) for x in m.group(3).split(":"))
        try:
            dt = datetime(year, _MONTHS[m.group(1)], int(m.group(2)), h, mi, s)
        except ValueError:
            return None
        return dt.astimezone().timestamp()
    return None


def parse_kernel_line(line: str, year: int | None = None) -> Event | None:
    """Línea de iptables LOG / UFW BLOCK. Solo SYN inicial (sin ACK) o UDP."""
    fields = dict(_KV.findall(line))
    if not {"SRC", "DST", "PROTO", "DPT"} <= fields.keys():
        return None
    proto = fields["PROTO"].upper()
    if proto not in ("TCP", "UDP"):
        return None
    if proto == "TCP":
        flags = set(line.split())
        if "SYN" not in flags or "ACK" in flags:
            return None
    ts = _parse_kernel_ts(line, year or datetime.now().year)
    if ts is None:
        return None
    try:
        dport = int(fields["DPT"])
    except ValueError:
        return None
    return Event(ts, fields["SRC"], fields["DST"], dport, proto)


# En un flujo normal (web, API) el servidor envía muchos paquetes; un escaneo deja
# flujos que no pasan del SYN-ACK / RST / ACK-FIN.
MAX_SCAN_PKTS_TOCLIENT = 2


def _looks_like_scan_flow(obj: dict) -> bool:
    flow = obj.get("flow")
    if not isinstance(flow, dict) or "pkts_toclient" not in flow:
        return True  # sin estadísticas no se puede descartar
    try:
        return int(flow["pkts_toclient"]) <= MAX_SCAN_PKTS_TOCLIENT
    except (TypeError, ValueError):
        return True


def parse_eve_line(line: str, include_established: bool = False) -> Event | None:
    """Evento de eve.json. Los `flow` con tráfico real (muchos paquetes del servidor)
    se descartan por defecto: un cliente que navega a 20 servidores :443 no es un
    barrido. Las `alert` y `anomaly` siempre cuentan."""
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("event_type") not in ("flow", "alert", "anomaly"):
        return None
    try:
        ts = _parse_iso(obj["timestamp"])
        dport = int(obj["dest_port"])
        src, dst = obj["src_ip"], obj["dest_ip"]
    except (KeyError, TypeError, ValueError):
        return None
    if ts is None:
        return None
    if (obj["event_type"] == "flow" and not include_established
            and not _looks_like_scan_flow(obj)):
        return None
    return Event(ts, src, dst, dport, str(obj.get("proto", "TCP")).upper())


def parse_lines(lines: Iterable[str], fmt: str = "auto", year: int | None = None,
                include_established: bool = False) -> Iterator[Event]:
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if fmt == "eve" or (fmt == "auto" and line.startswith("{")):
            ev = parse_eve_line(line, include_established)
        else:
            ev = parse_kernel_line(line, year)
        if ev is not None:
            yield ev


def format_kernel_line(ev: Event, host: str = "lab", sport: int = 40000) -> str:
    """Genera una línea tipo UFW BLOCK; útil para tests y experimentos."""
    ts = datetime.fromtimestamp(ev.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    return (f"{ts} {host} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ev.src} DST={ev.dst} "
            f"LEN=60 TOS=0x00 TTL=64 ID=1 DF PROTO={ev.proto} SPT={sport} DPT={ev.dport} "
            f"WINDOW=64240 RES=0x00 SYN URGP=0")


def format_eve_flow(ev: Event, pkts_toclient: int = 1) -> str:
    """Línea eve.json tipo `flow`; útil para tests y experimentos."""
    ts = datetime.fromtimestamp(ev.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    return json.dumps({
        "timestamp": ts, "event_type": "flow", "src_ip": ev.src, "dest_ip": ev.dst,
        "src_port": 40000, "dest_port": ev.dport, "proto": ev.proto,
        "flow": {"pkts_toserver": max(1, pkts_toclient), "pkts_toclient": pkts_toclient},
    })
