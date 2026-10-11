"""Motor de escaneo TCP connect concurrente con límite de velocidad y banners."""

from __future__ import annotations

import errno
import random
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from portscan.models import PortResult, PortState
from portscan.ratelimit import RateLimiter
from portscan.services import HTTP_PORTS, TLS_PORTS, identify, name_for_port

BANNER_MAX = 200
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nUser-Agent: portscan\r\n\r\n"

# errno que indican "no hay ruta/filtrado", no "puerto cerrado"
_FILTERED_ERRNOS = {
    errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH,
    errno.EHOSTDOWN, errno.ENETDOWN, errno.EACCES, errno.EPERM,
}


@dataclass
class ScanConfig:
    rate: float = 100.0
    timeout: float = 1.0
    workers: int = 64
    banners: bool = False
    banner_timeout: float = 1.0
    shuffle: bool = False


def _decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _clean(raw: bytes) -> str:
    text = _decode(raw)
    first = text.replace("\r", "\n").split("\n", 1)[0] if text.strip() else ""
    printable = "".join(c if c.isprintable() else " " for c in first).strip()
    return printable[:BANNER_MAX]


def _recv(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(1024)
    except (socket.timeout, OSError):
        return b""


def _http_server_line(raw: bytes) -> str:
    """De una respuesta HTTP completa, devuelve 'HTTP/1.1 200 OK | Server: x'."""
    lines = _decode(raw).replace("\r", "").split("\n")
    status = lines[0].strip() if lines else ""
    server = next((l.strip() for l in lines[1:] if l.lower().startswith("server:")), "")
    joined = f"{status} | {server}" if server else status
    return _clean(joined.encode("utf-8"))


def grab_banner(sock: socket.socket, port: int, host: str, cfg: ScanConfig) -> tuple[str, str]:
    """Devuelve (banner, tls_info). Pasivo primero; sondea HTTP/TLS si hace falta."""
    tls_info = ""
    if port in TLS_PORTS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(cfg.banner_timeout + 1)
            with ctx.wrap_socket(sock, server_hostname=None) as tls:
                tls_info = f"{tls.version()} {tls.cipher()[0] if tls.cipher() else ''}".strip()
                if port in (443, 8443):
                    tls.sendall(_HTTP_PROBE)
                    return _http_server_line(tls.recv(2048)), tls_info
                return _clean(tls.recv(1024)), tls_info
        except (ssl.SSLError, OSError):
            return "", tls_info
    # Pasivo primero (SSH, FTP, SMTP hablan primero). En puertos web esperamos poco.
    banner = _recv(sock, cfg.banner_timeout if port not in HTTP_PORTS else 0.3)
    if banner:
        return _clean(banner), tls_info
    # Servicios que esperan al cliente: una petición HTTP provoca respuesta o error
    # reconocible (HTTP, Redis "-ERR", etc.) incluso en puertos no estándar.
    try:
        sock.sendall(_HTTP_PROBE)
    except OSError:
        return "", tls_info
    reply = _recv(sock, cfg.banner_timeout)
    if reply.startswith(b"HTTP/"):
        return _http_server_line(reply), tls_info
    return _clean(reply), tls_info


def probe_port(host: str, port: int, cfg: ScanConfig) -> PortResult:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(cfg.timeout)
    try:
        code = sock.connect_ex((host, port))
        if code == 0:
            banner = tls = ""
            if cfg.banners:
                banner, tls = grab_banner(sock, port, host, cfg)
            service = identify(port, banner) if banner else name_for_port(port)
            return PortResult(host, port, PortState.OPEN, service=service,
                              banner=banner, tls=tls)
        if code == errno.ECONNREFUSED or code == errno.ECONNRESET:
            return PortResult(host, port, PortState.CLOSED)
        return PortResult(host, port, PortState.FILTERED)
    except socket.timeout:
        return PortResult(host, port, PortState.FILTERED)
    except OSError as exc:
        state = PortState.FILTERED if exc.errno in _FILTERED_ERRNOS else PortState.CLOSED
        return PortResult(host, port, state)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def scan(
    hosts: list[str],
    ports: list[int],
    cfg: ScanConfig,
    on_result: Callable[[PortResult], None] | None = None,
    on_attempt: Callable[[float, str, int], None] | None = None,
    stop: threading.Event | None = None,
) -> list[PortResult]:
    """Escanea host x puerto. `on_attempt(ts, host, port)` se llama antes de cada conexión."""
    pairs = [(h, p) for h in hosts for p in ports]
    if cfg.shuffle:
        random.shuffle(pairs)
    limiter = RateLimiter(cfg.rate)
    stop = stop or threading.Event()
    lock = threading.Lock()
    results: list[PortResult] = []

    def work(pair: tuple[str, int]) -> None:
        if stop.is_set():
            return
        limiter.acquire()
        if stop.is_set():
            return
        host, port = pair
        if on_attempt:
            on_attempt(time.time(), host, port)
        res = probe_port(host, port, cfg)
        with lock:
            results.append(res)
            if on_result:
                on_result(res)

    with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as pool:
        list(pool.map(work, pairs))
    results.sort(key=lambda r: (r.host, r.port))
    return results
