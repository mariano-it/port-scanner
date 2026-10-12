"""Motor de escaneo TCP connect concurrente con límite de velocidad y banners."""

from __future__ import annotations

import errno
import random
import socket
import ssl
import threading
import time
import warnings
import ipaddress
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

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


LEGACY_TLS = ("TLSv1", "TLSv1_1")


def probe_legacy_tls(host: str, port: int, timeout: float = 2.0) -> list[str]:
    """Versiones TLS obsoletas que el servidor ACEPTA, probando cada una por separado.

    Fija minimum_version == maximum_version: un handshake normal negociaría la mejor
    versión y jamás revelaría que además acepta TLS 1.0/1.1. Si el OpenSSL local no
    puede hablar esa versión, simplemente no se reporta (no hay falso positivo).
    """
    accepted: list[str] = []
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for name in LEGACY_TLS:
        version = getattr(ssl.TLSVersion, name)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers("ALL:@SECLEVEL=0")
                ctx.minimum_version = version
                ctx.maximum_version = version
            with socket.socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(timeout)
                raw.connect((host, port))
                with ctx.wrap_socket(raw, server_hostname=None):
                    accepted.append(name.replace("_", "."))
        except (ssl.SSLError, OSError, ValueError):
            continue
    return accepted


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
    """Devuelve (banner, tls_info). Pasivo primero; sondea HTTP/TLS si hace falta.
    Las versiones TLS obsoletas se sondean aparte (probe_legacy_tls)."""
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
            legacy: list[str] = []
            if cfg.banners:
                banner, tls = grab_banner(sock, port, host, cfg)
                if tls:
                    legacy = probe_legacy_tls(host, port, cfg.banner_timeout + 1)
            service = identify(port, banner) if banner else name_for_port(port)
            return PortResult(host, port, PortState.OPEN, service=service,
                              banner=banner, tls=tls, tls_legacy=legacy)
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


class _Feeder:
    """Iterador compartido entre hilos: reparte trabajo sin materializar la lista."""

    def __init__(self, items: Iterable):
        self._it = iter(items)
        self._lock = threading.Lock()

    def next(self):
        with self._lock:
            return next(self._it, None)  # los items nunca son None


def _run_workers(items: Iterable, work: Callable, workers: int, stop: threading.Event) -> None:
    """Ejecuta work(item) en `workers` hilos. Ctrl+C detiene y propaga limpiamente."""
    feeder = _Feeder(items)
    errors: list[BaseException] = []

    def loop() -> None:
        while not stop.is_set():
            item = feeder.next()
            if item is None:
                return
            try:
                work(item)
            except BaseException as exc:  # noqa: BLE001 - se re-lanza en el hilo principal
                errors.append(exc)
                stop.set()
                return

    threads = [threading.Thread(target=loop, daemon=True) for _ in range(max(1, workers))]
    for t in threads:
        t.start()
    try:
        for t in threads:
            while t.is_alive():
                t.join(0.2)
    except KeyboardInterrupt:
        stop.set()
        raise
    if errors:
        raise errors[0]


def _pairs(hosts: list[str], ports: list[int], shuffle: bool) -> Iterator[tuple[str, int]]:
    """host x puerto perezoso: O(hosts + ports) de memoria aunque sean millones."""
    order = list(hosts)
    plist = list(ports)
    if shuffle:
        random.shuffle(order)
    for host in order:
        if shuffle:
            random.shuffle(plist)
        for port in plist:
            yield host, port


def scan(
    hosts: list[str],
    ports: list[int],
    cfg: ScanConfig,
    on_result: Callable[[PortResult], None] | None = None,
    on_attempt: Callable[[float, str, int], None] | None = None,
    stop: threading.Event | None = None,
    keep_all: bool = True,
    stats: Counter | None = None,
    into: list[PortResult] | None = None,
) -> list[PortResult]:
    """Escanea host x puerto en streaming.

    `on_attempt(ts, host, port)` se llama antes de cada conexión. Con keep_all=False
    solo se conservan los puertos abiertos (un /16 genera millones de cerrados);
    `stats` acumula el conteo por estado de TODO lo probado. `into` es la lista donde
    se acumulan los resultados: así quedan disponibles si el escaneo se interrumpe.
    """
    limiter = RateLimiter(cfg.rate)
    stop = stop or threading.Event()
    lock = threading.Lock()
    results: list[PortResult] = into if into is not None else []

    def work(pair: tuple[str, int]) -> None:
        limiter.acquire()
        if stop.is_set():
            return
        host, port = pair
        if on_attempt:
            on_attempt(time.time(), host, port)
        res = probe_port(host, port, cfg)
        with lock:
            if stats is not None:
                stats[res.state.value] += 1
            if keep_all or res.state is PortState.OPEN:
                results.append(res)
            if on_result:
                on_result(res)

    _run_workers(_pairs(hosts, ports, cfg.shuffle), work, cfg.workers, stop)
    results.sort(key=lambda r: (_host_key(r.host), r.port))
    return results


def _host_key(host: str):
    try:
        ip = ipaddress.ip_address(host)
        return (ip.version, int(ip))
    except ValueError:
        return (0, host)


DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 8080]


def discover(
    hosts: list[str],
    cfg: ScanConfig,
    ports: list[int] | None = None,
    on_host: Callable[[str, bool], None] | None = None,
    stop: threading.Event | None = None,
) -> list[str]:
    """Hosts "vivos": responden a algún puerto con SYN-ACK **o con RST**.

    Un RST (puerto cerrado) también prueba que el host existe. Sin raw sockets no hay
    ICMP, así que un host que descarta TODO el tráfico a estos puertos no se ve; si
    sospechas de eso, salta el descubrimiento (--no-discovery). Se detiene en el primer
    puerto que responde, por lo que los hosts vivos cuestan 1-2 intentos.
    """
    probe_ports = ports or DISCOVERY_PORTS
    probe_cfg = ScanConfig(rate=cfg.rate, timeout=cfg.timeout, workers=cfg.workers,
                           banners=False)
    limiter = RateLimiter(cfg.rate)
    stop = stop or threading.Event()
    lock = threading.Lock()
    alive: set[str] = set()

    def work(host: str) -> None:
        up = False
        for port in probe_ports:
            limiter.acquire()
            if stop.is_set():
                return
            if probe_port(host, port, probe_cfg).state is not PortState.FILTERED:
                up = True
                break
        with lock:
            if up:
                alive.add(host)
            if on_host:
                on_host(host, up)

    _run_workers(hosts, work, cfg.workers, stop)
    return sorted(alive, key=_host_key)
