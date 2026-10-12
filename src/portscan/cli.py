"""CLI: portscan --scope scope.txt TARGET... [-p 1-1024 | --top-ports N] ..."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from portscan import __version__
from portscan.analyze import analyze
from portscan.audit import AuditLog, new_scan_id
from portscan.models import ModuleResult, PortResult, PortState, Report
from portscan.ports import PortSpecError, parse_ports, top_ports
from portscan.report.json_report import render_json
from portscan.report.markdown_report import render_markdown
from portscan.scanner import DISCOVERY_PORTS, ScanConfig, _host_key, discover, scan
from portscan.scope import ScopeError, load_scope, resolve_targets

EXIT_OK, EXIT_ERROR, EXIT_SCOPE = 0, 1, 2
MAX_RATE = 5000.0
HARD_MAX_HOSTS = 1 << 16        # un /16 completo; más requiere dividir el trabajo
DISCOVER_AUTO_OVER = 256        # por encima de esto, el descubrimiento se activa solo


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscan",
        description="Scanner de puertos TCP connect con alcance obligatorio y auditoría.",
        epilog="Úsalo solo en sistemas propios o con autorización por escrito.",
    )
    p.add_argument("targets", nargs="+", help="IP, CIDR u hostname (deben estar en --scope)")
    p.add_argument("--scope", required=True, help="archivo con el alcance autorizado")
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("-p", "--ports", help="ej. 22,80,1-1024 o '-' para todos (default: 1-1024)")
    sel.add_argument("--top-ports", type=int, metavar="N", help="los N puertos más comunes")
    p.add_argument("--rate", type=float, default=100.0, help="intentos por segundo (default 100)")
    p.add_argument("--timeout", type=float, default=1.0, help="segundos por conexión (default 1)")
    p.add_argument("--workers", type=int, default=64,
                   help="hilos concurrentes (default 64; usa 256 para un /16)")
    p.add_argument("--banners", action="store_true", help="captura banners / info TLS")
    p.add_argument("--shuffle", action="store_true", help="orden aleatorio de puertos")
    p.add_argument("--allow-public", action="store_true", help="permite IPs públicas")
    p.add_argument("--max-hosts", type=int, default=1024,
                   help=f"tope de hosts (default 1024, máximo {HARD_MAX_HOSTS}: un /16)")
    disc = p.add_mutually_exclusive_group()
    disc.add_argument("--discover", action="store_true",
                      help="descubre hosts vivos antes de escanear puertos "
                           f"(automático con más de {DISCOVER_AUTO_OVER} hosts)")
    disc.add_argument("--no-discovery", action="store_true",
                      help="escanea todos los hosts aunque no respondan al descubrimiento")
    p.add_argument("--discovery-ports", default=",".join(map(str, DISCOVERY_PORTS)),
                   help="puertos del descubrimiento (default %(default)s)")
    p.add_argument("--discover-only", action="store_true",
                   help="solo lista los hosts vivos y termina")
    p.add_argument("--all", dest="show_all", action="store_true",
                   help="muestra también puertos cerrados/filtrados")
    p.add_argument("-o", "--output", action="append", default=[], metavar="FILE",
                   help="reporte .json o .md (repetible)")
    p.add_argument("--audit-log", help="ruta del log de auditoría (JSONL)")
    p.add_argument("--progress", action="store_true", help="barra de progreso en stderr")
    p.add_argument("-q", "--quiet", action="store_true", help="sin tabla en pantalla")
    p.add_argument("--version", action="version", version=f"portscan {__version__}")
    return p


class _Progress:
    """Progreso en stderr con velocidad y ETA. Seguro entre hilos."""

    def __init__(self, label: str, total: int, enabled: bool):
        self.label, self.total, self.enabled = label, max(total, 1), enabled
        self.done = 0
        self.start = time.time()
        self._last = 0.0
        self._lock = threading.Lock()

    def tick(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.done += 1
            now = time.time()
            if self.done != self.total and now - self._last < 0.25:
                return
            self._last = now
            elapsed = max(now - self.start, 1e-6)
            rate = self.done / elapsed
            eta = (self.total - self.done) / rate if rate else 0
            sys.stderr.write(
                f"\r  {self.label}: {self.done}/{self.total} "
                f"({100 * self.done // self.total}%)  {rate:,.0f}/s  ETA {_fmt_secs(eta)}   ")
            sys.stderr.flush()

    def finish(self) -> None:
        if self.enabled:
            sys.stderr.write("\n")


def _fmt_secs(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


def _print_table(results: list[PortResult], show_all: bool, out) -> None:
    rows = [r for r in results if show_all or r.state is PortState.OPEN]
    if not rows:
        print("Sin puertos abiertos.", file=out)
        return
    w_host = max(len("HOST"), *(len(r.host) for r in rows))
    print(f"{'HOST':<{w_host}}  {'PUERTO':<9} {'ESTADO':<9} {'SERVICIO':<14} BANNER", file=out)
    for r in rows:
        extra = f"{r.banner}" + (f" [{r.tls}]" if r.tls else "")
        print(f"{r.host:<{w_host}}  {r.port:<5}/tcp {r.state.value:<9} {r.service:<14} {extra}",
              file=out)


def _diagnose(counts: Counter, hosts_alive: int | None, discovered: bool) -> list[str]:
    """Qué significa 'no hay puertos abiertos', según lo que sí se observó."""
    total = sum(counts.values())
    if total == 0:
        return []
    tips: list[str] = []
    filtered, closed = counts.get("filtered", 0), counts.get("closed", 0)
    if filtered / total > 0.9:
        tips.append("Casi todo salió 'filtered': un firewall descarta el tráfico, el host está "
                    "apagado o --timeout es corto para esa red. Prueba --timeout 3 y menos --rate.")
    elif closed / total > 0.9:
        tips.append("Casi todo salió 'closed': los hosts responden (RST) pero no hay servicios "
                    "en esos puertos. Prueba otros: -p 1-10000 o --top-ports 1000.")
    if discovered and hosts_alive == 0:
        tips.append("Ningún host respondió al descubrimiento. Sin raw sockets/ICMP solo se "
                    "ve TCP en --discovery-ports; si el firewall los descarta, usa "
                    "--no-discovery o ajusta --discovery-ports.")
    return tips


def _write_private(path: str, text: str) -> None:
    """Los reportes contienen la topología de la red: solo lectura del dueño (0600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)  # también si el archivo ya existía con otros permisos


def _write_reports(report: Report, paths: list[str]) -> None:
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix == ".json":
            _write_private(path, render_json(report))
        elif suffix in (".md", ".markdown"):
            _write_private(path, render_markdown(report))
        else:
            raise ValueError(f"extensión no soportada para -o: {path!r} (usa .json o .md)")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    audit = AuditLog(args.audit_log)
    scan_id = new_scan_id()

    def refuse(reason: str, code: int) -> int:
        print(f"portscan: {reason}", file=sys.stderr)
        audit.write("denied", scan_id, argv=argv, reason=reason)
        return code

    for out in args.output:
        if Path(out).suffix.lower() not in (".json", ".md", ".markdown"):
            return refuse(f"extensión no soportada para -o: {out!r} (usa .json o .md)", EXIT_ERROR)
    if not (0 < args.rate <= MAX_RATE):
        return refuse(f"--rate debe estar entre 0 y {MAX_RATE:g}", EXIT_ERROR)
    if args.timeout <= 0 or args.workers < 1:
        return refuse("--timeout y --workers deben ser positivos", EXIT_ERROR)
    if not (1 <= args.max_hosts <= HARD_MAX_HOSTS):
        return refuse(f"--max-hosts debe estar entre 1 y {HARD_MAX_HOSTS}", EXIT_ERROR)
    try:
        if args.top_ports is not None:
            ports = top_ports(args.top_ports)
        else:
            ports = parse_ports(args.ports or "1-1024")
    except PortSpecError as exc:
        return refuse(str(exc), EXIT_ERROR)

    try:
        scope = load_scope(args.scope)
        hosts = resolve_targets(args.targets, scope, args.allow_public, args.max_hosts)
    except ScopeError as exc:
        return refuse(str(exc), EXIT_SCOPE)

    if args.allow_public and any(_is_public(h) for h in hosts) and sys.stdin.isatty():
        answer = input("IPs públicas en el objetivo. ¿Tienes autorización escrita? [escribe SI]: ")
        if answer.strip() != "SI":
            return refuse("confirmación de IP pública no otorgada", EXIT_SCOPE)

    cfg = ScanConfig(rate=args.rate, timeout=args.timeout, workers=args.workers,
                     banners=args.banners, shuffle=args.shuffle)
    do_discovery = args.discover or args.discover_only or (
        not args.no_discovery and len(hosts) > DISCOVER_AUTO_OVER)
    try:
        disc_ports = parse_ports(args.discovery_ports)
    except PortSpecError as exc:
        return refuse(f"--discovery-ports: {exc}", EXIT_ERROR)

    started = time.time()
    audit.write("start", scan_id, argv=argv, scope_file=scope.path,
                scope_sha256=scope.sha256, target_specs=args.targets,
                targets=hosts if len(hosts) <= 64 else len(hosts),
                ports=len(ports), rate=cfg.rate, banners=cfg.banners,
                discovery=do_discovery)

    stop = threading.Event()
    stats: Counter = Counter()
    results: list[PortResult] = []
    alive: list[str] = list(hosts)
    aborted = False
    quiet = args.quiet

    try:
        if do_discovery:
            prog = _Progress("descubrimiento", len(hosts), args.progress)
            alive = discover(hosts, cfg, disc_ports, on_host=lambda h, up: prog.tick(),
                             stop=stop)
            prog.finish()
            audit.write("discovery", scan_id, hosts=len(hosts), alive=len(alive),
                        elapsed=round(time.time() - started, 2))
            if not quiet:
                print(f"Descubrimiento: {len(alive)} de {len(hosts)} hosts responden "
                      f"({','.join(map(str, disc_ports))})")
        if not args.discover_only and alive:
            prog = _Progress("escaneo", len(alive) * len(ports), args.progress)
            scan(alive, ports, cfg, on_result=lambda _r: prog.tick(), stop=stop,
                 keep_all=args.show_all, stats=stats, into=results)
            prog.finish()
    except KeyboardInterrupt:
        stop.set()
        aborted = True
        audit.write("aborted", scan_id, elapsed=round(time.time() - started, 2),
                    states=dict(stats), open_found=len(results))
        print("\nportscan: interrumpido (se guardan los resultados parciales)",
              file=sys.stderr)

    results.sort(key=lambda r: (_host_key(r.host), r.port))
    counts = dict(stats)
    findings = analyze(results)
    elapsed = time.time() - started
    if not aborted:
        audit.write("end", scan_id, elapsed=round(elapsed, 2), states=counts,
                    findings=len(findings), hosts_alive=len(alive))

    target_label = ", ".join(args.targets)
    meta = {
        "scan_id": scan_id, "scope_file": scope.path, "scope_sha256": scope.sha256,
        "hosts": len(hosts), "hosts_alive": len(alive) if do_discovery else None,
        "discovery": do_discovery, "ports_scanned": 0 if args.discover_only else len(ports),
        "rate": cfg.rate, "elapsed_s": round(elapsed, 2), "state_counts": counts,
        "aborted": aborted,
    }
    data: dict = {"meta": meta,
                  "ports": [r.to_dict() for r in results
                            if r.state is PortState.OPEN or args.show_all]}
    if args.discover_only or do_discovery:
        data["alive_hosts"] = alive if len(alive) <= 5000 else alive[:5000]
    result = ModuleResult(module="portscan", target=target_label, data=data,
                          findings=findings)
    report = Report(target=target_label, results=[result])
    try:
        _write_reports(report, args.output)
    except OSError as exc:
        print(f"portscan: no se pudo escribir el reporte: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not quiet:
        if args.discover_only:
            for h in alive:
                print(h)
        else:
            print(f"Scan {scan_id}: {len(alive)} host(s) x {len(ports)} puertos "
                  f"en {elapsed:.1f}s  {counts}")
            _print_table(results, args.show_all, sys.stdout)
            if not any(r.state is PortState.OPEN for r in results):
                for tip in _diagnose(stats, len(alive), do_discovery):
                    print(f"  * {tip}")
            if findings:
                print("\nHallazgos:")
                for f in findings:
                    print(f"  [{f.severity.label.upper():6}] {f.title}  ({f.evidence})")
                    print(f"           -> {f.remediation}")
    return EXIT_ERROR if aborted else EXIT_OK


def _is_public(host: str) -> bool:
    import ipaddress
    return ipaddress.ip_address(host).is_global


if __name__ == "__main__":
    raise SystemExit(main())
