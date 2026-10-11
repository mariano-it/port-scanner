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
from portscan.scanner import ScanConfig, scan
from portscan.scope import ScopeError, load_scope, resolve_targets

EXIT_OK, EXIT_ERROR, EXIT_SCOPE = 0, 1, 2
MAX_RATE = 5000.0


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
    p.add_argument("--workers", type=int, default=64, help="hilos concurrentes (default 64)")
    p.add_argument("--banners", action="store_true", help="captura banners / info TLS")
    p.add_argument("--shuffle", action="store_true", help="orden aleatorio de puertos")
    p.add_argument("--allow-public", action="store_true", help="permite IPs públicas")
    p.add_argument("--max-hosts", type=int, default=1024, help="tope de hosts (default 1024)")
    p.add_argument("--all", dest="show_all", action="store_true",
                   help="muestra también puertos cerrados/filtrados")
    p.add_argument("-o", "--output", action="append", default=[], metavar="FILE",
                   help="reporte .json o .md (repetible)")
    p.add_argument("--audit-log", help="ruta del log de auditoría (JSONL)")
    p.add_argument("--progress", action="store_true", help="barra de progreso en stderr")
    p.add_argument("-q", "--quiet", action="store_true", help="sin tabla en pantalla")
    p.add_argument("--version", action="version", version=f"portscan {__version__}")
    return p


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
    started = time.time()
    audit.write("start", scan_id, argv=argv, scope_file=scope.path,
                scope_sha256=scope.sha256, targets=hosts if len(hosts) <= 64 else len(hosts),
                ports=len(ports), rate=cfg.rate, banners=cfg.banners)

    stop = threading.Event()
    total = len(hosts) * len(ports)
    done = [0]
    on_result = None
    if args.progress:
        def on_result(_res: PortResult) -> None:
            done[0] += 1
            if done[0] % 25 == 0 or done[0] == total:
                pct = 100 * done[0] // total
                sys.stderr.write(f"\r  progreso: {done[0]}/{total} ({pct}%)")
                sys.stderr.flush()
                if done[0] == total:
                    sys.stderr.write("\n")
    try:
        results = scan(hosts, ports, cfg, on_result=on_result, stop=stop)
    except KeyboardInterrupt:
        stop.set()
        audit.write("aborted", scan_id, elapsed=round(time.time() - started, 2))
        print("\nportscan: interrumpido", file=sys.stderr)
        return EXIT_ERROR

    counts = Counter(r.state.value for r in results)
    findings = analyze(results)
    elapsed = time.time() - started
    audit.write("end", scan_id, elapsed=round(elapsed, 2), states=dict(counts),
                findings=len(findings))

    target_label = ", ".join(args.targets)
    result = ModuleResult(
        module="portscan",
        target=target_label,
        data={
            "meta": {
                "scan_id": scan_id, "scope_file": scope.path,
                "scope_sha256": scope.sha256, "hosts": len(hosts),
                "ports_scanned": len(ports), "rate": cfg.rate,
                "elapsed_s": round(elapsed, 2), "state_counts": dict(counts),
            },
            "ports": [r.to_dict() for r in results if r.state is PortState.OPEN or args.show_all],
        },
        findings=findings,
    )
    report = Report(target=target_label, results=[result])
    try:
        _write_reports(report, args.output)
    except OSError as exc:
        print(f"portscan: no se pudo escribir el reporte: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        print(f"Scan {scan_id}: {len(hosts)} host(s) x {len(ports)} puertos "
              f"en {elapsed:.1f}s  {dict(counts)}")
        _print_table(results, args.show_all, sys.stdout)
        if findings:
            print("\nHallazgos:")
            for f in findings:
                print(f"  [{f.severity.label.upper():6}] {f.title}  ({f.evidence})")
                print(f"           -> {f.remediation}")
    return EXIT_OK


def _is_public(host: str) -> bool:
    import ipaddress
    return ipaddress.ip_address(host).is_global


if __name__ == "__main__":
    raise SystemExit(main())
