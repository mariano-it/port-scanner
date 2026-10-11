"""portscan-detect: busca escaneos de puertos (T1046) en logs de firewall/Suricata."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from portscan.detect.detector import DEFAULT_RULES, DIST, Rule, detect
from portscan.detect.parsers import parse_lines


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="portscan-detect",
        description="Detecta IPs que tocan muchos puertos/hosts distintos en poco tiempo.",
    )
    p.add_argument("logs", nargs="+", help="logs UFW/iptables o Suricata eve.json ('-' = stdin)")
    p.add_argument("--format", choices=["auto", "kernel", "eve"], default="auto")
    p.add_argument("--window", type=float, default=DEFAULT_RULES[0].window,
                   help="ventana rápida en segundos (default 10)")
    p.add_argument("--threshold", type=int, default=DEFAULT_RULES[0].threshold,
                   help="destinos distintos para alertar en la ventana rápida (default 15)")
    p.add_argument("--slow-window", type=float, default=DEFAULT_RULES[1].window,
                   help="ventana lenta en segundos (default 3600)")
    p.add_argument("--slow-threshold", type=int, default=DEFAULT_RULES[1].threshold,
                   help="umbral de la ventana lenta (default 40; 0 la desactiva)")
    p.add_argument("--dist-window", type=float, default=DIST.window,
                   help="ventana de la regla distribuida (default 60)")
    p.add_argument("--dist-threshold", type=int, default=DIST.threshold,
                   help="puertos distintos recibidos por un destino (default 20; 0 la desactiva)")
    p.add_argument("--dist-min-sources", type=int, default=DIST.min_sources,
                   help="orígenes distintos mínimos (default 5)")
    p.add_argument("--allow", action="append", default=[], metavar="IP",
                   help="IP a ignorar (monitoreo, scanners autorizados)")
    p.add_argument("--eve-include-established", action="store_true",
                   help="cuenta también flujos eve con tráfico real (más falsos positivos)")
    p.add_argument("--year", type=int, help="año para logs syslog sin año")
    p.add_argument("--json", action="store_true", help="salida JSON")
    args = p.parse_args(argv)

    rules = [Rule("fast", args.window, args.threshold)]
    if args.slow_threshold > 0:
        rules.append(Rule("slow", args.slow_window, args.slow_threshold))

    if args.dist_threshold > 0:
        rules.append(Rule("distributed", args.dist_window, args.dist_threshold,
                          "dst", args.dist_min_sources))

    def lines():
        for path in args.logs:
            if path == "-":
                yield from sys.stdin
            else:
                with open(path, errors="replace") as fh:
                    yield from fh

    events = list(parse_lines(lines(), args.format, args.year, args.eve_include_established))
    alerts = detect(events, rules, args.allow)

    if args.json:
        json.dump({"events_parsed": len(events), "alerts": [a.to_dict() for a in alerts]},
                  sys.stdout, indent=2)
        print()
    else:
        print(f"{len(events)} eventos analizados, {len(alerts)} alerta(s)")
        for a in alerts:
            src = a.src if a.kind != "distributed" else f"{len(a.srcs)} IPs -> {sorted(a.hosts)[0]}"
            print(f"[{a.technique}] {a.rule:<11} {a.kind:<11} src={src} "
                  f"puertos={len(a.ports)} hosts={len(a.hosts)} "
                  f"{_fmt(a.first_ts)} -> detectado tras {a.time_to_detect:.1f}s")
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
