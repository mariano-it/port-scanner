#!/usr/bin/env python3
"""Experimento purple team: ¿qué detecta el detector y qué se le escapa?

Genera perfiles de escaneo (rápido, lento, distribuido, barrido horizontal...) más
tráfico benigno, los convierte a líneas de log tipo UFW, los pasa por el parser y el
detector reales y escribe una tabla de resultados.

Los perfiles son SIMULADOS en tiempo (un escaneo de 1 puerto/min no se ejecuta en
real); el perfil "live" sí ejecuta el scanner real contra servicios locales y alimenta
al detector con los intentos reales. Esto valida el pipeline completo.

Uso: PYTHONPATH=src python3 experiments/run_experiment.py [-o experiments/results.md]
"""

from __future__ import annotations

import argparse
import random
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "lab"))

from portscan.detect.detector import DEFAULT_RULES, Rule, detect  # noqa: E402
from portscan.detect.parsers import (  # noqa: E402
    Event, format_eve_flow, format_kernel_line, parse_lines)

T0 = 1_760_000_000.0
TARGET = "10.0.0.5"
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432,
             5900, 6379, 8080, 8443]


@dataclass
class Profile:
    name: str
    description: str
    malicious: bool
    events: list[Event]
    fmt: str = "kernel"          # formato de log por el que pasa: kernel | eve
    pkts_toclient: int = 1       # solo eve: paquetes del servidor por flujo


def seq_scan(src: str, ports: list[int], rate: float, start: float = T0,
             host: str = TARGET, jitter: float = 0.0, rng: random.Random | None = None):
    rng = rng or random.Random(1)
    out, t = [], start
    for p in ports:
        out.append(Event(t, src, host, p))
        t += (1.0 / rate) * (1 + rng.uniform(-jitter, jitter))
    return out


def build_profiles() -> list[Profile]:
    rng = random.Random(42)
    shuffled = list(range(1, 1025))
    rng.shuffle(shuffled)
    ps: list[Profile] = []
    ps.append(Profile("A. Rápido secuencial", "1-1024 a 1000 puertos/s", True,
                      seq_scan("203.0.113.10", list(range(1, 1025)), 1000)))
    ps.append(Profile("B. Moderado (100/s)", "1-1024 a 100 puertos/s", True,
                      seq_scan("203.0.113.11", list(range(1, 1025)), 100)))
    ps.append(Profile("C. Lento aleatorio (1/s)", "1024 puertos barajados, 1 por segundo", True,
                      seq_scan("203.0.113.12", shuffled, 1, jitter=0.3, rng=rng)))
    ps.append(Profile("D. Muy lento (1 / 30 s)", "1024 puertos, uno cada 30 s (~8,5 h)", True,
                      seq_scan("203.0.113.13", shuffled, 1 / 30, jitter=0.5, rng=rng)))
    ps.append(Profile("E. Paranoico (1 / 5 min)", "100 puertos, uno cada 5 min (~8 h)", True,
                      seq_scan("203.0.113.14", shuffled[:100], 1 / 300, jitter=0.5, rng=rng)))
    dist: list[Event] = []
    chunk = 8
    for i in range(128):
        dist += seq_scan(f"198.51.{100 + i // 250}.{i % 250 + 1}",
                         shuffled[i * chunk:(i + 1) * chunk], 5,
                         start=T0 + rng.uniform(0, 20), rng=rng)
    ps.append(Profile("F. Distribuido (128 IPs)", "1024 puertos repartidos, 8 puertos por IP",
                      True, dist))
    ps.append(Profile("G. Dirigido (20 puertos)", "20 servicios comunes a 50/s", True,
                      seq_scan("203.0.113.15", TOP_PORTS, 50)))
    ps.append(Profile("H. Dirigido lento (20 puertos)", "20 servicios comunes, 1 cada 10 s", True,
                      seq_scan("203.0.113.16", TOP_PORTS, 0.1, jitter=0.4, rng=rng)))
    sweep = [Event(T0 + i / 50, "203.0.113.17", f"10.0.1.{i}", 22) for i in range(1, 255)]
    ps.append(Profile("I. Barrido horizontal :22", "1 puerto en 254 hosts a 50/s", True, sweep))
    # benignos
    web = [Event(T0 + i * 0.7, f"192.0.2.{(i % 40) + 1}", TARGET, 443) for i in range(2000)]
    ps.append(Profile("Z1. Tráfico web normal", "40 clientes, 2000 conexiones a :443", False, web))
    mon = []
    for cycle in range(12):  # monitoreo: 12 puertos cada 5 min
        mon += seq_scan("192.0.2.200", TOP_PORTS[:12], 20, start=T0 + cycle * 300)
    ps.append(Profile("Z2. Monitoreo legítimo", "Nagios sondea 12 servicios cada 5 min", False, mon))
    spread = [Event(T0 + i * 15 + c * 300, "192.0.2.201", TARGET, TOP_PORTS[i])
              for c in range(12) for i in range(20)]
    ps.append(Profile("Z4. Monitoreo espaciado", "20 servicios, 1 sonda cada 15 s, ciclo de 5 min",
                      False, spread))
    # Navegación real: un cliente abre 40 servidores distintos :443 en ~6 s (CDN, APIs,
    # trackers). Flujos eve con tráfico del servidor (muchos paquetes).
    browse = [Event(T0 + i * 0.15, "192.0.2.50", f"198.18.{i // 250}.{i % 250 + 1}", 443)
              for i in range(40)]
    ps.append(Profile("Z5. Navegación web (eve.json)", "1 cliente, 40 servidores :443 en 6 s, "
                      "flujos con tráfico real", False, browse, fmt="eve", pkts_toclient=25))
    ps.append(Profile("Z3. Reintentos a un puerto", "cliente reintenta :22 cada 2 s (fuerza bruta/mal config)",
                      False, [Event(T0 + i * 2, "192.0.2.99", TARGET, 22) for i in range(300)]))
    return ps


def run_detector(events: list[Event], rules=DEFAULT_RULES, fmt: str = "kernel",
                 pkts_toclient: int = 1, include_established: bool = False):
    """Pasa por formato log real -> parser -> detector (pipeline completo)."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        for ev in sorted(events, key=lambda e: e.ts):
            fh.write((format_eve_flow(ev, pkts_toclient) if fmt == "eve"
                      else format_kernel_line(ev)) + "\n")
        path = fh.name
    try:
        with open(path) as fh:
            parsed = list(parse_lines(fh, fmt, include_established=include_established))
    finally:
        Path(path).unlink(missing_ok=True)
    return parsed, detect(parsed, rules)


def live_profile() -> Profile | None:
    """Escaneo real del scanner contra servicios locales; devuelve los intentos reales."""
    import fake_services
    from portscan.scanner import ScanConfig, scan
    try:
        servers = fake_services.start("127.0.0.1")
    except OSError:
        return None
    attempts: list[Event] = []
    try:
        scan(["127.0.0.1"], list(range(1900, 2500)),
             ScanConfig(rate=500, timeout=0.5, workers=32),
             on_attempt=lambda ts, h, p: attempts.append(Event(ts, "127.0.0.1", h, p)))
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
    return Profile("L. LIVE: portscan real", "scanner real a 500/s, 600 puertos en localhost",
                   True, attempts)


def summarize(profiles: list[Profile], rules, include_established: bool = False) -> list[dict]:
    rows = []
    for p in profiles:
        parsed, alerts = run_detector(p.events, rules, p.fmt, p.pkts_toclient,
                                      include_established)
        srcs = {e.src for e in p.events}
        alerted: set[str] = set()
        for a in alerts:
            alerted |= (a.srcs & srcs) if a.distributed else {a.src}
        rules_hit = sorted({a.rule for a in alerts})
        ttd = min((a.time_to_detect for a in alerts), default=None)
        rows.append({
            "name": p.name, "desc": p.description, "malicious": p.malicious,
            "events": len(p.events), "srcs": len(srcs), "alerted": len(alerted),
            "rules": rules_hit, "ttd": ttd,
        })
    return rows


def verdict(r: dict) -> str:
    if r["malicious"]:
        if r["alerted"] == 0:
            return "EVADE (no detectado)"
        if r["alerted"] < r["srcs"]:
            return f"PARCIAL ({r['alerted']}/{r['srcs']} IPs)"
        return "detectado"
    return "FALSO POSITIVO" if r["alerted"] else "ok (sin alerta)"


def table(rows: list[dict]) -> str:
    out = ["| Perfil | Descripción | Eventos | Reglas | 1ª alerta tras | Veredicto |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        ttd = "—" if r["ttd"] is None else f"{r['ttd']:.1f} s"
        out.append(f"| {r['name']} | {r['desc']} | {r['events']} | "
                   f"{', '.join(r['rules']) or '—'} | {ttd} | **{verdict(r)}** |")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--output", default=str(ROOT / "experiments" / "results.md"))
    args = ap.parse_args()

    profiles = build_profiles()
    live = live_profile()
    if live:
        profiles.append(live)

    default = summarize(profiles, DEFAULT_RULES)
    per_source = [r for r in DEFAULT_RULES if r.group_by == "src"]
    fast_only = summarize(profiles, [DEFAULT_RULES[0]])
    no_dist = summarize(profiles, per_source)
    naive = summarize([p for p in profiles if p.fmt == "eve"], DEFAULT_RULES,
                      include_established=True)
    tuned = summarize(profiles, DEFAULT_RULES + (Rule("slow-15", 3600, 15),
                                                 Rule("daily", 86400, 25)))

    text = f"""# Resultados del experimento ofensivo vs. defensivo (T1046)

Generado por `experiments/run_experiment.py`. Perfiles simulados en tiempo + un perfil
LIVE real. Cada perfil pasa por: log tipo UFW -> parser -> detector.

## 1. Solo regla rápida (10 s, 15 destinos distintos)

{table(fast_only)}

## 2. Reglas por origen (rápida 10 s/15 + lenta 1 h/40)

{table(no_dist)}

## 3. Reglas por defecto (anteriores + distribuida por destino: 20 puertos, 5 IPs, 60 s)

{table(default)}

## 4. Ajustada (por defecto + 1 h/15 + 24 h/25)

{table(tuned)}

## 5. Z5 con el conteo ingenuo de flujos (`--eve-include-established`)

{table(naive)}

## Lectura

- La regla rápida atrapa lo ruidoso (A, B, G, I) en pocos segundos, pero **no ve** los
  escaneos que espaciaron sus paquetes más allá de la ventana (C, D, E, H) ni el F.
- Una ventana lenta cubre C y D, a cambio de riesgo de falsos positivos con monitoreo
  legítimo (Z2): por eso existe `--allow` y por eso importa el umbral por ventana.
- El escaneo **distribuido** (F) es el punto ciego de cualquier detector por IP de origen:
  cada IP toca pocos puertos (8). Solo aparece al correlacionar por **destino** (muchos
  puertos distintos recibidos por un host desde muchos orígenes): sección 3.
- Z5 (navegación web en `eve.json`) es un falso positivo clásico: un cliente que abre
  40 servidores :443 parece un barrido horizontal si se cuentan todos los flujos
  (sección 5). El parser descarta por defecto los flujos con tráfico real del servidor
  (`pkts_toclient > 2`) y solo cuenta los que mueren en el handshake, como un escaneo.
- Z4 es el costo de cubrir los escaneos lentos: un monitor legítimo que sondea 20
  servicios repartidos en el tiempo es indistinguible de un escaneo lento por patrón;
  se resuelve con `--allow` o con contexto (inventario de monitores), no con más umbral.
- Baja `threshold` y sube `window` reduce evasión y sube falsos positivos: es un
  compromiso medible, no una configuración "correcta".
"""
    Path(args.output).write_text(text)
    print(text)
    print(f"\n-> escrito en {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
