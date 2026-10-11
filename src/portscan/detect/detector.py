"""Detección por ventana deslizante: una IP que toca muchos (host,puerto) distintos."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Iterable

from portscan.detect.parsers import Event

TECHNIQUE = "T1046"  # MITRE ATT&CK: Network Service Discovery


@dataclass(frozen=True)
class Rule:
    """group_by='src': un origen toca >= threshold (host,puerto) distintos.
    group_by='dst': un destino recibe >= threshold puertos distintos desde
    >= min_sources orígenes distintos (escaneo distribuido)."""

    name: str
    window: float      # segundos
    threshold: int
    group_by: str = "src"
    min_sources: int = 1


FAST = Rule("fast", window=10.0, threshold=15)
SLOW = Rule("slow", window=3600.0, threshold=40)
DIST = Rule("distributed", window=60.0, threshold=20, group_by="dst", min_sources=5)
DEFAULT_RULES = (FAST, SLOW, DIST)


@dataclass
class Alert:
    rule: str
    src: str
    first_ts: float
    detected_ts: float
    last_ts: float
    ports: set[int] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    events: int = 0
    srcs: set[str] = field(default_factory=set)
    distributed: bool = False
    technique: str = TECHNIQUE

    @property
    def kind(self) -> str:
        if self.distributed:
            return "distributed"  # muchos orígenes, un destino
        many_ports, many_hosts = len(self.ports) > 1, len(self.hosts) > 1
        if many_ports and many_hosts:
            return "block"       # varios hosts x varios puertos
        if many_hosts:
            return "horizontal"  # un puerto, muchos hosts (barrido)
        return "vertical"        # un host, muchos puertos

    @property
    def time_to_detect(self) -> float:
        return self.detected_ts - self.first_ts

    def to_dict(self) -> dict:
        return {
            "technique": self.technique, "rule": self.rule, "src": self.src,
            "kind": self.kind, "first_seen": self.first_ts,
            "detected_at": self.detected_ts, "last_seen": self.last_ts,
            "time_to_detect_s": round(self.time_to_detect, 3),
            "distinct_ports": len(self.ports), "distinct_hosts": len(self.hosts),
            "events": self.events, "sources": len(self.srcs),
            "sample_ports": sorted(self.ports)[:20],
        }


class _Tracker:
    """Estado de una (regla, clave de agrupación)."""

    def __init__(self, rule: Rule):
        self.rule = rule
        self.window: deque[Event] = deque()
        self.counts: Counter = Counter()      # destinos distintos
        self.src_counts: Counter[str] = Counter()
        self.active: Alert | None = None

    def _key(self, ev: Event):
        return ev.dport if self.rule.group_by == "dst" else (ev.dst, ev.dport)

    @staticmethod
    def _dec(counter: Counter, key) -> None:
        counter[key] -= 1
        if counter[key] <= 0:
            del counter[key]

    def feed(self, ev: Event) -> Alert | None:
        r = self.rule
        if self.active and ev.ts - self.active.last_ts > r.window:
            self.active = None
        while self.window and ev.ts - self.window[0].ts > r.window:
            old = self.window.popleft()
            self._dec(self.counts, self._key(old))
            self._dec(self.src_counts, old.src)
        self.window.append(ev)
        self.counts[self._key(ev)] += 1
        self.src_counts[ev.src] += 1

        if self.active:
            a = self.active
            a.last_ts = ev.ts
            a.events += 1
            a.ports.add(ev.dport)
            a.hosts.add(ev.dst)
            a.srcs.add(ev.src)
            return None
        if len(self.counts) >= r.threshold and len(self.src_counts) >= r.min_sources:
            dist = r.group_by == "dst"
            a = Alert(r.name, "*" if dist else ev.src, self.window[0].ts, ev.ts, ev.ts,
                      distributed=dist)
            for w in self.window:
                a.ports.add(w.dport)
                a.hosts.add(w.dst)
                a.srcs.add(w.src)
            a.events = len(self.window)
            self.active = a
            return a
        return None


def detect(
    events: Iterable[Event],
    rules: Iterable[Rule] = DEFAULT_RULES,
    allowlist: Iterable[str] = (),
) -> list[Alert]:
    """Devuelve alertas ordenadas por momento de detección."""
    rules = list(rules)
    skip = set(allowlist)
    trackers: dict[tuple[str, str], _Tracker] = {}
    alerts: list[Alert] = []
    for ev in sorted(events, key=lambda e: e.ts):
        if ev.src in skip:
            continue
        for rule in rules:
            group = ev.dst if rule.group_by == "dst" else ev.src
            tr = trackers.get((rule.name, group))
            if tr is None:
                tr = trackers[(rule.name, group)] = _Tracker(rule)
            alert = tr.feed(ev)
            if alert:
                alerts.append(alert)
    return sorted(alerts, key=lambda a: a.detected_ts)
