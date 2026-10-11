"""Registro de auditoría (JSONL): quién, cuándo, qué alcance.

Es un REGISTRO, no un control: cualquiera con permisos de escritura puede editarlo.
Cada línea incluye el hash de la anterior (cadena), así que alterar o borrar una
entrada intermedia es detectable con `AuditLog.verify()`. Truncar el final solo se
evita con permisos del sistema (p. ej. `chattr +a` sobre el archivo, como root).
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def default_path() -> Path:
    env = os.environ.get("PORTSCAN_AUDIT")
    if env:
        return Path(env)
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "portscan" / "audit.jsonl"


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


GENESIS = "0" * 64


def _last_hash(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return GENESIS
    lines = [l for l in data.splitlines() if l.strip()]
    return hashlib.sha256(lines[-1]).hexdigest() if lines else GENESIS


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_path()

    def write(self, event: str, scan_id: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "scan_id": scan_id,
            "user": getpass.getuser(),
            "host": socket.gethostname(),
            "pid": os.getpid(),
            **fields,
            "prev": _last_hash(self.path),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def verify(self) -> tuple[bool, int, str]:
        """(íntegro, líneas, detalle). Detecta ediciones/borrados intermedios."""
        prev = GENESIS
        count = 0
        for n, raw in enumerate(self.path.read_bytes().splitlines(), 1):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                return False, count, f"línea {n}: JSON inválido"
            if rec.get("prev") != prev:
                return False, count, f"línea {n}: la cadena de hashes no coincide"
            prev = hashlib.sha256(raw).hexdigest()
            count += 1
        return True, count, "ok"

    @staticmethod
    def now() -> float:
        return time.time()
