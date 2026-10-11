"""Registro de auditoría append-only (JSONL): quién, cuándo, qué alcance."""

from __future__ import annotations

import getpass
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
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def now() -> float:
        return time.time()
