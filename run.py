#!/usr/bin/env python3
"""Lanzador: ejecuta `python3 run.py` (o ./run.py) y sigue el menú."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from portscan.interactive import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
