"""Modo interactivo: banner ASCII + menú. Pide el objetivo y arma el escaneo."""

from __future__ import annotations

import ipaddress
import os
import sys
from datetime import datetime
from pathlib import Path

from portscan import __version__
from portscan import cli as scan_cli
from portscan.detect import cli as detect_cli
from portscan.scope import ScopeError, parse_scope, resolve_targets

BANNER = r"""
  ____   ___  ____ _____   ____   ____    _    _   _ _   _ _____ ____
 |  _ \ / _ \|  _ \_   _| / ___| / ___|  / \  | \ | | \ | | ____|  _ \
 | |_) | | | | |_) || |   \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
 |  __/| |_| |  _ < | |    ___) | |___ / ___ \| |\  | |\  | |___|  _ <
 |_|    \___/|_| \_\|_|   |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\
"""

PROFILES = {
    "1": ("Rápido", "los 100 puertos más comunes + banners", ["--top-ports", "100", "--banners"]),
    "2": ("Estándar", "puertos 1-1024 + banners", ["-p", "1-1024", "--banners"]),
    "3": ("Completo", "los 65535 puertos (tarda varios minutos)", ["-p", "-", "--banners"]),
    "4": ("Personalizado", "tú eliges los puertos", None),
}

ROOT = Path(__file__).resolve().parents[2]


class _Style:
    def __init__(self) -> None:
        on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.c = (lambda code: f"\033[{code}m") if on else (lambda code: "")

    def paint(self, text: str, code: str) -> str:
        return f"{self.c(code)}{text}{self.c('0')}"


S = _Style()


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{S.paint('›', '36')} {prompt}{suffix}: ").strip()
    except EOFError:
        raise KeyboardInterrupt from None
    return value or default


def _confirm(prompt: str, default: bool = False) -> bool:
    hint = "S/n" if default else "s/N"
    answer = _ask(f"{prompt} ({hint})").lower()
    if not answer:
        return default
    return answer in ("s", "si", "sí", "y", "yes")


def show_banner() -> None:
    print(S.paint(BANNER, "32"))
    print(S.paint(f"  Scanner de puertos didáctico · v{__version__} · purple team", "2"))
    print(S.paint("  Úsalo solo en sistemas propios o con autorización por escrito.\n", "33"))


def _scope_path() -> Path:
    return ROOT / "scope.txt"


def _add_to_scope(target: str) -> Path:
    """Registra el objetivo (ya confirmado por el usuario) en scope.txt."""
    path = _scope_path()
    existing = path.read_text().splitlines() if path.exists() else []
    if target not in (l.split("#", 1)[0].strip() for l in existing):
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        with open(path, "a", encoding="utf-8") as fh:
            if existing and not path.read_text().endswith("\n"):
                fh.write("\n")
            fh.write(f"{target}  # añadido desde modo interactivo {stamp}\n")
    return path


def _check_target(target: str) -> tuple[list[str], bool]:
    """Valida el objetivo; devuelve (hosts, hay_ip_publica)."""
    scope = parse_scope(target)  # lanza ScopeError si es demasiado amplio / irresoluble
    hosts = resolve_targets([target], scope, allow_public=True, max_hosts=1024)
    public = any(ipaddress.ip_address(h).is_global for h in hosts)
    return hosts, public


def _pick_profile() -> list[str]:
    print("\n  Perfil de escaneo:")
    for key, (name, desc, _) in PROFILES.items():
        print(f"    {S.paint(key, '36')}) {name:<14} {S.paint(desc, '2')}")
    while True:
        choice = _ask("Elige un perfil", "1")
        if choice in PROFILES:
            break
        print(S.paint("  Opción no válida.", "31"))
    args = PROFILES[choice][2]
    if args is not None:
        return list(args)
    while True:
        spec = _ask("Puertos (ej. 22,80,443 o 1-1024)", "1-1024")
        try:
            from portscan.ports import parse_ports
            parse_ports(spec)
            break
        except ValueError as exc:
            print(S.paint(f"  {exc}", "31"))
    return ["-p", spec, "--banners"]


def _run_scan(preset_target: str | None = None) -> None:
    target = preset_target or _ask("IP, rango (ej. 192.168.56.0/24) o hostname a escanear")
    if not target:
        print(S.paint("  Debes indicar un objetivo.", "31"))
        return
    try:
        hosts, public = _check_target(target)
    except ScopeError as exc:
        print(S.paint(f"  ✗ {exc}", "31"))
        return

    print(f"\n  Objetivo: {S.paint(target, '1')}  ({len(hosts)} host(s))")
    extra: list[str] = []
    if public:
        print(S.paint("  ⚠ Incluye IPs PÚBLICAS: escanearlas sin permiso puede ser ilegal.", "31"))
        if _ask("Escribe SI (mayúsculas) si tienes autorización escrita") != "SI":
            print(S.paint("  Cancelado.", "33"))
            return
        extra.append("--allow-public")
    elif not _confirm("¿Es un sistema tuyo o tienes autorización para escanearlo?"):
        print(S.paint("  Cancelado.", "33"))
        return

    profile = _pick_profile()
    rate = _ask("Velocidad (intentos/segundo)", "200")
    try:
        float(rate)
    except ValueError:
        print(S.paint("  Velocidad inválida.", "31"))
        return

    scope_file = _add_to_scope(target)
    out_dir = ROOT / "reports"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in target)
    base = out_dir / f"{stamp}-{safe}"

    argv = [target, "--scope", str(scope_file), *profile, "--rate", rate, "--progress",
            "-o", f"{base}.json", "-o", f"{base}.md", *extra]
    print(S.paint("\n  Escaneando… (Ctrl+C para cancelar)\n", "2"))
    code = scan_cli.main(argv)
    if code == scan_cli.EXIT_OK:
        print(S.paint(f"\n  Reportes guardados en {base}.json y {base}.md", "32"))


def _run_detector() -> None:
    path = _ask("Ruta del log a analizar (UFW/iptables o eve.json)")
    if not path:
        return
    if not Path(path).is_file():
        print(S.paint("  Archivo no encontrado.", "31"))
        return
    print()
    detect_cli.main([path])


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-h", "--help"):
        print("Uso: python3 run.py [OBJETIVO]\n"
              "Sin argumentos abre el menú interactivo. Con OBJETIVO salta al escaneo.\n"
              "Para opciones avanzadas usa: python3 -m portscan --help")
        return 0
    show_banner()
    preset = argv[0] if argv else None
    try:
        while True:
            if preset is None:
                print("  1) Escanear puertos")
                print("  2) Analizar logs en busca de escaneos (detector)")
                print("  3) Salir")
                choice = _ask("Elige una opción", "1")
                if choice == "3":
                    break
                if choice == "2":
                    _run_detector()
                elif choice == "1":
                    _run_scan()
                else:
                    print(S.paint("  Opción no válida.", "31"))
                    continue
            else:
                _run_scan(preset)
                preset = None
            print()
            if not _confirm("¿Hacer otra cosa?", default=False):
                break
    except KeyboardInterrupt:
        print("\n  Saliendo.")
    return 0
