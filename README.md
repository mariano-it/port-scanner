# portscan

Port scanner didáctico en Python (solo biblioteca estándar) con enfoque **purple team**:
el lado ofensivo (scanner) y el defensivo (detector + reglas) viven juntos y se miden
entre sí. Pensado para tu home-lab; usa el mismo modelo `Finding` y reportes
JSON/Markdown que `osint-tool`.

> Úsalo solo en sistemas propios o con autorización por escrito.

## Qué incluye

| Pieza | Dónde | Qué hace |
|---|---|---|
| Scanner TCP connect | `src/portscan/` | Hilos + límite de velocidad + banners + info TLS |
| Alcance obligatorio | `scope.py` | Sin `--scope` no hay escaneo; fuera de scope se rechaza |
| Auditoría | `audit.py` | JSONL append-only: quién, cuándo, alcance (con sha256), resultado, denegaciones |
| Hallazgos | `analyze.py` | Telnet, SMB, Redis expuesto, SSH viejo, TLS obsoleto… con remediación |
| Detector | `src/portscan/detect/` | Ventanas deslizantes sobre logs UFW/iptables y Suricata `eve.json` (T1046) |
| Reglas | `detection/rules/` | Sigma (con correlación `value_count`) y Suricata |
| Experimento | `experiments/` | Qué detecta el detector y qué se le escapa (`results.md`) |
| Modo interactivo | `run.py`, `interactive.py` | Banner ASCII + menú guiado |
| Lab | `lab/fake_services.py` | Servicios falsos en localhost (SSH viejo, Telnet, Apache 2.2, Redis) |

## Inicio rápido (modo interactivo)

```bash
python3 run.py            # menú con banner: pide la IP y arma el escaneo
python3 run.py 192.168.56.10   # salta directo al escaneo de ese objetivo
```

Te pregunta objetivo → confirmación de autorización → perfil (rápido, estándar,
completo o personalizado) → velocidad. Guarda los reportes en `reports/` y registra el
objetivo en `scope.txt` y en el log de auditoría. IPs públicas exigen escribir `SI`.
El modo interactivo es solo una capa sobre el CLI: las mismas protecciones aplican.

## Uso avanzado (CLI)

Sin instalar (desde esta carpeta):

```bash
export PYTHONPATH=src
python3 lab/fake_services.py &            # lab local
python3 -m portscan --scope scope.example.txt 127.0.0.1 -p 1-10000 --rate 500 --banners
python3 -m portscan --scope scope.example.txt 192.168.56.0/24 --top-ports 100 -o reporte.json -o reporte.md
```

O instalado en un venv: `python3 -m venv .venv && .venv/bin/pip install -e .` y entonces
`portscan ...` / `portscan-detect ...`.

Opciones principales: `-p` / `--top-ports N` (usa la frecuencia de nmap si existe
`/usr/share/nmap/nmap-services`), `--rate` (intentos/s, default 100, tope 5000),
`--timeout`, `--workers`, `--banners`, `--shuffle`, `--all`, `--allow-public`,
`--max-hosts`, `--audit-log` (o env `PORTSCAN_AUDIT`; default `~/.local/state/portscan/audit.jsonl`).

Códigos de salida: `0` ok · `1` error de uso · `2` fuera de alcance / no autorizado.

### Límites de seguridad (por diseño)

- `--scope` obligatorio: IP, CIDR u hostname por línea; rangos menores a /16 (IPv4) se rechazan.
- IPs públicas requieren `--allow-public` (y confirmación `SI` si hay terminal).
- `--rate` siempre limitado y `--max-hosts` por defecto 1024.
- Cada escaneo (y cada rechazo) queda en el log de auditoría.

## Detector

```bash
# logs: ver detection/rules/iptables_logging.md
python3 -m portscan.detect.cli ufw.log
python3 -m portscan.detect.cli /var/log/suricata/eve.json --format eve --json
python3 -m portscan.detect.cli ufw.log --allow 192.168.56.2     # ignora tu monitor
```

Tres reglas por defecto: **fast** (≥15 destinos distintos / 10 s por origen),
**slow** (≥40 / 1 h) y **distributed** (≥20 puertos distintos recibidos por un destino
desde ≥5 orígenes / 60 s). Clasifica `vertical`, `horizontal`, `block` o `distributed`.

## Experimento (ofensivo vs. defensivo)

```bash
PYTHONPATH=src python3 experiments/run_experiment.py     # escribe experiments/results.md
```

Resumen de lo que muestra: lo ruidoso lo caza la regla rápida en segundos; lo lento
exige ventanas largas y paga falsos positivos (monitoreo legítimo); lo distribuido solo
se ve correlacionando por destino; y un escaneo de 1 puerto cada 5 min solo cae con una
ventana de 24 h. Los perfiles son simulados en tiempo, más un perfil LIVE real.

## Pruebas

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Contraste con nmap (tus herramientas)

```bash
nmap -sT -p 1-10000 127.0.0.1                 # mismo resultado que portscan
sudo nmap -sS -p 1-1024 127.0.0.1             # SYN scan: lo que será la versión en C
sudo tcpdump -ni lo 'tcp[tcpflags] & tcp-syn != 0' # o Wireshark: ver el 3-way handshake
```

En Wireshark compara un `-sT` (handshake completo + RST/FIN) contra `-sS` (SYN, SYN-ACK,
RST sin ACK final): esa diferencia es lo que detecta cada regla.

## Roadmap

1. **v2 en C**: SYN scan con raw sockets (checksums IP/TCP a mano, `IP_HDRINCL`),
   mismo `--scope`, mismo formato de reporte JSON.
2. Escaneo UDP y descubrimiento de hosts (ARP/ICMP).
3. Detector en tiempo real (tail de log) y exportación de alertas a Sigma/Suricata.
4. Integrar los reportes con `osint-tool` en un solo informe.
