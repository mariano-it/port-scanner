# portscan

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencias](https://img.shields.io/badge/dependencias-0-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1046-red)
![Enfoque](https://img.shields.io/badge/enfoque-purple%20team-8A2BE2)

Scanner de puertos **didáctico** escrito en Python puro (solo biblioteca estándar), con un
enfoque *purple team*: el lado ofensivo (el scanner) y el defensivo (detector y reglas de
detección) viven en el mismo proyecto y se miden entre sí.

No pretende reemplazar a `nmap`. Sirve para entender cómo funciona un escaneo por dentro y,
sobre todo, para construir lo que `nmap` no te da: **tu propio detector y una comparación
ofensiva vs. defensiva con datos**.

```
  ____   ___  ____ _____   ____   ____    _    _   _ _   _ _____ ____
 |  _ \ / _ \|  _ \_   _| / ___| / ___|  / \  | \ | | \ | | ____|  _ \
 | |_) | | | | |_) || |   \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
 |  __/| |_| |  _ < | |    ___) | |___ / ___ \| |\  | |\  | |___|  _ <
 |_|    \___/|_| \_\|_|   |____/ \____/_/   \_\_| \_|_____|_| \_\
```

> ⚠️ **Uso legal.** Escanea únicamente sistemas propios o con autorización por escrito.
> El escaneo no autorizado de redes ajenas puede ser ilegal. Quien use esta herramienta es
> el único responsable de su uso.

---

## Contenido

- [Características](#características)
- [Inicio rápido](#inicio-rápido)
- [Uso avanzado (CLI)](#uso-avanzado-cli)
- [Salida de ejemplo](#salida-de-ejemplo)
- [Seguridad por diseño](#seguridad-por-diseño)
- [Detector y reglas (lado defensivo)](#detector-y-reglas-lado-defensivo)
- [Experimento ofensivo vs. defensivo](#experimento-ofensivo-vs-defensivo)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Pruebas](#pruebas)
- [Contraste con nmap y Wireshark](#contraste-con-nmap-y-wireshark)
- [Roadmap](#roadmap)

## Características

| Área | Qué ofrece |
|---|---|
| **Scanner** | TCP connect concurrente (hilos), límite de velocidad global, IPv4/IPv6, CIDR y hostnames |
| **Identificación** | *Banner grabbing* pasivo, sondeo HTTP en puertos no estándar e información TLS (versión y cipher) |
| **Hallazgos** | Telnet, FTP, SMB, RDP, VNC, bases de datos expuestas, Redis con/sin autenticación, OpenSSH desactualizado, TLS 1.0/1.1 aceptado (sondeo por versión), versiones de servidor web, cada uno con su remediación |
| **Reportes** | JSON y Markdown con severidades; mismo modelo `Finding` que `osint-tool` para combinar resultados |
| **Controles** | Alcance obligatorio validado antes de expandir, rangos privados por defecto, tope de velocidad y de hosts, log de auditoría encadenado, reportes `0600` |
| **Detector** | Ventanas deslizantes sobre logs UFW/iptables y `eve.json` de Suricata, clasificación vertical / horizontal / bloque / distribuido |
| **Reglas** | Sigma (con correlación `value_count`) y Suricata, mapeadas a MITRE ATT&CK T1046 |
| **Experimento** | Perfiles de escaneo contra el detector: qué se detecta, qué se evade y qué da falsos positivos |
| **Modo interactivo** | Banner ASCII y menú guiado: ejecutas un archivo y escribes la IP |

## Inicio rápido

Requisitos: Python 3.10 o superior. No hay dependencias que instalar.

```bash
git clone <url-del-repo>
cd port-scanner
python3 run.py
```

`run.py` abre un menú que te guía paso a paso:

1. Escribes la IP, un rango (`192.168.56.0/24`) o un hostname.
2. Si el objetivo **no está** en `scope.txt`, te lo dice y te pide escribir `AUTORIZO`: esa
   decisión es independiente del escaneo y queda anotada en el archivo (bórrala de ahí para
   revocarla). Para IPs públicas, además, debes escribir `SI`.
3. Eliges un perfil: **Rápido** (top 100), **Estándar** (1-1024), **Completo** (1-65535) o
   **Personalizado**.
4. Ves el progreso, la tabla de puertos con banners y los hallazgos con su remediación.
5. Los reportes `.json` y `.md` se guardan en `reports/`.

También puedes saltarte el menú:

```bash
python3 run.py 192.168.56.10
```

### Probarlo sin tocar nada real

El proyecto trae un laboratorio local con servicios falsos y vulnerables (SSH viejo,
Telnet, Apache 2.2 y Redis sin autenticación):

```bash
python3 lab/fake_services.py &
python3 run.py 127.0.0.1
```

## Uso avanzado (CLI)

```bash
# desde la raíz del repo, sin instalar
export PYTHONPATH=src

python3 -m portscan --scope scope.txt 192.168.56.10 -p 1-1024 --rate 200 --banners
python3 -m portscan --scope scope.txt 192.168.56.0/24 --top-ports 100 -o reporte.json -o reporte.md
```

También puedes instalarlo en un entorno virtual y obtener los comandos `portscan` y
`portscan-detect`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

| Opción | Descripción |
|---|---|
| `--scope FILE` | **Obligatoria.** Archivo con el alcance autorizado (ver `scope.example.txt`) |
| `-p`, `--ports` | `22,80,1-1024` o `-` para los 65535 (por defecto `1-1024`) |
| `--top-ports N` | Los N puertos más comunes, N ≥ 1 (usa la frecuencia de nmap si está instalado) |
| `--rate N` | Intentos por segundo (por defecto 100, tope 5000) |
| `--timeout S` | Segundos por conexión (por defecto 1) |
| `--workers N` | Hilos concurrentes (por defecto 64) |
| `--banners` | Captura banners e información TLS |
| `--shuffle` | Orden aleatorio de puertos |
| `--all` | Muestra también puertos cerrados y filtrados |
| `--allow-public` | Permite IPs públicas (solo con autorización escrita) |
| `--max-hosts N` | Tope de hosts por escaneo (por defecto 1024) |
| `-o FILE` | Reporte `.json` o `.md` (repetible) |
| `--audit-log FILE` | Ruta del log de auditoría (o variable `PORTSCAN_AUDIT`) |
| `--progress`, `-q` | Barra de progreso / salida silenciosa |

Códigos de salida: `0` correcto · `1` error de uso · `2` objetivo fuera de alcance.

## Salida de ejemplo

Contra el laboratorio incluido:

```
Scan 7d51cf1f0c41: 1 host(s) x 403 puertos en 1.8s  {'closed': 399, 'open': 4}
HOST       PUERTO    ESTADO    SERVICIO       BANNER
127.0.0.1  2222 /tcp open      ssh            SSH-2.0-OpenSSH_7.4
127.0.0.1  2323 /tcp open      telnet         login:
127.0.0.1  6380 /tcp open      redis          -NOAUTH Authentication required.
127.0.0.1  8089 /tcp open      http           HTTP/1.0 200 OK | Server: Apache/2.2.15 (CentOS)

Hallazgos:
  [HIGH  ] Telnet abierto  (127.0.0.1:2323 telnet | login:)
           -> Deshabilita telnet y usa SSH con autenticación por clave.
  [MEDIUM] Redis expuesto (autenticación activa)  (127.0.0.1:6380 redis | -NOAUTH Authentication required.)
           -> Enlaza a 127.0.0.1, activa requirepass/ACL y filtra el puerto.
  [MEDIUM] Versión de SSH desactualizada  (127.0.0.1:2222 ssh | SSH-2.0-OpenSSH_7.4)
           -> Actualiza OpenSSH desde el repositorio de la distribución.
  [LOW   ] Versión de servidor web expuesta  (127.0.0.1:8089 http | ... Server: Apache/2.2.15)
           -> Oculta la versión (ServerTokens Prod / server_tokens off).
```

Los puertos abiertos coinciden con los de `nmap -sT` sobre el mismo objetivo.

## Seguridad por diseño

Un scanner es más sensible que un recolector pasivo, así que los límites están en el diseño
y no son opcionales:

- **Alcance obligatorio.** Sin `--scope` no hay escaneo. Si el objetivo no está listado, se
  rechaza con código de salida 2. Los rangos menores a /16 (IPv4) no se aceptan en el archivo.
- **Validación antes de expandir.** El tamaño y la pertenencia al alcance se comprueban sobre
  la red (`num_addresses`, `subnet_of`) antes de enumerar hosts: un `/8` o un IPv6 `/64` fuera
  de alcance se rechaza al instante, sin consumir memoria ni tiempo.
- **Privado por defecto.** Las IPs públicas requieren `--allow-public` y, en modo
  interactivo, escribir `SI` de forma explícita.
- **Velocidad limitada.** `--rate` tiene tope para no tumbar tu propio laboratorio.
- **Modo interactivo.** `run.py` construye una llamada al CLI y la consulta de alcance es de
  solo lectura. Para escanear algo que no está en `scope.txt` hay una acción aparte y
  deliberada (`AUTORIZO`); no es un efecto secundario de escanear. Es una comodidad para un
  usuario único en su propio lab: **no sustituye** un control de acceso real.
- **Auditoría.** Cada escaneo, y también cada rechazo y cada interrupción, queda en un JSONL
  con usuario, fecha, argumentos, alcance (con su sha256) y resultado. Por defecto en
  `~/.local/state/portscan/audit.jsonl` (permisos `0600`).
- **Banners = datos no confiables.** Se filtran caracteres de control y, en el reporte
  Markdown, siempre se emiten como código en línea con un delimitador que el contenido no
  puede cerrar, de modo que un servicio hostil no inyecta enlaces ni HTML.
- **Reportes privados.** Los `.json`/`.md` se crean con permisos `0600`: describen tu red.

### Limitaciones conocidas

- **El log de auditoría es un registro, no un control.** Quien pueda escribir el archivo puede
  editarlo. Cada entrada incluye el hash de la anterior, así que modificar o borrar una línea
  intermedia es detectable (`AuditLog.verify()`); truncar el final solo se impide con
  permisos del sistema, p. ej. `sudo chattr +a ~/.local/state/portscan/audit.jsonl`.
- **Versiones por banner.** "OpenSSH < 8.0" se infiere del banner; RHEL/CentOS y otras
  distribuciones parchean sin cambiar la versión, así que puede ser un falso positivo. El
  hallazgo lo advierte y propone verificarlo con el gestor de paquetes.
- **TLS obsoleto** se sondea con el OpenSSL local; si el sistema no puede hablar TLS 1.0/1.1
  no se reporta nada (sin falsos positivos, pero con posibles falsos negativos).
- **Redis** se clasifica por la respuesta a una petición ajena: `-ERR` (sin autenticación,
  HIGH) frente a `-NOAUTH` (con autenticación, MEDIUM). Sin `--banners` solo se informa de que
  está expuesto.

## Detector y reglas (lado defensivo)

Por cada técnica ofensiva hay un detector equivalente:

```bash
# generar logs: ver detection/rules/iptables_logging.md
python3 -m portscan.detect.cli ufw.log
python3 -m portscan.detect.cli /var/log/suricata/eve.json --format eve --json
python3 -m portscan.detect.cli ufw.log --allow 192.168.56.2    # ignora tu monitor
```

Reglas por defecto, todas etiquetadas **T1046 (Network Service Discovery)**:

| Regla | Condición | Qué atrapa |
|---|---|---|
| `fast` | ≥ 15 destinos (host, puerto) distintos desde un origen en 10 s | Escaneos rápidos y moderados |
| `slow` | ≥ 40 destinos distintos desde un origen en 1 h | Escaneos espaciados |
| `distributed` | ≥ 20 puertos distintos recibidos por un destino desde ≥ 5 orígenes en 60 s | Escaneos repartidos entre muchas IPs |

Todas son configurables desde la línea de comandos (`--window`, `--threshold`,
`--slow-window`, `--dist-*`).

**Sobre `eve.json`:** los eventos `flow` incluyen tráfico exitoso, y un cliente que navega a
20 servidores por `:443` parecería un barrido. Por eso solo se cuentan los flujos que no pasan
del handshake (`pkts_toclient ≤ 2`) y los eventos `alert`/`anomaly`. Con
`--eve-include-established` se cuenta todo (más falsos positivos). Los logs de bloqueo de UFW
no tienen este problema porque solo registran lo bloqueado.

Reglas para tus propias herramientas, en `detection/rules/`:

- `portscan_fw_block.sigma.yml`: regla Sigma base y correlaciones `value_count` rápida y lenta.
- `portscan.rules`: reglas Suricata (con la limitación documentada: `threshold` cuenta
  eventos, no puertos distintos).
- `iptables_logging.md`: cómo generar los logs que consume el detector.

## Experimento ofensivo vs. defensivo

```bash
PYTHONPATH=src python3 experiments/run_experiment.py   # escribe experiments/results.md
```

Cada perfil de escaneo pasa por la cadena completa: log tipo UFW → parser → detector. Los
perfiles están simulados en el tiempo (un escaneo de 8 horas no se ejecuta en real) y se
añade un perfil **LIVE** que ejecuta el scanner real.

Resultado con las reglas por defecto:

| Perfil | Resultado |
|---|---|
| Rápido / moderado / dirigido / barrido horizontal | Detectado en menos de 1 s por `fast` |
| Lento aleatorio (1 puerto/s) | Detectado por `slow` tras ~39 s |
| Muy lento (1 puerto cada 30 s) | Detectado por `slow` tras ~19 min |
| Distribuido (128 IPs, 8 puertos cada una) | **Invisible por origen**; detectado solo por `distributed` |
| Paranoico (1 puerto cada 5 min) | **Evade** hasta añadir una ventana de 24 h |
| Dirigido lento (20 servicios, 1 cada 10 s) | **Evade** hasta bajar el umbral de la ventana lenta |
| Monitoreo legítimo espaciado | **Falso positivo** al bajar el umbral para cazar lo lento |
| Navegación web en `eve.json` (40 servidores :443) | Sin alerta; **falso positivo** si se cuentan todos los flujos |

Conclusión: bajar el umbral y alargar la ventana reduce la evasión, pero sube los falsos
positivos. Es un compromiso que se mide, no una configuración correcta única. El detalle
completo, con tres configuraciones comparadas, está en
[`experiments/results.md`](experiments/results.md).

## Estructura del proyecto

```
port-scanner/
├── run.py                      # lanzador interactivo (python3 run.py)
├── scope.example.txt           # ejemplo de archivo de alcance
├── pyproject.toml
├── src/portscan/
│   ├── cli.py                  # CLI
│   ├── interactive.py          # banner + menú
│   ├── scanner.py              # motor TCP connect, banners, TLS
│   ├── scope.py                # alcance obligatorio
│   ├── ratelimit.py            # limitador de velocidad
│   ├── ports.py                # parseo de puertos y top-ports
│   ├── services.py             # servicios por puerto y por banner
│   ├── analyze.py              # hallazgos y remediación
│   ├── audit.py                # log de auditoría
│   ├── models.py               # Finding / Report (compatible con osint-tool)
│   ├── report/                 # JSON y Markdown
│   └── detect/                 # parsers + detector + CLI
├── detection/rules/            # Sigma, Suricata, guía de logging
├── experiments/                # experimento y resultados
├── lab/fake_services.py        # servicios falsos para pruebas
└── tests/                      # 50 pruebas (unittest)
```

## Pruebas

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Cubren alcance (incluido el rechazo de rangos enormes sin expandir), límite de velocidad,
clasificación de estados sin red (errno simulado), escaneo contra sockets locales, sondeo TLS
por versión contra un servidor TLS local, hallazgos, escapado de Markdown hostil, cadena de
auditoría, parsers, detector (rápido, lento, horizontal, distribuido, falsos positivos de
`eve.json`) y el CLI. No dependen de Internet.

## Contraste con nmap y Wireshark

```bash
nmap -sT -p 1-10000 127.0.0.1                        # mismo resultado que portscan
sudo nmap -sS -p 1-1024 127.0.0.1                    # SYN scan (half-open)
sudo tcpdump -ni lo 'tcp[tcpflags] & tcp-syn != 0'   # o Wireshark
```

En Wireshark compara un `-sT` (handshake completo seguido de cierre) con un `-sS` (SYN,
SYN-ACK y RST sin el ACK final). Esa diferencia es justo lo que distingue a cada regla de
detección.

## Roadmap

- [ ] **v2 en C**: SYN scan con raw sockets (`IP_HDRINCL`, checksums IP/TCP a mano), con el
      mismo `--scope` y el mismo formato de reporte.
- [ ] Escaneo UDP y descubrimiento de hosts (ARP/ICMP).
- [ ] Detector en tiempo real (seguir el log) y exportación de alertas.
- [ ] Informe combinado con `osint-tool`.
- [ ] Detección de *OS fingerprinting* pasivo a partir de los banners.

## Referencias

- [MITRE ATT&CK T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [Sigma: reglas de detección genéricas](https://github.com/SigmaHQ/sigma)
- [Suricata](https://suricata.io/)
