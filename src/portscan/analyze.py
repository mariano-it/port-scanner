"""Convierte resultados de puertos en hallazgos con remediación."""

from __future__ import annotations

import re

from portscan.models import Finding, PortResult, PortState, Severity
from portscan.services import PORT_NAMES

# puerto -> (título, severidad, descripción, remediación)
_RISKY: dict[int, tuple[str, Severity, str, str]] = {
    23: ("Telnet abierto", Severity.HIGH,
         "Telnet transmite credenciales y sesión en texto claro.",
         "Deshabilita telnet y usa SSH con autenticación por clave."),
    21: ("FTP abierto", Severity.MEDIUM,
         "FTP envía credenciales sin cifrar y suele permitir acceso anónimo.",
         "Reemplaza por SFTP/FTPS y deshabilita el acceso anónimo."),
    445: ("SMB expuesto", Severity.HIGH,
          "SMB expuesto es vector clásico de movimiento lateral y ransomware.",
          "Restringe 445 por firewall a hosts necesarios y exige SMB signing/SMBv3."),
    139: ("NetBIOS expuesto", Severity.MEDIUM,
          "NetBIOS filtra nombres de host e información de la red.",
          "Deshabilita NetBIOS sobre TCP/IP si no se necesita."),
    3389: ("RDP expuesto", Severity.MEDIUM,
           "RDP es objetivo frecuente de fuerza bruta y exploits.",
           "Limita RDP tras VPN, activa NLA y bloqueo por intentos fallidos."),
    5900: ("VNC expuesto", Severity.HIGH,
           "VNC suele tener autenticación débil o nula y tráfico sin cifrar.",
           "Túnel por SSH/VPN y contraseña fuerte; no exponer a la red general."),
    6379: ("Redis expuesto", Severity.HIGH,
           "Redis sin autenticación permite lectura/escritura y a veces RCE.",
           "Enlaza a 127.0.0.1, activa requirepass/ACL y filtra el puerto."),
    27017: ("MongoDB expuesto", Severity.HIGH,
            "MongoDB accesible en red; históricamente sin autenticación por defecto.",
            "Activa autenticación, bindIp a interfaz interna y firewall."),
    11211: ("Memcached expuesto", Severity.HIGH,
            "Memcached sin autenticación permite fuga de datos y amplificación DDoS.",
            "Enlaza a localhost y filtra 11211 (TCP/UDP)."),
    9200: ("Elasticsearch expuesto", Severity.HIGH,
           "La API REST de Elasticsearch suele no requerir autenticación.",
           "Activa seguridad (auth/TLS) y restringe el acceso por red."),
    3306: ("MySQL/MariaDB expuesto", Severity.MEDIUM,
           "Una base de datos accesible desde la red amplía la superficie de ataque.",
           "Enlaza a localhost o red interna y limita usuarios por host."),
    5432: ("PostgreSQL expuesto", Severity.MEDIUM,
           "Una base de datos accesible desde la red amplía la superficie de ataque.",
           "Ajusta listen_addresses y pg_hba.conf; filtra por firewall."),
    1433: ("MS SQL Server expuesto", Severity.MEDIUM,
           "Una base de datos accesible desde la red amplía la superficie de ataque.",
           "Restringe por firewall y exige cifrado y autenticación fuerte."),
    111: ("rpcbind expuesto", Severity.LOW,
          "rpcbind revela servicios RPC/NFS disponibles.",
          "Filtra 111 si no se usa NFS/NIS."),
}

# nombre de servicio -> puerto canónico, para detectar servicios en puertos no estándar
_SERVICE_TO_PORT = {PORT_NAMES[p]: p for p in _RISKY if p in PORT_NAMES}

_OPENSSH = re.compile(r"OpenSSH[_-](\d+)\.(\d+)", re.I)
_SERVER_VERSION = re.compile(r"Server:\s*([A-Za-z\-_]+)/(\d[\w.\-]*)", re.I)
_WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
OPENSSH_MIN = (8, 0)


def analyze(results: list[PortResult]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        if r.state is not PortState.OPEN:
            continue
        where = f"{r.host}:{r.port}"
        evidence = f"{where} {r.service}" + (f" | {r.banner}" if r.banner else "")
        key = r.port if r.port in _RISKY else _SERVICE_TO_PORT.get(r.service)
        if key is not None:
            title, sev, desc, fix = _RISKY[key]
            findings.append(Finding(title, sev, desc, fix, evidence))
        if r.banner.startswith("SSH-1.") and not r.banner.startswith("SSH-1.99"):
            findings.append(Finding(
                "SSH protocolo 1", Severity.HIGH,
                "SSHv1 tiene fallos criptográficos conocidos.",
                "Fuerza 'Protocol 2' en sshd_config.", evidence))
        m = _OPENSSH.search(r.banner)
        if m and (int(m.group(1)), int(m.group(2))) < OPENSSH_MIN:
            findings.append(Finding(
                "Versión de SSH desactualizada", Severity.MEDIUM,
                f"OpenSSH {m.group(1)}.{m.group(2)} es anterior a "
                f"{OPENSSH_MIN[0]}.{OPENSSH_MIN[1]} y acumula CVEs corregidos.",
                "Actualiza OpenSSH desde el repositorio de la distribución.", evidence))
        if r.tls.split(" ")[0] in _WEAK_TLS:
            findings.append(Finding(
                "TLS obsoleto aceptado", Severity.MEDIUM,
                f"El servicio negoció {r.tls.split(' ')[0]}, considerado inseguro.",
                "Exige TLS 1.2 o superior en la configuración del servicio.", evidence))
        sv = _SERVER_VERSION.search(r.banner)
        if sv:
            findings.append(Finding(
                "Versión de servidor web expuesta", Severity.LOW,
                f"El banner revela {sv.group(1)} {sv.group(2)}, útil para el atacante.",
                "Oculta la versión (ServerTokens Prod / server_tokens off).", evidence))
    return sorted(findings, key=lambda f: f.severity, reverse=True)
