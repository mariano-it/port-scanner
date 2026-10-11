from __future__ import annotations

import re

from portscan.models import Report, Severity


def _code(text: object) -> str:
    """Texto NO confiable (banners, hosts, rutas) como código en línea.

    El delimitador es más largo que cualquier racha de comillas invertidas del
    contenido, así que no se puede cerrar el span ni inyectar enlaces/HTML. Los
    saltos de línea y el pipe se neutralizan para no romper tablas.
    """
    raw = " ".join(str(text).split())
    if not raw:
        return "—"
    longest = max((len(m) for m in re.findall(r"`+", raw)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if raw.startswith("`") or raw.endswith("`") else ""
    return f"{fence}{pad}{raw.replace('|', '&#124;')}{pad}{fence}"


def render_markdown(report: Report) -> str:
    data = report.to_dict()
    lines = [
        f"# Reporte de escaneo de puertos: {_code(report.target)}",
        "",
        f"Generado: {data['generated_at']}",
        "",
        "> Uso exclusivo sobre sistemas propios o con autorización por escrito.",
        "",
        "## Resumen",
        "",
        "| Severidad | Hallazgos |",
        "|---|---|",
    ]
    for sev in sorted(Severity, reverse=True):
        lines.append(f"| {sev.label} | {data['summary'][sev.label]} |")

    lines += ["", "## Hallazgos (ordenados por riesgo)", ""]
    findings = report.all_findings()
    if not findings:
        lines += ["Sin hallazgos.", ""]
    for module, f in findings:
        lines += [
            f"### [{f.severity.label.upper()}] {f.title}",
            "",
            f"- **Módulo:** {module}",
            f"- **Descripción:** {f.description}",
        ]
        if f.evidence:
            lines.append(f"- **Evidencia:** {_code(f.evidence)}")
        lines += [f"- **Remediación:** {f.remediation}", ""]

    lines += ["## Puertos", ""]
    for r in report.results:
        meta = r.data.get("meta", {})
        lines += [
            f"- **Scan ID:** {_code(meta.get('scan_id', ''))}",
            f"- **Alcance:** {_code(meta.get('scope_file', ''))} "
            f"(sha256 {_code(str(meta.get('scope_sha256', ''))[:12])})",
            f"- **Puertos probados:** {meta.get('ports_scanned', 0)} por host, "
            f"{meta.get('hosts', 0)} host(s), {meta.get('rate', '?')} intentos/s",
            f"- **Estados:** {meta.get('state_counts', {})}",
            "",
            "| Host | Puerto | Estado | Servicio | Banner | TLS |",
            "|---|---|---|---|---|---|",
        ]
        for p in r.data.get("ports", []):
            tls = p["tls"]
            if p.get("tls_legacy"):
                tls = f"{tls} (acepta {', '.join(p['tls_legacy'])})".strip()
            lines.append(
                f"| {_code(p['host'])} | {p['port']}/{p['proto']} | {p['state']} | "
                f"{_code(p['service'])} | {_code(p['banner'])} | {_code(tls)} |"
            )
        lines.append("")
    return "\n".join(lines)
