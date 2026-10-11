from __future__ import annotations

from portscan.models import Report, Severity


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report) -> str:
    data = report.to_dict()
    lines = [
        f"# Reporte de escaneo de puertos: {report.target}",
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
            lines.append(f"- **Evidencia:** `{f.evidence}`")
        lines += [f"- **Remediación:** {f.remediation}", ""]

    lines += ["## Puertos", ""]
    for r in report.results:
        meta = r.data.get("meta", {})
        lines += [
            f"- **Scan ID:** `{meta.get('scan_id', '')}`",
            f"- **Alcance:** `{meta.get('scope_file', '')}` (sha256 `{str(meta.get('scope_sha256', ''))[:12]}`)",
            f"- **Puertos probados:** {meta.get('ports_scanned', 0)} por host, "
            f"{meta.get('hosts', 0)} host(s), {meta.get('rate', '?')} intentos/s",
            f"- **Estados:** {meta.get('state_counts', {})}",
            "",
            "| Host | Puerto | Estado | Servicio | Banner | TLS |",
            "|---|---|---|---|---|---|",
        ]
        for p in r.data.get("ports", []):
            lines.append(
                f"| {p['host']} | {p['port']}/{p['proto']} | {p['state']} | "
                f"{_cell(p['service'])} | {_cell(p['banner'])} | {_cell(p['tls'])} |"
            )
        lines.append("")
    return "\n".join(lines)
