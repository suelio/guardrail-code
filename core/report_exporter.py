"""Generate standalone HTML, Markdown, and JSON audit reports in PT-BR or EN."""

import datetime
import html
import json
from typing import Dict, Any
from .rules_catalog import normalize_lang


def export_json_report(scan_data: Dict[str, Any], env_data: Dict[str, Any] = None) -> str:
    """Serialize scan metrics and runtime findings into a structured JSON document."""
    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "audit_summary": scan_data,
        "environment_audit": env_data or {},
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def export_markdown_report(
    scan_data: Dict[str, Any],
    env_data: Dict[str, Any] = None,
    lang: str = "pt",
) -> str:
    """Build a human-readable Markdown summary localized to PT-BR or EN."""
    is_en = normalize_lang(lang or scan_data.get("lang", "pt")) == "en"
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M" if is_en else "%d/%m/%Y %H:%M")
    sev = scan_data.get("severity_counts", {})
    brand = "guardrail code"
    risk_lbl = "Identified risks" if is_en else "Riscos encontrados"
    fix_lbl = "Security measure" if is_en else "Como corrigir"
    duration_s = f"{(scan_data.get('scan_time_ms', 0) or 0) / 1000.0:.2f}s"

    lines = [
        f"# {brand} - {scan_data.get('project_name', 'Project' if is_en else 'Projeto')}",
        "",
        f"- **{'Audit date' if is_en else 'Data da auditoria'}:** {now_str}",
        f"- **{'Target directory' if is_en else 'Diretório analisado'}:** `{scan_data.get('target_dir', '')}`",
        f"- **{'Grade / Score' if is_en else 'Nota / Score'}:** {scan_data.get('grade', '-')} ({scan_data.get('score', 0)}/100)",
        f"- **{'Deploy verdict' if is_en else 'Veredito de deploy'}:** {scan_data.get('verdict', '')}",
        f"- **{'Scan duration' if is_en else 'Tempo de varredura'}:** {duration_s} ({scan_data.get('files_scanned', 0)} {'files' if is_en else 'arquivos'})",
        "",
        f"## {'Summary by severity' if is_en else 'Resumo por severidade'}",
        "",
        f"| {'Severity' if is_en else 'Severidade'} | {'Count' if is_en else 'Quantidade'} |",
        "| --- | ---: |",
        f"| CRITICAL | {sev.get('CRITICAL', 0)} |",
        f"| HIGH | {sev.get('HIGH', 0)} |",
        f"| MEDIUM | {sev.get('MEDIUM', 0)} |",
        f"| LOW | {sev.get('LOW', 0)} |",
        "",
    ]

    if env_data and env_data.get("runtime"):
        rt = env_data["runtime"]
        lines.extend([
            f"## {'Environment, runtime, and dependencies' if is_en else 'Ambiente, runtime e dependências'}",
            "",
            f"- **{'Installed Python' if is_en else 'Python instalado'}:** {rt.get('current_version')} (`{rt.get('executable')}`)",
            f"- **{'Latest official release' if is_en else 'Última versão oficial'}:** {rt.get('latest_official_version')} ({rt.get('status_label')})",
            f"- **{'Recommended upgrade command' if is_en else 'Comando de atualização'}:** `{rt.get('recommended_command')}`",
            "",
        ])

    lines.append(f"## {'Detailed findings and remediation plan' if is_en else 'Achados detalhados e plano de correção'}")
    lines.append("")

    findings = scan_data.get("findings") or []
    if not findings:
        lines.append(
            "No vulnerabilities or exposure issues detected."
            if is_en else
            "Nenhuma vulnerabilidade ou falha de configuracao encontrada nesta varredura."
        )
    else:
        for idx, f in enumerate(findings, start=1):
            lines.extend([
                f"### {idx}. [{f['severity']}] {f['title']}",
                f"- **{'Category' if is_en else 'Categoria'}:** {f['category_label']} (`{f['rule_id']}`)",
                f"- **{'Location' if is_en else 'Local'}:** `{f['file_path']}` ({'line' if is_en else 'linha'} {f['line']})",
                f"- **{'Matched Snippet' if is_en else 'Trecho Detectado'}:** `{f['snippet']}`",
                f"- **{risk_lbl}:** {f['plain_why']}",
                f"- **{fix_lbl}:** {f['how_to_fix']}",
                "",
            ])
            if f.get("fix_example"):
                lines.append("```python")
                lines.append(f["fix_example"])
                lines.append("```")
                lines.append("")

    return "\n".join(lines)


def export_html_report(
    scan_data: Dict[str, Any],
    env_data: Dict[str, Any] = None,
    lang: str = "pt",
) -> str:
    """Render a standalone print-ready HTML report localized to PT-BR or EN."""
    is_en = normalize_lang(lang or scan_data.get("lang", "pt")) == "en"
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M" if is_en else "%d/%m/%Y %H:%M")
    sev = scan_data.get("severity_counts", {})
    findings = scan_data.get("findings") or []

    brand = "guardrail code"
    risk_lbl = "Identified risks:" if is_en else "Riscos encontrados:"
    fix_lbl = "Security measure:" if is_en else "Medida de segurança:"
    doc_lang = "en" if is_en else "pt-BR"

    grade = scan_data.get("grade", "F")
    grade_color = {
        "A": "#137333",
        "B": "#1a73e8",
        "C": "#b06000",
        "D": "#c5221f",
        "F": "#a50e0e",
    }.get(grade, "#3c4043")

    rows_html = ""
    for f in findings:
        sev_cls = f["severity"].lower()
        fix_block = f"<pre>{html.escape(f['fix_example'])}</pre>" if f.get("fix_example") else ""
        file_word = "File" if is_en else "Arquivo"
        line_word = "Line" if is_en else "Linha"
        rule_word = "Rule" if is_en else "Regra"
        rows_html += f"""
        <div class="finding-card sev-{sev_cls}">
            <div class="finding-head">
                <span class="sev-badge {sev_cls}">{html.escape(f['severity'])}</span>
                <span class="cat-badge">{html.escape(f['category_label'])}</span>
                <strong>{html.escape(f['title'])}</strong>
            </div>
            <div class="meta-line">{file_word}: <code>{html.escape(f['file_path'])}</code> ({line_word} {f['line']}) &bull; {rule_word}: <code>{html.escape(f['rule_id'])}</code></div>
            <pre class="snippet">{html.escape(f['snippet'])}</pre>
            <p><strong>{risk_lbl}</strong> {html.escape(f['plain_why'])}</p>
            <p><strong>{fix_lbl}</strong> {html.escape(f['how_to_fix'])}</p>
            {fix_block}
        </div>
        """

    if not rows_html:
        rows_html = (
            "<div class='ok-box'>No vulnerabilities or credential exposures detected.</div>"
            if is_en else
            "<div class='ok-box'>Nenhuma vulnerabilidade ou exposicao detectada. Codigo em conformidade basica de deploy.</div>"
        )

    runtime_html = ""
    if env_data and env_data.get("runtime"):
        rt = env_data["runtime"]
        runtime_html = f"""
        <section class="panel">
            <h2>{'Environment, runtime, and dependencies' if is_en else 'Ambiente, runtime e dependências'}</h2>
            <p><strong>{'Active Python' if is_en else 'Python ativo'}:</strong> {html.escape(str(rt.get('current_version')))} &bull;
               <strong>{'Latest official' if is_en else 'Última versão oficial'}:</strong> {html.escape(str(rt.get('latest_official_version')))} &bull;
               <strong>Status:</strong> {html.escape(str(rt.get('status_label')))}</p>
            <p><strong>{'Upgrade command' if is_en else 'Comando recomendado'}:</strong> <code>{html.escape(str(rt.get('recommended_command')))}</code></p>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="{doc_lang}">
<head>
<meta charset="UTF-8">
<title>{html.escape(brand)} - {html.escape(str(scan_data.get('project_name', 'Project')))}</title>
<style>
    body {{ font-family: 'Segoe UI', Roboto, Arial, sans-serif; color: #1f2937; margin: 32px; background: #ffffff; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e5e7eb; padding-bottom: 16px; margin-bottom: 24px; }}
    .grade-box {{ background: {grade_color}; color: #fff; padding: 14px 22px; border-radius: 10px; text-align: center; }}
    .grade-letter {{ font-size: 28px; font-weight: 800; line-height: 1; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
    .kpi {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; background: #f9fafb; }}
    .kpi span {{ display: block; font-size: 12px; color: #6b7280; }}
    .kpi strong {{ font-size: 20px; color: #111827; }}
    .panel {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 20px; background: #f8fafc; }}
    .finding-card {{ border: 1px solid #e5e7eb; border-left: 5px solid #9ca3af; border-radius: 8px; padding: 14px; margin-bottom: 14px; page-break-inside: avoid; }}
    .sev-critical {{ border-left-color: #b91c1c; }}
    .sev-high {{ border-left-color: #d97706; }}
    .sev-medium {{ border-left-color: #2563eb; }}
    .sev-low {{ border-left-color: #6b7280; }}
    .finding-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 15px; }}
    .sev-badge {{ padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; }}
    .sev-badge.critical {{ background: #b91c1c; }}
    .sev-badge.high {{ background: #d97706; }}
    .sev-badge.medium {{ background: #2563eb; }}
    .sev-badge.low {{ background: #4b5563; }}
    .cat-badge {{ padding: 2px 8px; border-radius: 999px; font-size: 11px; background: #eef2ff; color: #3730a3; }}
    .meta-line {{ font-size: 12px; color: #4b5563; margin-bottom: 8px; }}
    pre {{ background: #f3f4f6; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
    .ok-box {{ padding: 18px; background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; border-radius: 8px; font-weight: 600; }}
    @media print {{ body {{ margin: 16px; }} .no-print {{ display: none; }} }}
</style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin:0 0 4px 0;">{html.escape(brand)} &mdash; {'Executive security report' if is_en else 'Relatório de segurança'}</h1>
            <div style="color:#4b5563; font-size:13px;">{'Project' if is_en else 'Projeto'}: <strong>{html.escape(str(scan_data.get('project_name')))}</strong> &bull; {'Path' if is_en else 'Caminho'}: <code>{html.escape(str(scan_data.get('target_dir')))}</code> &bull; {'Generated' if is_en else 'Emissão'}: {now_str}</div>
        </div>
        <div class="grade-box">
            <div class="grade-letter">{html.escape(grade)}</div>
            <div style="font-size:12px;">Score {scan_data.get('score', 0)}/100</div>
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi"><span>{'Verdict' if is_en else 'Veredito'}</span><strong>{html.escape(str(scan_data.get('verdict', '')))}</strong></div>
        <div class="kpi"><span>{'Critical / High' if is_en else 'Críticos / Altos'}</span><strong>{sev.get('CRITICAL', 0)} / {sev.get('HIGH', 0)}</strong></div>
        <div class="kpi"><span>{'Medium / Low' if is_en else 'Médios / Baixos'}</span><strong>{sev.get('MEDIUM', 0)} / {sev.get('LOW', 0)}</strong></div>
        <div class="kpi"><span>{'Scan speed' if is_en else 'Varredura'}</span><strong>{scan_data.get('scan_time_ms', 0)} ms ({scan_data.get('files_scanned', 0)} {'files' if is_en else 'arq'})</strong></div>
    </div>

    {runtime_html}

    <section>
        <h2>{'Diagnostics and remediation plan' if is_en else 'Diagnóstico e plano de ação'}</h2>
        {rows_html}
    </section>
</body>
</html>
"""
