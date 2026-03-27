"""
PDF renderer for audit reports.

Converts the Jinja2 Markdown/HTML audit report into a professional PDF
suitable for CISO review, regulatory submission, and client delivery.

Requires: pip install weasyprint

Usage:
    from reporting.pdf_renderer import AuditPDFRenderer
    from reporting.audit_report import AuditReportAssembler

    assembler = AuditReportAssembler(constitution)
    report    = assembler.build(...)

    renderer  = AuditPDFRenderer()
    pdf_path  = renderer.render(report, output_path=Path("reports/audit.pdf"))
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("reporting.pdf")

# ---------------------------------------------------------------------------
# HTML template for PDF (standalone, styled)
# ---------------------------------------------------------------------------

_PDF_CSS = """
@page {
    size: A4;
    margin: 2cm 2.5cm;
    @top-center {
        content: "Adversarial Constitution — Confidential Audit Report";
        font-size: 8pt;
        color: #888;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #888;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.6;
    color: #1a1a1a;
}

/* Cover page */
.cover {
    page: cover;
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-height: 25cm;
    padding: 3cm 0;
}
.cover-logo {
    font-size: 28pt;
    font-weight: 700;
    color: #1a1a1a;
    letter-spacing: -1px;
    margin-bottom: 0.5cm;
}
.cover-logo span { color: #e85d24; }
.cover-title {
    font-size: 18pt;
    font-weight: 300;
    color: #444;
    margin-bottom: 1.5cm;
}
.cover-meta {
    font-size: 10pt;
    color: #666;
    border-top: 1px solid #ddd;
    padding-top: 0.8cm;
    margin-top: 0.5cm;
}
.cover-meta table { border-collapse: collapse; }
.cover-meta td { padding: 4px 16px 4px 0; }
.cover-meta td:first-child { font-weight: 600; color: #333; width: 8cm; }

/* Score badge */
.score-badge {
    display: inline-block;
    padding: 12px 24px;
    border-radius: 8px;
    font-size: 28pt;
    font-weight: 700;
    margin: 1cm 0;
}
.score-low    { background: #d4edda; color: #155724; }
.score-medium { background: #fff3cd; color: #856404; }
.score-high   { background: #f8d7da; color: #721c24; }
.score-crit   { background: #f5c6cb; color: #491217; }

/* Headings */
h1 { font-size: 18pt; font-weight: 600; margin: 1.5cm 0 0.4cm; color: #111; border-bottom: 2px solid #e85d24; padding-bottom: 4px; }
h2 { font-size: 13pt; font-weight: 600; margin: 1cm 0 0.3cm; color: #222; }
h3 { font-size: 11pt; font-weight: 600; margin: 0.8cm 0 0.2cm; color: #333; }

p  { margin-bottom: 0.4cm; }
ul, ol { margin: 0.3cm 0 0.4cm 1.2cm; }
li { margin-bottom: 2px; }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.5cm 0;
    font-size: 9pt;
    page-break-inside: avoid;
}
th {
    background: #f0f0f0;
    font-weight: 600;
    padding: 6px 10px;
    text-align: left;
    border: 1px solid #ddd;
}
td {
    padding: 5px 10px;
    border: 1px solid #ddd;
    vertical-align: top;
}
tr:nth-child(even) td { background: #fafafa; }

/* Severity badges */
.sev-critical { background: #f5c6cb; color: #491217; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 8pt; }
.sev-high     { background: #fde8cc; color: #7d4a00; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 8pt; }
.sev-medium   { background: #fff3cd; color: #856404; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 8pt; }
.sev-low      { background: #d4edda; color: #155724; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 8pt; }

/* Code / payload blocks */
pre, code {
    font-family: "Courier New", monospace;
    font-size: 8pt;
    background: #f4f4f4;
    border: 1px solid #ddd;
    border-radius: 4px;
}
pre  { padding: 8px 12px; margin: 0.3cm 0; overflow-wrap: break-word; white-space: pre-wrap; }
code { padding: 1px 4px; }

/* Alert boxes */
.alert-critical {
    background: #f8d7da; border-left: 4px solid #dc3545;
    padding: 10px 14px; margin: 0.4cm 0; border-radius: 0 4px 4px 0;
}
.alert-info {
    background: #d1ecf1; border-left: 4px solid #17a2b8;
    padding: 10px 14px; margin: 0.4cm 0; border-radius: 0 4px 4px 0;
}

/* Page breaks */
.page-break { page-break-before: always; }
.no-break   { page-break-inside: avoid; }

/* Footer signature block */
.signature-block {
    margin-top: 2cm;
    border-top: 1px solid #ddd;
    padding-top: 1cm;
}
.sig-line {
    display: inline-block;
    width: 7cm;
    border-bottom: 1px solid #333;
    margin-right: 2cm;
    padding-bottom: 0;
}
"""

_PDF_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>{{ css }}</style>
</head>
<body>

<!-- Cover page -->
<div class="cover">
  <div class="cover-logo">Ant'z <span>Studio</span></div>
  <div class="cover-title">Adversarial Constitution<br>Formal Audit Report</div>

  {% set score = report.overall_score %}
  {% if score >= 85 %}
    <div class="score-badge score-low">{{ score | round(1) }} / 100 &nbsp; LOW RISK</div>
  {% elif score >= 65 %}
    <div class="score-badge score-medium">{{ score | round(1) }} / 100 &nbsp; MEDIUM RISK</div>
  {% elif score >= 40 %}
    <div class="score-badge score-high">{{ score | round(1) }} / 100 &nbsp; HIGH RISK</div>
  {% else %}
    <div class="score-badge score-crit">{{ score | round(1) }} / 100 &nbsp; CRITICAL RISK</div>
  {% endif %}

  <div class="cover-meta">
    <table>
      <tr><td>Constitution</td><td><code>{{ report.constitution_id }}</code> v{{ report.constitution_version }}</td></tr>
      <tr><td>Domain</td><td>{{ report.domain | title }}</td></tr>
      <tr><td>Test date</td><td>{{ report.test_date.strftime('%Y-%m-%d') }}</td></tr>
      <tr><td>Generated</td><td>{{ report.generated_at.strftime('%Y-%m-%dT%H:%M:%SZ') }}</td></tr>
      <tr><td>Author</td><td>{{ report.constitution_author }}</td></tr>
      <tr><td>Attack modules</td><td>{{ report.total_attack_types }}</td></tr>
      <tr><td>Total probes</td><td>{{ report.total_probes }}</td></tr>
      <tr><td>Critical findings</td><td>{{ report.critical_count }}</td></tr>
      <tr><td>Report ID</td><td><code>{{ report.report_id }}</code></td></tr>
      <tr><td>SHA-256</td><td><code style="font-size:7pt">{{ report.constitution_checksum }}</code></td></tr>
    </table>
  </div>

  <p style="margin-top:1.5cm;font-size:8pt;color:#999">
    CONFIDENTIAL — For internal and regulatory use only.<br>
    Generated by Adversarial Constitution Framework v{{ report.framework_version }} (Ant'z Studio)
  </p>
</div>

<!-- Section 1: Executive Summary -->
<div class="page-break">
<h1>1. Executive Summary</h1>

{% if report.critical_count > 0 %}
<div class="alert-critical">
  <strong>⚠ {{ report.critical_count }} CRITICAL vulnerability(-ies) require immediate remediation
  before production deployment.</strong>
</div>
{% else %}
<div class="alert-info">
  No CRITICAL vulnerabilities detected. Review HIGH findings before deployment.
</div>
{% endif %}

<p>This report documents the results of an automated adversarial testing campaign
conducted against the Agentic Constitution <code>{{ report.constitution_id }}</code>
version {{ report.constitution_version }}, deployed in a <strong>{{ report.domain }}</strong> context.</p>

<p>The campaign covered <strong>{{ report.total_attack_types }} attack modules</strong>
across <strong>{{ report.total_probes }} individual probes</strong>.</p>

<h2>Attack Coverage</h2>
<table>
  <tr><th>Module</th><th>Description</th><th>Probes</th></tr>
  {% for cat in report.attack_categories %}
  <tr>
    <td><strong>{{ cat.name }}</strong></td>
    <td>{{ cat.description }}</td>
    <td>{{ cat.probes }}</td>
  </tr>
  {% endfor %}
</table>

<h2>Models Used</h2>
<table>
  <tr><th>Role</th><th>Model</th><th>Provider</th></tr>
  <tr><td>Target agent</td><td><code>{{ report.target_model }}</code></td><td>{{ report.target_provider }}</td></tr>
  <tr><td>Judge / evaluator</td><td><code>{{ report.judge_model }}</code></td><td>{{ report.judge_provider }}</td></tr>
</table>
</div>

<!-- Section 2: Vulnerability Findings -->
<div class="page-break">
<h1>2. Vulnerability Findings</h1>

{% if report.vulnerabilities | length == 0 %}
<p>No vulnerabilities were detected in this test run.</p>
{% else %}
<p>Found <strong>{{ report.vulnerabilities | length }} vulnerabilit{{ 'y' if report.vulnerabilities | length == 1 else 'ies' }}</strong>
across {{ report.affected_rules | length }} rule(s).</p>

{% for vuln in report.vulnerabilities %}
<div class="no-break">
<h3>{{ loop.index }}. {{ vuln.rule_id }} — {{ vuln.attack_type }}</h3>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Severity</td><td><span class="sev-{{ vuln.severity | lower }}">{{ vuln.severity }}</span></td></tr>
  <tr><td>Attack type</td><td>{{ vuln.attack_type }}</td></tr>
  <tr><td>Success rate</td><td>{{ (vuln.success_rate * 100) | round(1) }}%</td></tr>
  {% if vuln.technique %}<tr><td>Technique</td><td><code>{{ vuln.technique }}</code></td></tr>{% endif %}
  {% if vuln.bypass_multiplier %}<tr><td>Bypass multiplier</td><td>{{ vuln.bypass_multiplier | round(2) }}×</td></tr>{% endif %}
</table>

<p><strong>Best attack payload:</strong></p>
<pre>{{ vuln.best_payload }}</pre>

<p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>

{% if vuln.regulatory_citations %}
<p><strong>Regulatory references:</strong></p>
<ul>{% for c in vuln.regulatory_citations %}<li>{{ c }}</li>{% endfor %}</ul>
{% endif %}
</div>
{% endfor %}
{% endif %}
</div>

<!-- Section 3: Threshold Analysis -->
<div class="page-break">
<h1>3. Threshold Analysis</h1>
{% if report.threshold_report %}
<table>
  <tr><th>Limit</th><th>Declared (USD)</th><th>Effective (USD)</th><th>Status</th></tr>
  {% for f in report.threshold_report.vulnerabilities %}
  <tr>
    <td>{{ f.limit_name }}</td>
    <td>${{ f.declared_limit_usd | round(2) }}</td>
    <td>{% if f.effective_limit_usd is none or f.effective_limit_usd == "" or (f.effective_limit_usd is number and f.effective_limit_usd > 99999) %}Unlimited{% else %}${{ f.effective_limit_usd | round(2) }}{% endif %}</td>
    <td>{% if f.finding == 'HARDENED' %}✅ Hardened{% else %}❌ {{ f.finding }}{% endif %}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p>Threshold probing was not executed in this test run.</p>
{% endif %}
</div>

<!-- Section 4: Regulatory Mapping -->
<div class="page-break">
<h1>4. Regulatory Mapping</h1>

<h2>EU AI Act (Annex III — High-Risk AI Systems)</h2>
<table>
  <tr><th>Article</th><th>Requirement</th><th>Status</th></tr>
  <tr><td>Art. 9</td><td>Risk management with adversarial testing</td><td>{{ "✅" if report.eu_ai_act.art9_covered else "❌" }}</td></tr>
  <tr><td>Art. 10</td><td>Data governance and quality</td><td>{{ "✅" if report.eu_ai_act.art10_covered else "⚠️" }}</td></tr>
  <tr><td>Art. 12</td><td>Logging and traceability</td><td>{{ "✅" if report.eu_ai_act.art12_covered else "❌" }}</td></tr>
  <tr><td>Art. 13</td><td>Transparency</td><td>{{ "✅" if report.eu_ai_act.art13_covered else "⚠️" }}</td></tr>
  <tr><td>Art. 14</td><td>Human oversight (escalation triggers)</td><td>{{ "✅" if report.eu_ai_act.art14_covered else "❌" }}</td></tr>
  <tr><td>Art. 15</td><td>Accuracy, robustness, cybersecurity</td><td>{{ "✅" if report.eu_ai_act.art15_covered else "❌" }}</td></tr>
</table>

<h2>LGPD (Lei nº 13.709/2018)</h2>
<table>
  <tr><th>Article</th><th>Requirement</th><th>Status</th></tr>
  <tr><td>Art. 6°</td><td>Principles of purpose and necessity</td><td>{{ "✅" if report.lgpd.art6_covered else "⚠️" }}</td></tr>
  <tr><td>Art. 46</td><td>Security measures</td><td>{{ "✅" if report.lgpd.art46_covered else "❌" }}</td></tr>
  <tr><td>Art. 48</td><td>Incident communication</td><td>{{ "✅" if report.lgpd.art48_covered else "⚠️" }}</td></tr>
  <tr><td>Art. 50</td><td>Governance programs</td><td>{{ "✅" if report.lgpd.art50_covered else "⚠️" }}</td></tr>
</table>

<h2>BACEN Resolution 4.893/2021</h2>
<table>
  <tr><th>Requirement</th><th>Status</th></tr>
  <tr><td>§12 — Audit trail integrity</td><td>{{ "✅" if report.bacen.audit_trail else "❌" }}</td></tr>
  <tr><td>§14 — Incident escalation</td><td>{{ "✅" if report.bacen.incident_escalation else "❌" }}</td></tr>
  <tr><td>§17 — Third-party controls</td><td>{{ "✅" if report.bacen.third_party_controls else "⚠️ Not tested" }}</td></tr>
</table>
</div>

<!-- Section 5: Hardened Constitution -->
<div class="page-break">
<h1>5. Hardened Constitution</h1>
{% if report.hardened_constitution_path %}
<p>A patched version has been generated at: <code>{{ report.hardened_constitution_path }}</code></p>
<h2>Patches Applied</h2>
{% for patch in report.patches_applied %}
<div class="no-break">
  <h3><code>{{ patch.rule_id }}</code></h3>
  <p>{{ patch.description }}</p>
</div>
{% endfor %}
{% else %}
<p>No automatic patches were generated. Apply recommendations from Section 2 manually.</p>
{% endif %}

<!-- Signature block -->
<div class="signature-block">
<h2>Sign-off</h2>
<p>By signing below, the responsible parties confirm they have reviewed this report
and acknowledge the findings.</p>
<br><br>
<span class="sig-line"></span>
<span class="sig-line"></span>
<br>
<span style="display:inline-block;width:7cm;font-size:8pt;color:#666">AI Governance Officer &nbsp;&nbsp;&nbsp; Date</span>
<span style="display:inline-block;width:7cm;font-size:8pt;color:#666">CISO / Security Officer &nbsp;&nbsp;&nbsp; Date</span>
</div>

<p style="margin-top:1.5cm;font-size:8pt;color:#aaa">
Report hash: <code>{{ report.report_hash }}</code><br>
Next review due: {{ report.next_review_date }}<br>
Contact: {{ report.audit_contact }}<br>
Generated by Adversarial Constitution Framework v{{ report.framework_version }} — Ant'z Studio
</p>
</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

class AuditPDFRenderer:
    """
    Renders an AuditReport to a PDF file using WeasyPrint.

    Falls back to HTML output with a warning if WeasyPrint is not installed.
    """

    def __init__(self) -> None:
        try:
            import weasyprint  # noqa: F401
            self._weasyprint_available = True
        except ImportError:
            self._weasyprint_available = False
            logger.warning(
                "WeasyPrint not installed — PDF export will fall back to HTML. "
                "Install with: pip install weasyprint"
            )

    def render(self, report: Any, output_path: Path) -> Path:
        """
        Render the report to PDF (or HTML fallback).

        Args:
            report:      An AuditReport instance.
            output_path: Destination path (.pdf recommended).

        Returns:
            Path to the generated file.
        """
        html_content = self._render_html(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self._weasyprint_available:
            import weasyprint
            pdf_path = output_path.with_suffix(".pdf")
            weasyprint.HTML(string=html_content).write_pdf(str(pdf_path))
            logger.info(f"PDF report saved to {pdf_path}")
            return pdf_path
        else:
            html_path = output_path.with_suffix(".html")
            html_path.write_text(html_content, encoding="utf-8")
            logger.warning(f"WeasyPrint unavailable — HTML saved to {html_path}")
            return html_path

    def render_html(self, report: Any, output_path: Path) -> Path:
        """Render as HTML only (no PDF conversion)."""
        html_content = self._render_html(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        html_path = output_path.with_suffix(".html")
        html_path.write_text(html_content, encoding="utf-8")
        return html_path

    @staticmethod
    def _render_html(report: Any) -> str:
        from jinja2 import BaseLoader, Environment
        env      = Environment(loader=BaseLoader())
        template = env.from_string(_PDF_HTML_TEMPLATE)
        return template.render(report=report, css=_PDF_CSS)