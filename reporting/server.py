"""
Audit Dashboard — FastAPI web server for browsing audit reports.

Serves a local web UI that lists all reports in the reports/ directory,
shows vulnerability details with severity filtering, and provides
PDF/JSON/Markdown download links.

Usage:
    python -m reporting.server
    # or via docker-compose: service audit-dashboard
    # or via CLI: antz serve

Endpoints:
    GET  /              → dashboard (list all reports)
    GET  /report/{id}   → full report view
    GET  /health        → health check
    GET  /download/{id}/{format}  → download json|md|pdf
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("reporting.server")

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPORTS_DIR      = Path(os.environ.get("REPORTS_DIR",      "reports"))
CONSTITUTION_DIR = Path(os.environ.get("CONSTITUTION_DIR", "constitution/examples"))
HOST             = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
PORT             = int(os.environ.get("DASHBOARD_PORT", "8080"))

# ---------------------------------------------------------------------------
# HTML templates (inline — no Jinja2 dependency for the server itself)
# ---------------------------------------------------------------------------

_BASE_STYLE = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, sans-serif; font-size: 14px; color: #1a1a1a; background: #f5f5f5; }
.nav  { background: #1a1a1a; color: #fff; padding: 14px 28px; display: flex; align-items: center; gap: 16px; }
.nav h1 { font-size: 16px; font-weight: 600; }
.nav span { font-size: 12px; color: #aaa; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px; }
.card { background: #fff; border-radius: 8px; border: 1px solid #e0e0e0; margin-bottom: 16px; overflow: hidden; }
.card-header { padding: 14px 20px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 12px; }
.card-body  { padding: 16px 20px; }
.badge { display: inline-block; padding: 3px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.badge-crit   { background: #fde8e8; color: #c0392b; }
.badge-high   { background: #fef3e0; color: #d68910; }
.badge-medium { background: #fefde0; color: #9a7d0a; }
.badge-ok     { background: #e8f8f0; color: #1e8449; }
.score { font-size: 28px; font-weight: 700; }
.score-low  { color: #1e8449; }
.score-med  { color: #d68910; }
.score-high { color: #c0392b; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #f0f0f0; padding: 8px 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: 600; }
td { padding: 7px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.btn { display: inline-block; padding: 6px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; text-decoration: none; cursor: pointer; border: 1px solid transparent; }
.btn-primary { background: #e85d24; color: #fff; }
.btn-outline { background: #fff; color: #333; border-color: #ccc; }
.btn:hover   { opacity: 0.85; }
pre  { background: #f4f4f4; border: 1px solid #ddd; border-radius: 4px; padding: 10px 14px; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
code { background: #f4f4f4; border-radius: 3px; padding: 1px 5px; font-size: 12px; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.stat { text-align: center; }
.stat-value { font-size: 28px; font-weight: 700; }
.stat-label { font-size: 12px; color: #666; margin-top: 2px; }
.empty { text-align: center; color: #999; padding: 40px; }
</style>
"""

# ---------------------------------------------------------------------------
# Report loader
# ---------------------------------------------------------------------------

def _list_reports() -> list[dict[str, Any]]:
    """Load all JSON reports from REPORTS_DIR."""
    reports = []
    if not REPORTS_DIR.exists():
        return reports
    for f in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            data["_file"] = f.name
            data["_stem"] = f.stem
            reports.append(data)
        except Exception:
            continue
    return reports


def _load_report(stem: str) -> dict[str, Any] | None:
    path = REPORTS_DIR / f"{stem}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _score_class(score: float) -> str:
    if score >= 85:
        return "score-low"
    if score >= 65:
        return "score-med"
    return "score-high"


def _sev_badge(sev: str) -> str:
    cls = {"CRITICAL": "badge-crit", "HIGH": "badge-high", "MEDIUM": "badge-medium"}.get(sev, "badge-ok")
    return f'<span class="badge {cls}">{sev}</span>'

# ---------------------------------------------------------------------------
# Page builders
# ---------------------------------------------------------------------------

def _render_dashboard(reports: list[dict]) -> str:
    rows = ""
    if not reports:
        rows = '<div class="empty">No reports found. Run an audit first:<br><code>antz run -c constitution/examples/banking.yaml ...</code></div>'
    else:
        for r in reports:
            score     = r.get("overall_score", 0)
            sc        = _score_class(score)
            crit      = r.get("critical_count", 0)
            badge     = _sev_badge("CRITICAL") if crit > 0 else '<span class="badge badge-ok">CLEAN</span>'
            stem      = r.get("_stem", "")
            rows += f"""
            <div class="card">
              <div class="card-header">
                <div class="score {sc}">{score:.0f}</div>
                <div style="flex:1">
                  <div style="font-weight:600;font-size:15px">{r.get('constitution','?')} v{r.get('version','?')}</div>
                  <div style="color:#666;font-size:12px">{r.get('domain','').title()} · {r.get('test_date','?')} · {r.get('total_probes',0)} probes</div>
                </div>
                {badge}
                <a class="btn btn-primary" href="/report/{stem}">View Report</a>
                <a class="btn btn-outline" href="/download/{stem}/json">JSON</a>
              </div>
            </div>
            """

    return f"""<!DOCTYPE html><html><head><title>Audit Dashboard</title>{_BASE_STYLE}</head><body>
    <div class="nav">
      <h1>🐜 Ant'z Studio</h1>
      <span>Adversarial Constitution — Audit Dashboard</span>
    </div>
    <div class="container">
      <h2 style="margin:20px 0 16px;font-size:18px">Audit Reports ({len(reports)})</h2>
      {rows}
    </div>
    </body></html>"""


def _render_report_page(data: dict) -> str:
    stem  = data.get("_stem", data.get("report_id", "report"))
    vulns = data.get("vulnerabilities", [])

    vuln_rows = ""
    for v in vulns:
        rate     = v.get("success_rate", 0)
        rate_str = f"{rate*100:.0f}%"
        color    = "color:#c0392b" if rate > 0.3 else ("color:#d68910" if rate > 0 else "color:#1e8449")
        vuln_rows += f"""
        <tr>
          <td><code>{v.get('rule','')}</code></td>
          <td>{_sev_badge(v.get('severity',''))}</td>
          <td>{v.get('attack_type','')}</td>
          <td style="font-weight:600;{color}">{rate_str}</td>
          <td style="font-size:11px;max-width:300px">{v.get('recommendation','')[:120]}...</td>
        </tr>
        """

    if not vuln_rows:
        vuln_rows = '<tr><td colspan="5" style="text-align:center;color:#1e8449;padding:20px">✅ No vulnerabilities detected</td></tr>'

    score = data.get("overall_score", 0)
    sc    = _score_class(score)

    return f"""<!DOCTYPE html><html><head><title>Report — {data.get('constitution')}</title>{_BASE_STYLE}</head><body>
    <div class="nav">
      <h1>🐜 Ant'z Studio</h1>
      <span><a href="/" style="color:#aaa;text-decoration:none">Dashboard</a> → {data.get('constitution')}</span>
      <div style="margin-left:auto;display:flex;gap:8px">
        <a class="btn btn-outline" href="/download/{stem}/json">⬇ JSON</a>
        <a class="btn btn-outline" href="/download/{stem}/md">⬇ Markdown</a>
        <a class="btn btn-primary" href="/download/{stem}/pdf">⬇ PDF</a>
      </div>
    </div>
    <div class="container">

      <div class="card" style="margin-top:20px">
        <div class="card-body grid-2">
          <div>
            <div style="font-size:13px;color:#666;margin-bottom:4px">Overall Risk Score</div>
            <div class="score {sc}" style="font-size:48px">{score:.1f}<span style="font-size:20px;color:#999"> / 100</span></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;align-items:center">
            <div class="stat"><div class="stat-value" style="color:#c0392b">{data.get('critical_count',0)}</div><div class="stat-label">Critical</div></div>
            <div class="stat"><div class="stat-value" style="color:#d68910">{data.get('high_count',0)}</div><div class="stat-label">High</div></div>
            <div class="stat"><div class="stat-value">{data.get('total_probes',0)}</div><div class="stat-label">Probes</div></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><strong>Vulnerability Findings</strong></div>
        <table>
          <tr><th>Rule</th><th>Severity</th><th>Attack Type</th><th>Bypass Rate</th><th>Recommendation</th></tr>
          {vuln_rows}
        </table>
      </div>

      <div class="card">
        <div class="card-header"><strong>Report Metadata</strong></div>
        <div class="card-body">
          <table>
            <tr><td><strong>Constitution</strong></td><td><code>{data.get('constitution')}</code> v{data.get('version')}</td></tr>
            <tr><td><strong>Test date</strong></td><td>{data.get('test_date')}</td></tr>
            <tr><td><strong>Domain</strong></td><td>{data.get('domain','').title()}</td></tr>
            <tr><td><strong>Report ID</strong></td><td><code>{data.get('report_id')}</code></td></tr>
            <tr><td><strong>SHA-256</strong></td><td><code style="font-size:11px">{data.get('constitution_checksum','')}</code></td></tr>
            <tr><td><strong>Report hash</strong></td><td><code style="font-size:11px">{data.get('report_hash','')}</code></td></tr>
          </table>
        </div>
      </div>

    </div>
    </body></html>"""

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

def create_app() -> Any:
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI and uvicorn are required for the dashboard. "
            "Install with: pip install fastapi uvicorn"
        )

    app = FastAPI(
        title="Adversarial Constitution — Audit Dashboard",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "reports": len(_list_reports())})

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        reports = _list_reports()
        return HTMLResponse(_render_dashboard(reports))

    @app.get("/report/{stem}", response_class=HTMLResponse)
    async def report_view(stem: str) -> HTMLResponse:
        data = _load_report(stem)
        if not data:
            raise HTTPException(status_code=404, detail=f"Report '{stem}' not found")
        data["_stem"] = stem
        return HTMLResponse(_render_report_page(data))

    @app.get("/download/{stem}/{fmt}")
    async def download(stem: str, fmt: str) -> Any:
        if fmt == "json":
            path = REPORTS_DIR / f"{stem}.json"
            if not path.exists():
                raise HTTPException(404, "Report not found")
            return FileResponse(path, media_type="application/json", filename=f"{stem}.json")

        elif fmt == "md":
            path = REPORTS_DIR / f"{stem}.md"
            if path.exists():
                return FileResponse(path, media_type="text/markdown", filename=f"{stem}.md")

            # Generate markdown on-the-fly from JSON
            data = _load_report(stem)
            if not data:
                raise HTTPException(404, "Report not found")

            lines = [
                "# Adversarial Constitution — Audit Report",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Constitution | `{data.get('constitution')}` v{data.get('version')} |",
                f"| Domain | {data.get('domain', '').title()} |",
                f"| Test date | {data.get('test_date')} |",
                f"| Overall score | **{data.get('overall_score', 0):.1f} / 100** |",
                f"| Critical findings | {data.get('critical_count', 0)} |",
                f"| High findings | {data.get('high_count', 0)} |",
                f"| Total probes | {data.get('total_probes', 0)} |",
                f"| Report ID | `{data.get('report_id')}` |",
                "",
                "## Vulnerability Findings",
                "",
            ]
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                lines.append("No vulnerabilities detected.")
            else:
                lines += ["| Rule | Severity | Attack Type | Bypass Rate |", "|---|---|---|---|"]
                for v in vulns:
                    rate = f"{v.get('success_rate', 0) * 100:.0f}%"
                    lines.append(f"| `{v.get('rule')}` | {v.get('severity')} | {v.get('attack_type')} | {rate} |")
                lines.append("")
                for v in vulns:
                    lines += [
                        f"### {v.get('rule')} -- {v.get('attack_type')}",
                        "",
                        f"**Severity:** {v.get('severity')}  ",
                        f"**Bypass rate:** {v.get('success_rate', 0) * 100:.0f}%  ",
                        f"**Technique:** `{v.get('technique', 'n/a')}`",
                        "",
                        "**Best payload:**",
                        "```",
                        f"{v.get('best_payload', '')}",
                        "```",
                        "",
                        f"**Recommendation:** {v.get('recommendation', '')}",
                        "",
                        "---",
                        "",
                    ]
            ta = data.get("threshold_analysis")
            if ta:
                lines += ["## Threshold Analysis", "", "| Limit | Declared | Effective | Status |", "|---|---|---|---|"]
                for f in ta.get("findings", []):
                    eff = f.get("effective_limit_usd")
                    eff_str = "Unlimited" if eff is None else f"${eff:.2f}"
                    status = "OK" if f.get("finding") == "HARDENED" else f.get("finding", "")
                    lines.append(f"| {f.get('limit_name')} | ${f.get('declared_limit_usd', 0):.2f} | {eff_str} | {status} |")
                lines.append("")
            lines += [
                "## Metadata",
                "",
                f"- **Report hash:** `{data.get('report_hash', '')}`",
                "- **Generated by:** Adversarial Constitution Framework — Ant\'z Studio",
            ]
            md_content = "\n".join(lines)
            path.write_text(md_content, encoding="utf-8")
            return FileResponse(path, media_type="text/markdown", filename=f"{stem}.md")

        elif fmt == "pdf":
            pdf_path = REPORTS_DIR / f"{stem}.pdf"
            if pdf_path.exists():
                return FileResponse(pdf_path, media_type="application/pdf", filename=f"{stem}.pdf")

            # Generate PDF / HTML on the fly from the JSON report
            data = _load_report(stem)
            if not data:
                raise HTTPException(404, "Report not found")

            try:
                from datetime import datetime as _dt
                from reporting.pdf_renderer import AuditPDFRenderer

                # Date fields that the Jinja2 template calls .strftime() on
                _DATE_FIELDS = ("generated_at", "test_date")

                def _parse_dt(value: str) -> _dt:
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d"):
                        try:
                            return _dt.strptime(value, fmt)
                        except ValueError:
                            continue
                    return _dt.utcnow()

                class _ReportProxy:
                    """
                    Proxy over the raw JSON dict that:
                    - Converts ISO date strings to datetime objects
                    - Returns safe defaults for missing fields
                    - Exposes nested objects (eu_ai_act, lgpd, bacen, threshold_report)
                      as simple attribute containers so the template doesn't crash
                    """
                    def __getattr__(self, name: str):
                        value = data.get(name, "")

                        # Convert date strings → datetime
                        if name in _DATE_FIELDS and isinstance(value, str) and value:
                            return _parse_dt(value)

                        # Wrap regulatory coverage dicts as attribute objects
                        if name in ("eu_ai_act", "lgpd", "bacen") and isinstance(value, dict):
                            return _DictProxy(value)

                        # threshold_report: expose .vulnerabilities list
                        if name == "threshold_report":
                            ta = data.get("threshold_analysis")
                            if not ta:
                                return None

                            def _wrap_finding(f: dict) -> "_DictProxy":
                                safe = dict(f)
                                # effective_limit_usd is null in JSON when unlimited
                                if safe.get("effective_limit_usd") is None:
                                    safe["effective_limit_usd"] = float("inf")
                                return _DictProxy(safe)

                            return _DictProxy({
                                "vulnerabilities": [
                                    _wrap_finding(f) for f in ta.get("findings", [])
                                ],
                                "worst_multiplier": ta.get("worst_multiplier", 1.0),
                                "is_vulnerable": ta.get("is_vulnerable", False),
                            })

                        # vulnerabilities list — wrap each item
                        if name == "vulnerabilities" and isinstance(value, list):
                            return [_DictProxy(v) for v in value]

                        # attack_categories list
                        if name == "attack_categories" and isinstance(value, list):
                            return [_DictProxy(c) for c in value]

                        # patches_applied list
                        if name == "patches_applied" and isinstance(value, list):
                            return [_DictProxy(p) for p in value]

                        # Numeric defaults
                        if name in ("overall_score", "critical_count", "high_count",
                                    "total_probes", "total_attack_types",
                                    "prohibited_action_count", "escalation_trigger_count",
                                    "spend_limits_configured") and value == "":
                            return 0

                        return value

                class _DictProxy:
                    """Wraps a dict so attributes are accessible via dot notation."""
                    def __init__(self, d: dict):
                        object.__setattr__(self, "_d", d)
                    def __getattr__(self, name: str):
                        return self._d.get(name, "")
                    def __iter__(self):
                        return iter(self._d.get("vulnerabilities", []))

                renderer  = AuditPDFRenderer()
                html_path = renderer.render_html(_ReportProxy(), REPORTS_DIR / stem)
                return FileResponse(
                    html_path,
                    media_type="text/html",
                    filename=f"{stem}.html",
                )
            except Exception as exc:
                raise HTTPException(500, f"PDF generation failed: {exc}") from exc

        raise HTTPException(400, f"Unknown format '{fmt}'. Use: json, md, pdf")

    @app.get("/api/reports")
    async def api_reports() -> JSONResponse:
        return JSONResponse(_list_reports())

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def serve(host: str = HOST, port: int = PORT) -> None:
    if not _FASTAPI_AVAILABLE:
        print("[dashboard] FastAPI not installed. Run: pip install fastapi uvicorn")
        return

    app = create_app()
    logger.info(f"Starting audit dashboard on http://{host}:{port}")
    print(f"\n  🐜 Ant'z Studio — Audit Dashboard")
    print(f"  → http://localhost:{port}\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    serve()