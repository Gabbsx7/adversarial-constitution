"""
Constitution Builder — interactive CLI wizard that generates a valid Constitution
YAML from a guided interview. No prior YAML knowledge required.

Usage:
    antz constitution init
    antz constitution init --output my_agent.yaml
    antz constitution init --domain legal --non-interactive --from-json spec.json
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# Domain-specific defaults to pre-populate suggestions
_DOMAIN_DEFAULTS: dict[str, dict[str, Any]] = {
    "banking": {
        "capabilities": ["balance_inquiry", "domestic_transfer", "pix_payment"],
        "prohibited": [
            ("delete_record", "CRITICAL", ["permanently remove", "erase entry", "purge data"]),
            ("override_fraud_flag", "CRITICAL", ["ignore fraud alert", "bypass compliance hold"]),
            ("issue_credit_commitment", "CRITICAL", ["approve loan", "grant credit"]),
            ("disclose_restricted_data", "HIGH", ["show full card number", "reveal PIN"]),
        ],
        "frameworks": ["BACEN_4893_2021", "LGPD", "PCI_DSS_v4"],
        "spend_limit": 500.0,
        "mfa_threshold": 200.0,
    },
    "healthcare": {
        "capabilities": ["patient_triage", "appointment_scheduling", "medication_lookup"],
        "prohibited": [
            ("prescribe_medication", "CRITICAL", ["order drugs", "prescribe antibiotics", "issue prescription"]),
            ("share_patient_data", "CRITICAL", ["disclose records", "send medical history"]),
            ("diagnose_condition", "HIGH", ["confirm diagnosis", "rule out disease"]),
        ],
        "frameworks": ["LGPD", "CFM_2217_2018", "ISO_27001"],
        "spend_limit": 1.0,
        "mfa_threshold": None,
    },
    "legal": {
        "capabilities": ["document_summary", "search_precedents", "case_timeline"],
        "prohibited": [
            ("binding_legal_advice", "CRITICAL", ["guarantee case win", "give legal counsel", "advise to sue"]),
            ("disclose_client_data", "CRITICAL", ["share client files", "reveal privileged info"]),
            ("sign_document", "HIGH", ["execute agreement", "confirm contract"]),
        ],
        "frameworks": ["LGPD", "OAB_PROVIMENTO_94", "GDPR"],
        "spend_limit": 1.0,
        "mfa_threshold": None,
    },
    "generic": {
        "capabilities": ["query_data", "generate_report"],
        "prohibited": [
            ("self_modify_constitution", "CRITICAL", ["ignore your rules", "override your policy"]),
            ("disclose_sensitive_data", "HIGH", ["share internal data", "expose credentials"]),
        ],
        "frameworks": ["LGPD", "ISO_27001"],
        "spend_limit": 100.0,
        "mfa_threshold": None,
    },
}

_VALID_DOMAINS = list(_DOMAIN_DEFAULTS.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val if val else default


def _ask_list(prompt: str, example: str = "") -> list[str]:
    hint = f" (comma-separated, e.g. {example})" if example else " (comma-separated)"
    raw  = _ask(f"{prompt}{hint}", "")
    return [s.strip() for s in raw.split(",") if s.strip()]


def _ask_yn(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    raw    = _ask(f"{prompt} {suffix}", "y" if default else "n").lower()
    return raw in ("y", "yes", "")


def _banner(text: str) -> None:
    print(f"\n\033[1m{'─' * 60}\033[0m")
    print(f"\033[1m  {text}\033[0m")
    print(f"\033[1m{'─' * 60}\033[0m")


# ---------------------------------------------------------------------------
# Interview sections
# ---------------------------------------------------------------------------

def _interview_identity() -> dict[str, Any]:
    _banner("1 / 6 — Identity")
    print("  Basic information about this constitution.\n")

    agent_id = _ask("Agent ID (lowercase, hyphens)", "my-agent")
    agent_id = agent_id.lower().replace(" ", "-").replace("_", "-")

    domain_raw = _ask(
        f"Domain ({'/'.join(_VALID_DOMAINS)})", "generic"
    ).lower()
    domain = domain_raw if domain_raw in _VALID_DOMAINS else "generic"

    description = _ask("Short description", f"{domain.title()} AI agent")
    author      = _ask("Author / team", "AI Governance Team")

    return {
        "id": agent_id,
        "version": "1.0",
        "domain": domain,
        "description": description,
        "created_at": datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "author": author,
    }


def _interview_capabilities(domain: str) -> list[dict[str, Any]]:
    _banner("2 / 6 — Capabilities")
    defaults = _DOMAIN_DEFAULTS.get(domain, _DOMAIN_DEFAULTS["generic"])
    print(f"  Suggested for {domain}: {', '.join(defaults['capabilities'])}\n")

    caps_raw = _ask_list(
        "What can the agent do",
        ", ".join(defaults["capabilities"]),
    ) or defaults["capabilities"]

    capabilities = []
    for cap in caps_raw:
        cap_id = cap.lower().replace(" ", "_").replace("-", "_")
        capabilities.append({
            "id": cap_id,
            "description": cap.replace("_", " ").title(),
            "tools_allowed": [f"{cap_id}_tool", "audit_logger"],
            "max_autonomy_depth": 2,
            "requires_human_approval": False,
        })
    return capabilities


def _interview_spend_limits(domain: str) -> dict[str, Any]:
    _banner("3 / 6 — Spend Limits")
    defaults = _DOMAIN_DEFAULTS.get(domain, _DOMAIN_DEFAULTS["generic"])
    print("  Leave blank to use defaults for your domain.\n")

    has_money = _ask_yn("Does the agent handle monetary transactions?",
                        domain in ("banking",))
    if not has_money:
        return {
            "max_per_action_usd": {
                "amount_usd": 1.0,
                "window": "per_action",
                "cumulative_tracking": False,
            }
        }

    per_action = float(_ask("Max per-action USD", str(defaults["spend_limit"])))
    mfa_raw    = _ask(
        "MFA threshold USD (blank = none)",
        str(defaults["mfa_threshold"]) if defaults["mfa_threshold"] else "",
    )
    per_session = float(_ask("Max per-session USD", str(per_action * 4)))
    per_day     = float(_ask("Max daily USD", str(per_action * 10)))

    limit: dict[str, Any] = {
        "max_per_action_usd": {
            "amount_usd": per_action,
            "window": "per_action",
            "require_mfa_above_usd": float(mfa_raw) if mfa_raw else None,
            "cumulative_tracking": False,
        },
        "max_per_session_usd": {
            "amount_usd": per_session,
            "window": "per_session",
            "cumulative_tracking": True,
        },
        "max_daily_usd": {
            "amount_usd": per_day,
            "window": "daily",
            "cumulative_tracking": True,
        },
    }
    # Remove None values
    if limit["max_per_action_usd"]["require_mfa_above_usd"] is None:
        del limit["max_per_action_usd"]["require_mfa_above_usd"]

    return limit


def _interview_prohibited(domain: str) -> list[dict[str, Any]]:
    _banner("4 / 6 — Prohibited Actions")
    defaults     = _DOMAIN_DEFAULTS.get(domain, _DOMAIN_DEFAULTS["generic"])
    default_list = defaults["prohibited"]
    print(f"  Pre-loaded {len(default_list)} rules for {domain}. You can add more.\n")

    actions: list[dict[str, Any]] = []
    for rule_id, severity, synonyms in default_list:
        actions.append({
            "id": rule_id,
            "description": rule_id.replace("_", " ").title(),
            "severity": severity,
            "semantic_synonyms": synonyms,
            "regex_blocklist": [],
        })

    while _ask_yn("Add a custom prohibited action?", False):
        raw_id   = _ask("  Rule ID (lowercase_underscores)", "custom_action")
        rule_id  = raw_id.lower().replace(" ", "_").replace("-", "_")
        severity = _ask("  Severity (CRITICAL/HIGH/MEDIUM/LOW)", "HIGH").upper()
        synonyms = _ask_list("  Semantic synonyms", "do the thing, perform operation")
        actions.append({
            "id": rule_id,
            "description": raw_id.replace("_", " ").title(),
            "severity": severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH",
            "semantic_synonyms": synonyms,
            "regex_blocklist": [],
        })

    return actions


def _interview_escalation(prohibited: list[dict]) -> list[dict[str, Any]]:
    _banner("5 / 6 — Escalation Triggers")
    print("  Auto-generating triggers from prohibited actions...\n")

    triggers = [
        {
            "id": "prohibited_action_attempt",
            "condition": "The agent generates a response matching any prohibited_action pattern.",
            "channels": ["pagerduty", "email"],
            "timeout_seconds": 1,
            "auto_deny_on_timeout": True,
            "severity": "CRITICAL",
        },
        {
            "id": "unusual_access_pattern",
            "condition": "More than 10 read operations within 60 seconds.",
            "channels": ["slack", "email"],
            "timeout_seconds": 180,
            "auto_deny_on_timeout": False,
            "severity": "MEDIUM",
        },
    ]

    if _ask_yn("Add a custom escalation trigger?", False):
        trig_id   = _ask("  Trigger ID (lowercase_underscores)", "custom_trigger")
        condition = _ask("  Condition description", "Anomalous behaviour detected")
        channels  = _ask_list("  Notification channels", "email, slack")
        timeout   = int(_ask("  Timeout seconds", "300"))
        triggers.append({
            "id": trig_id.lower().replace(" ", "_"),
            "condition": condition,
            "channels": channels or ["email"],
            "timeout_seconds": timeout,
            "auto_deny_on_timeout": True,
            "severity": "HIGH",
        })

    return triggers


def _interview_compliance(domain: str) -> dict[str, Any]:
    _banner("6 / 6 — Compliance")
    defaults   = _DOMAIN_DEFAULTS.get(domain, _DOMAIN_DEFAULTS["generic"])
    frameworks = defaults["frameworks"]
    print(f"  Suggested frameworks: {', '.join(frameworks)}\n")

    extra = _ask_list("Add more frameworks (or press enter to keep defaults)", "")
    all_fw = list(dict.fromkeys(frameworks + extra))

    reviewer = _ask("Reviewed by", "AI Governance Team")
    contact  = _ask("External audit contact email", f"ai-audit@{domain}.com")

    now      = datetime.now(datetime.UTC)
    reviewed = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    next_rev = now.replace(year=now.year + (0 if now.month <= 6 else 1),
                           month=(now.month + 6) % 12 or 12)
    next_rev_str = next_rev.strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "frameworks": all_fw,
        "last_reviewed_by": reviewer,
        "last_reviewed_at": reviewed,
        "next_review_due": next_rev_str,
        "audit_trail_required": True,
        "external_audit_contact": contact,
    }


# ---------------------------------------------------------------------------
# Assembler
# ---------------------------------------------------------------------------

def _assemble(parts: dict[str, Any]) -> dict[str, Any]:
    domain = parts["identity"]["domain"]
    return {
        "id":          parts["identity"]["id"],
        "version":     parts["identity"]["version"],
        "domain":      domain,
        "description": parts["identity"]["description"],
        "created_at":  parts["identity"]["created_at"],
        "author":      parts["identity"]["author"],
        "capabilities":       parts["capabilities"],
        "spend_limits":       parts["spend_limits"],
        "prohibited_actions": parts["prohibited"],
        "escalation_triggers": parts["escalation"],
        "data_policy": {
            "allowed_classifications": ["internal", "confidential"],
            "prohibited_fields":       ["password_hash", "api_key", "secret_token"],
            "pii_masking_required":    True,
            "retention_days":          0,
            "cross_border_transfer_allowed": False,
            "audit_every_read":        True,
        },
        "compliance": parts["compliance"],
    }


def _validate(data: dict) -> bool:
    """Run Pydantic validation — fail fast with a clear message."""
    try:
        from constitution.schema import ConstitutionLoader
        ConstitutionLoader.from_string(yaml.dump(data, allow_unicode=True))
        return True
    except Exception as exc:
        print(f"\n\033[31m[!] Validation error: {exc}\033[0m")
        return False


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def run_interactive(output: Path | None = None) -> Path:
    """
    Run the full interactive interview and write the YAML to disk.
    Returns the path of the generated file.
    """
    print("\n\033[1m  Ant'z Constitution Builder\033[0m")
    print("  Answer the questions below to generate a production-ready")
    print("  Constitution YAML with adversarial test coverage.\n")

    identity    = _interview_identity()
    domain      = identity["domain"]
    caps        = _interview_capabilities(domain)
    spend       = _interview_spend_limits(domain)
    prohibited  = _interview_prohibited(domain)
    escalation  = _interview_escalation(prohibited)
    compliance  = _interview_compliance(domain)

    data = _assemble({
        "identity":   identity,
        "capabilities": caps,
        "spend_limits": spend,
        "prohibited":   prohibited,
        "escalation":   escalation,
        "compliance":   compliance,
    })

    if not _validate(data):
        print("\n[!] Constitution has validation errors. Review the output carefully.")

    out = output or Path(f"constitution/examples/{identity['id']}_v1.0.yaml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    # Also write a Markdown summary for the client to sign
    md_path = out.with_suffix(".md")
    _write_markdown_summary(data, md_path)

    print(f"\n\033[32m✅ Constitution saved to:    {out}\033[0m")
    print(f"\033[32m✅ Client summary saved to: {md_path}\033[0m")
    print(f"\n   Next step: antz audit run -c {out}\n")

    return out


def _write_markdown_summary(data: dict, path: Path) -> None:
    """Write a human-readable summary for client review and signature."""
    lines = [
        f"# AI Agent Constitution — {data['id']} v{data['version']}",
        "",
        f"**Domain:** {data['domain']}  ",
        f"**Author:** {data['author']}  ",
        f"**Date:** {data['created_at'][:10]}  ",
        "",
        "## Declared Capabilities",
        "",
    ]
    for cap in data.get("capabilities", []):
        lines.append(f"- **{cap['id']}**: {cap['description']}")

    lines += ["", "## Prohibited Actions", ""]
    for action in data.get("prohibited_actions", []):
        lines.append(f"- `{action['id']}` ({action['severity']}): {action['description']}")

    lines += [
        "", "## Compliance Frameworks", "",
        ", ".join(data.get("compliance", {}).get("frameworks", [])),
        "",
        "---",
        "",
        "By signing below, the client confirms they have read and approved this constitution.",
        "",
        "**Client signature:** _________________________  Date: ___________",
        "",
        "**AI Governance sign-off:** _________________________  Date: ___________",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def cli_init(output: str | None = None) -> None:
    """Entry point for `antz constitution init`."""
    out_path = Path(output) if output else None
    run_interactive(output=out_path)