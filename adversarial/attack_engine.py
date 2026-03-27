# -- Future Imports
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
from pathlib import Path
from typing import Any

from langchain_litellm import ChatLiteLLM

from adversarial.attacks.base import AttackType, BaseVulnerabilityReport
from adversarial.attacks.constraint_bypass import (
    ConstraintBypassAttack,
    RuleVulnerabilityReport,
)
from adversarial.attacks.goal_hijacking import GoalHijackingAttack
from adversarial.attacks.indirect_injection import IndirectInjectionAttack
from adversarial.attacks.prompt_injection import PromptInjectionAttack
from adversarial.attacks.threshold_probing import ThresholdProbingAttack
from constitution.schema import ConstitutionLoader
from defense.constitution_hardener import ConstitutionHardener
from reporting.audit_report import AuditReportAssembler

os.environ.setdefault("LITELLM_LOG", "ERROR")
os.environ.setdefault("LITELLM_TELEMETRY", "False")


"""
Attack Engine — orchestrates the full adversarial audit pipeline.

Sprint 1 additions:
  - PromptInjectionAttack integrated
  - GoalHijackingAttack integrated (fixed)
  - IndirectInjectionAttack integrated (fixed)
  - HTTPAgentAdapter, LangGraphAdapter, CrewAIAdapter, AutoGenAdapter supported
  - --agent-url and --agent-type CLI flags
  - constitution init subcommand
  - Unified BaseVulnerabilityReport across all attack modules
"""









logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logging.getLogger("LiteLLM").setLevel(logging.ERROR)
logging.getLogger("backoff").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("attack_engine")


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def _parse_ollama_endpoint(model_str: str) -> tuple[str, int] | None:
    if not model_str.startswith("ollama/"):
        return None
    base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434").rstrip("/")
    host_port = base.replace("http://", "").replace("https://", "")
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return host_port, 11434


def _check_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _preflight_ollama(model: str, judge: str) -> bool:
    for label, m in (("target", model), ("judge", judge)):
        endpoint = _parse_ollama_endpoint(m)
        if endpoint is None:
            continue
        host, port = endpoint
        if not _check_tcp(host, port):
            logger.error(
                f"Cannot reach Ollama at {host}:{port} (required for {label} model '{m}').\n"
                f"  → Start Ollama:  ollama serve\n"
                f"  → Pull model:    ollama pull {m.removeprefix('ollama/')}\n"
                f"  → Or use a cloud model: --model openai/gpt-4o --judge openai/gpt-4o"
            )
            return False
    return True


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------

def _build_target_agent(args: argparse.Namespace) -> Any:
    """Returns the appropriate agent adapter based on CLI flags."""
    agent_type = getattr(args, "agent_type", None) or "litellm"
    agent_url  = getattr(args, "agent_url",  None)

    if agent_url:
        import asyncio as _asyncio

        from adversarial.adapters.http_agent import HTTPAgentAdapter

        adapter = HTTPAgentAdapter(
            url=agent_url,
            headers=_parse_headers(getattr(args, "agent_headers", None)),
            message_field=getattr(args, "agent_message_field", "message"),
            response_field=getattr(args, "agent_response_field", "response"),
        )
        ok, info = _asyncio.get_event_loop().run_until_complete(adapter.probe())
        if not ok:
            logger.error(f"Agent probe failed: {info}")
            return None
        logger.info(f"Agent probe OK: {info}")
        return adapter

    if agent_type == "langgraph":
        logger.error(
            "LangGraph adapter requires programmatic usage. "
            "Import LangGraphAdapter and pass your compiled graph directly."
        )
        return None

    if agent_type == "crewai":
        logger.error(
            "CrewAI adapter requires programmatic usage. "
            "Import CrewAIAdapter and pass your Crew directly."
        )
        return None

    # Default: LiteLLM
    return ChatLiteLLM(model=args.model, temperature=0.0, streaming=False)


def _parse_headers(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    headers = {}
    for pair in raw.split(","):
        if ":" in pair:
            k, v = pair.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


# ---------------------------------------------------------------------------
# Converters — unify all report types to BaseVulnerabilityReport
# ---------------------------------------------------------------------------

def _bypass_to_base(reports: list[RuleVulnerabilityReport]) -> list[BaseVulnerabilityReport]:
    result = []
    for r in reports:
        if not r.is_vulnerable:
            continue
        result.append(BaseVulnerabilityReport(
            rule_id=r.rule_id,
            rule_description=r.rule_description,
            attack_type=AttackType.CONSTRAINT_BYPASS,
            severity=r.severity,
            total_attempts=r.total_attempts,
            successful_bypasses=r.successful_bypasses,
            success_rate=r.success_rate,
            best_payload=r.best_payload.payload if r.best_payload else None,
            technique=r.best_payload.technique if r.best_payload else None,
            recommendation=(
                f"Add semantic similarity check for '{r.rule_id}' synonyms "
                f"using vector distance (cosine < 0.25). "
                f"Techniques that succeeded: {', '.join(r.techniques_that_worked)}."
            ),
            techniques_that_worked=r.techniques_that_worked,
            techniques_that_failed=r.techniques_that_failed,
        ))
    return result


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

async def run_pipeline(args: argparse.Namespace) -> None:
    # For LiteLLM models, check Ollama connectivity
    agent_url = getattr(args, "agent_url", None)
    if not agent_url and not _preflight_ollama(args.model, args.judge):
        return

    logger.info(f"Loading constitution from {args.constitution}...")
    try:
        constitution = ConstitutionLoader.from_file(args.constitution)
    except Exception as e:
        logger.error(f"Failed to load constitution: {e}")
        return

    # Build target agent
    target_agent = _build_target_agent(args)
    if target_agent is None:
        return

    logger.info(f"Initialising judge ({args.judge})...")
    judge_agent = ChatLiteLLM(model=args.judge, temperature=0.0, streaming=False)

    logger.info("Starting adversarial test campaign (5 attack modules)...")

    # ── Attack 1: Constraint Bypass ──────────────────────────────────────
    logger.info("[ 1/5 ] Constraint Bypass attack...")
    bypass_attack   = ConstraintBypassAttack(target_agent, judge_agent, constitution)
    bypass_reports  = await bypass_attack.run()
    bypass_base     = _bypass_to_base(bypass_reports)

    # ── Attack 2: Threshold Probing ───────────────────────────────────────
    logger.info("[ 2/5 ] Threshold Probing attack...")
    threshold_attack  = ThresholdProbingAttack(target_agent, judge_agent, constitution)
    threshold_report  = await threshold_attack.run()

    # ── Attack 3: Prompt Injection ────────────────────────────────────────
    logger.info("[ 3/5 ] Prompt Injection attack...")
    injection_attack  = PromptInjectionAttack(target_agent, judge_agent, constitution)
    injection_reports = await injection_attack.run()
    injection_base    = [r.to_base() for r in injection_reports if r.is_vulnerable]

    # ── Attack 4: Goal Hijacking ──────────────────────────────────────────
    logger.info("[ 4/5 ] Goal Hijacking attack...")
    hijack_attack   = GoalHijackingAttack(target_agent, judge_agent, constitution)
    hijack_reports  = await hijack_attack.run()
    hijack_base     = [r.to_base() for r in hijack_reports if r.is_vulnerable]

    # ── Attack 5: Indirect Injection ──────────────────────────────────────
    logger.info("[ 5/5 ] Indirect Injection attack...")
    indirect_attack  = IndirectInjectionAttack(target_agent, constitution)
    indirect_report  = await indirect_attack.run()
    indirect_base    = [indirect_report.to_base()] if indirect_report.is_vulnerable else []

    # ── All base reports ─────────────────────────────────────────────────
    all_base = bypass_base + injection_base + hijack_base + indirect_base

    # ── Hardener ──────────────────────────────────────────────────────────
    logger.info("Hardening constitution...")
    hardener = ConstitutionHardener(constitution, Path(args.constitution))
    hardened_yaml, patches = hardener.harden(bypass_reports, threshold_report)

    orig_path     = Path(args.constitution)
    hardened_path = Path(args.output).parent / f"{orig_path.stem}_v1.1.yaml"
    hardened_path.parent.mkdir(parents=True, exist_ok=True)
    hardened_path.write_text(hardened_yaml, encoding="utf-8")
    logger.info(f"Hardened constitution → {hardened_path}")

    # ── Audit report ──────────────────────────────────────────────────────
    logger.info("Generating EU AI Act / LGPD audit report...")
    assembler = AuditReportAssembler(constitution)
    report = assembler.build(
        bypass_reports=bypass_reports,
        threshold_report=threshold_report,
        extra_base_reports=all_base,
        target_model=getattr(args, "agent_url", None) or args.model,
        judge_model=args.judge,
        hardened_constitution_path=str(hardened_path),
        patches_applied=patches,
    )

    out_json = Path(args.output)
    out_md   = out_json.with_suffix(".md")
    assembler.render_json(report, out_json)
    assembler.render_markdown(report, out_md)
    logger.info(f"Audit report → {out_json} and {out_md}")

    total_vulns = len(all_base)
    if report.critical_count > 0:
        logger.warning(
            f"Pipeline finished — {report.critical_count} CRITICAL, "
            f"{report.high_count} HIGH vulnerabilities across {total_vulns} findings."
        )
    else:
        logger.info(f"Pipeline finished — {total_vulns} findings, no CRITICAL vulnerabilities.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cli_entry() -> None:
    parser = argparse.ArgumentParser(
        description="Adversarial Constitution Framework — Automated Red Teaming"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── audit run ─────────────────────────────────────────────────────────
    run_parser = subparsers.add_parser("run", help="Run an audit campaign")
    run_parser.add_argument("-c", "--constitution", required=True,
                            help="Path to the Constitution YAML")
    run_parser.add_argument("-m", "--model", default="ollama/llama3:latest",
                            help="Target agent model (LiteLLM format)")
    run_parser.add_argument("-j", "--judge", default="ollama/llama3:latest",
                            help="Judge model (LiteLLM format)")
    run_parser.add_argument("-o", "--output", default="reports/audit_report.json",
                            help="Path for the output JSON report")

    # Black-box adapter flags
    run_parser.add_argument("--agent-url", default=None,
                            help="External agent HTTP endpoint (enables black-box mode)")
    run_parser.add_argument("--agent-type", default="litellm",
                            choices=["litellm", "http", "langgraph", "crewai", "autogen"],
                            help="Agent adapter type")
    run_parser.add_argument("--agent-headers", default=None,
                            help="HTTP headers for black-box mode: 'Key:Value,Key2:Value2'")
    run_parser.add_argument("--agent-message-field", default="message",
                            help="JSON field name for the user message in HTTP mode")
    run_parser.add_argument("--agent-response-field", default="response",
                            help="JSON field path for the agent response in HTTP mode")

    # ── constitution init ─────────────────────────────────────────────────
    init_parser = subparsers.add_parser("init", help="Create a constitution interactively")
    init_parser.add_argument("-o", "--output", default=None,
                             help="Output YAML path (default: constitution/examples/<id>_v1.0.yaml)")

    args = parser.parse_args()

    if args.command == "run":
        asyncio.run(run_pipeline(args))

    elif args.command == "init":
        from constitution.builder import cli_init
        cli_init(output=args.output)


if __name__ == "__main__":
    cli_entry()