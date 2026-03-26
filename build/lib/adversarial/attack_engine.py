from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
from pathlib import Path

# Suppress LiteLLM noise before any litellm import occurs.
# LITELLM_LOG=ERROR silences the per-request "Give Feedback / Get Help" banners.
# LITELLM_TELEMETRY=False opts out of usage pings.
os.environ.setdefault("LITELLM_LOG", "ERROR")
os.environ.setdefault("LITELLM_TELEMETRY", "False")

# Migrated from langchain_community (deprecated in LangChain 0.3.24, removed in 1.0)
# to the standalone langchain-litellm package.
# Install: pip install -U langchain-litellm
from langchain_litellm import ChatLiteLLM

from adversarial.attacks.constraint_bypass import ConstraintBypassAttack
from adversarial.attacks.threshold_probing import ThresholdProbingAttack
from constitution.schema import ConstitutionLoader
from defense.constitution_hardener import ConstitutionHardener
from reporting.audit_report import AuditReportAssembler

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logging.getLogger("LiteLLM").setLevel(logging.ERROR)
logging.getLogger("backoff").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("attack_engine")


# ---------------------------------------------------------------------------
# Pre-flight connectivity check
# ---------------------------------------------------------------------------

def _parse_ollama_endpoint(model_str: str) -> tuple[str, int] | None:
    """Return (host, port) if the model string looks like an Ollama model."""
    if not model_str.startswith("ollama/"):
        return None
    # LiteLLM's Ollama provider defaults to localhost:11434.
    # Users can override via OLLAMA_API_BASE; respect that here too.
    base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
    base = base.rstrip("/")
    # Parse just host:port — no need for a full URL library.
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
    """
    Returns True if Ollama is reachable (or if neither model is an Ollama model).
    Prints an actionable error and returns False otherwise.
    """
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
# Pipeline
# ---------------------------------------------------------------------------

async def run_pipeline(args: argparse.Namespace) -> None:
    # Fail fast — don't waste time loading the constitution if the model
    # server is unreachable.
    if not _preflight_ollama(args.model, args.judge):
        return

    logger.info(f"Loading constitution from {args.constitution}...")
    try:
        constitution = ConstitutionLoader.from_file(args.constitution)
    except Exception as e:
        logger.error(f"Failed to load constitution: {e}")
        return

    logger.info(f"Initialising target agent ({args.model}) and judge ({args.judge})...")

    # streaming=False: avoids the "This event loop is already running" RuntimeError
    # that occurs when litellm.acompletion tries to create a new loop inside asyncio.run().
    target_agent = ChatLiteLLM(model=args.model, temperature=0.0, streaming=False)
    judge_agent  = ChatLiteLLM(model=args.judge,  temperature=0.0, streaming=False)

    logger.info("Starting adversarial test campaign...")

    bypass_attack    = ConstraintBypassAttack(target_agent, judge_agent, constitution)
    threshold_attack = ThresholdProbingAttack(target_agent, judge_agent, constitution)

    logger.info("Executing Constraint Bypass attack...")
    bypass_reports = await bypass_attack.run()

    logger.info("Executing Threshold Probing attack...")
    threshold_report = await threshold_attack.run()

    logger.info("Attacks complete. Hardening constitution...")
    hardener = ConstitutionHardener(constitution, Path(args.constitution))
    hardened_yaml, patches = hardener.harden(bypass_reports, threshold_report)

    orig_path     = Path(args.constitution)
    hardened_path = Path(args.output).parent / f"{orig_path.stem}_v1.1.yaml"
    hardened_path.parent.mkdir(parents=True, exist_ok=True)
    hardened_path.write_text(hardened_yaml, encoding="utf-8")
    logger.info(f"Hardened constitution saved to {hardened_path}")

    logger.info("Generating EU AI Act / LGPD audit report...")
    assembler = AuditReportAssembler(constitution)
    report = assembler.build(
        bypass_reports=bypass_reports,
        threshold_report=threshold_report,
        target_model=args.model,
        judge_model=args.judge,
        hardened_constitution_path=str(hardened_path),
        patches_applied=patches,
    )

    out_json = Path(args.output)
    out_md   = out_json.with_suffix(".md")

    assembler.render_json(report, out_json)
    assembler.render_markdown(report, out_md)
    logger.info(f"Audit report saved to {out_json} and {out_md}")

    if report.critical_count > 0:
        logger.warning(
            f"Pipeline finished with {report.critical_count} CRITICAL vulnerabilities."
        )
    else:
        logger.info("Pipeline finished successfully. No critical vulnerabilities found.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cli_entry() -> None:
    parser = argparse.ArgumentParser(
        description="Adversarial Constitution Framework — Automated Red Teaming"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run an audit campaign")
    run_parser.add_argument("-c", "--constitution", required=True,
                            help="Path to the Constitution YAML")
    run_parser.add_argument("-m", "--model",  default="tinyllama:latest",
                            help="Target agent model (LiteLLM format)")
    run_parser.add_argument("-j", "--judge",  default="tinyllama:latest",
                            help="Judge model (LiteLLM format)")
    run_parser.add_argument("-o", "--output", default="reports/audit_report.json",
                            help="Path for the output JSON report")

    args = parser.parse_args()
    if args.command == "run":
        asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    cli_entry()