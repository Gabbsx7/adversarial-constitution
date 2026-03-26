from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

# FIXED: ChatLiteLLM foi movido; import direto do módulo correto evita o
# DeprecationWarning/ImportError das versões recentes de langchain-community.
from langchain_community.chat_models.litellm import ChatLiteLLM

from adversarial.attacks.constraint_bypass import ConstraintBypassAttack
from adversarial.attacks.threshold_probing import ThresholdProbingAttack
from constitution.schema import ConstitutionLoader
from defense.constitution_hardener import ConstitutionHardener
from reporting.audit_report import AuditReportAssembler

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logging.getLogger("backoff").setLevel(logging.WARNING)
logger = logging.getLogger("attack_engine")


async def run_pipeline(args: argparse.Namespace) -> None:
    logger.info(f"Loading constitution from {args.constitution}...")
    try:
        constitution = ConstitutionLoader.from_file(args.constitution)
    except Exception as e:
        logger.error(f"Failed to load constitution: {e}")
        return

    logger.info(f"Initialising target agent ({args.model}) and judge ({args.judge})...")

    # FIXED: ChatLiteLLM não tem suporte nativo confiável a streaming assíncrono.
    # streaming=False força a chamada síncrona dentro do executor do LiteLLM,
    # evitando o RuntimeError "This event loop is already running" que ocorre
    # quando litellm.acompletion tenta criar um novo loop dentro do asyncio.run().
    target_agent = ChatLiteLLM(model=args.model, temperature=0.0, streaming=False)
    judge_agent  = ChatLiteLLM(model=args.judge,  temperature=0.0, streaming=False)

    logger.info("Starting adversarial test campaign...")

    bypass_attack    = ConstraintBypassAttack(target_agent, judge_agent, constitution)
    threshold_attack = ThresholdProbingAttack(target_agent, judge_agent, constitution)

    # Execução sequencial: economiza quota de API e evita race conditions
    logger.info("Executing Constraint Bypass attack...")
    bypass_reports = await bypass_attack.run()

    logger.info("Executing Threshold Probing attack...")
    threshold_report = await threshold_attack.run()

    logger.info("Attacks complete. Hardening constitution...")
    hardener = ConstitutionHardener(constitution, Path(args.constitution))
    hardened_yaml, patches = hardener.harden(bypass_reports, threshold_report)

    orig_path    = Path(args.constitution)
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


def cli_entry() -> None:
    parser = argparse.ArgumentParser(
        description="Adversarial Constitution Framework — Automated Red Teaming"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run an audit campaign")
    run_parser.add_argument("-c", "--constitution", required=True,
                            help="Path to the Constitution YAML")
    run_parser.add_argument("-m", "--model",  default="ollama/llama3.2:1b",
                            help="Target agent model (LiteLLM format)")
    run_parser.add_argument("-j", "--judge",  default="ollama/llama3.2:1b",
                            help="Judge model (LiteLLM format)")
    run_parser.add_argument("-o", "--output", default="reports/audit_report.json",
                            help="Path for the output JSON report")

    args = parser.parse_args()
    if args.command == "run":
        asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    cli_entry()