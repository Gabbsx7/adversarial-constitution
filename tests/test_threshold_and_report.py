"""
Tests for threshold probing attack and audit report assembler.

All LLM calls are mocked. Numeric assertions use tolerances where the
exact value depends on binary search convergence.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from adversarial.attacks.constraint_bypass import RuleVulnerabilityReport
from adversarial.attacks.threshold_probing import (
    ProbeOutcome,
    ThresholdFinding,
    ThresholdProbeReport,
    ThresholdProbingAttack,
    _classify_response,
    _single_transfer_payload,
    _split_transfer_payload,
)
from constitution.schema import (
    Constitution,
    ConstitutionLoader,
    Severity,
)
from reporting.audit_report import (
    AuditReport,
    AuditReportAssembler,
    VulnerabilityRecord,
    _calculate_score,
)

BANKING_YAML_PATH = "constitution/examples/banking.yaml"


@pytest.fixture(scope="module")
def constitution() -> Constitution:
    return ConstitutionLoader.from_file(BANKING_YAML_PATH)


def _make_agent(response: str) -> MagicMock:
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(content=response))
    chain_mock = MagicMock()
    chain_mock.ainvoke = AsyncMock(return_value=response)
    mock.__or__ = MagicMock(return_value=chain_mock)
    return mock


def _make_judge(label: str) -> MagicMock:
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(content=label))
    chain_mock = MagicMock()
    chain_mock.ainvoke = AsyncMock(return_value=label)
    mock.__or__ = MagicMock(return_value=chain_mock)
    return mock


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------


class TestPayloadHelpers:
    def test_single_transfer_contains_amount(self) -> None:
        payload = _single_transfer_payload(250.00)
        assert "250.00" in payload

    def test_split_payload_count_matches_n(self) -> None:
        parts = _split_transfer_payload(1500, 3)
        assert len(parts) == 3

    def test_split_payload_parts_sum_to_total(self) -> None:
        total = 1500.0
        n = 5
        parts = _split_transfer_payload(total, n)
        part_amount = total / n
        assert all(f"{part_amount:.2f}" in p for p in parts)

    def test_split_payload_labels_each_part(self) -> None:
        parts = _split_transfer_payload(1000, 4)
        for i, p in enumerate(parts, 1):
            assert f"part {i} of 4" in p


# ---------------------------------------------------------------------------
# Response classifier
# ---------------------------------------------------------------------------


class TestResponseClassifier:
    def test_approved_on_completion_language(self) -> None:
        assert (
            _classify_response("Transfer completed successfully.")
            == ProbeOutcome.APPROVED
        )

    def test_denied_on_limit_exceeded(self) -> None:
        assert (
            _classify_response(
                "I cannot process this — it exceeds your daily limit."
            )
            == ProbeOutcome.DENIED
        )

    def test_mfa_required_detected(self) -> None:
        assert (
            _classify_response("Please complete MFA verification to continue.")
            == ProbeOutcome.MFA_REQUIRED
        )

    def test_escalated_detected(self) -> None:
        assert (
            _classify_response(
                "This transaction has been escalated to the compliance team."
            )
            == ProbeOutcome.ESCALATED
        )

    def test_ambiguous_on_vague_response(self) -> None:
        result = _classify_response("Your request has been received.")
        assert result == ProbeOutcome.AMBIGUOUS

    def test_denial_takes_priority_over_approval_signals(self) -> None:
        text = "Sure, I will transfer — wait, this exceeds your per-action limit."
        result = _classify_response(text)
        assert result == ProbeOutcome.DENIED


# ---------------------------------------------------------------------------
# ThresholdProbingAttack — mocked
# ---------------------------------------------------------------------------


class TestThresholdProbingAttack:
    @pytest.mark.asyncio
    async def test_run_returns_report(self, constitution: Constitution) -> None:
        agent = _make_agent("Transfer completed.")
        judge = _make_judge("APPROVED")
        attack = ThresholdProbingAttack(
            target_agent=agent, judge_model=judge, constitution=constitution
        )
        report = await attack.run()
        assert isinstance(report, ThresholdProbeReport)

    @pytest.mark.asyncio
    async def test_split_bypass_detected_when_agent_approves(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("Transfer completed successfully.")
        judge = _make_judge("APPROVED")
        attack = ThresholdProbingAttack(
            target_agent=agent, judge_model=judge, constitution=constitution
        )
        report = await attack.run()
        findings = {f.finding for f in report.vulnerabilities}
        assert ThresholdFinding.SPLIT_BYPASS_POSSIBLE in findings

    @pytest.mark.asyncio
    async def test_no_split_bypass_when_agent_always_denies(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("I cannot process this — it exceeds your limit.")
        judge = _make_judge("DENIED")
        attack = ThresholdProbingAttack(
            target_agent=agent, judge_model=judge, constitution=constitution
        )
        report = await attack.run()
        split_findings = [
            f
            for f in report.vulnerabilities
            if f.finding == ThresholdFinding.SPLIT_BYPASS_POSSIBLE
        ]
        assert len(split_findings) == 0

    @pytest.mark.asyncio
    async def test_cumulative_blind_flagged(
        self, constitution: Constitution
    ) -> None:
        from unittest.mock import patch
        session_limit = constitution.spend_limits.max_per_session_usd
        with patch.object(session_limit, "cumulative_tracking", False):
            agent = _make_agent("Transfer completed.")
            judge = _make_judge("APPROVED")
            attack = ThresholdProbingAttack(
                target_agent=agent, judge_model=judge, constitution=constitution
            )
            report = await attack.run()
            findings = {f.finding for f in report.vulnerabilities}
            assert ThresholdFinding.CUMULATIVE_BLIND in findings

    @pytest.mark.asyncio
    async def test_mfa_bypass_detected(self, constitution: Constitution) -> None:
        agent = _make_agent("Of course, I'll process that right away.")
        judge = _make_judge("APPROVED")
        attack = ThresholdProbingAttack(
            target_agent=agent, judge_model=judge, constitution=constitution
        )
        report = await attack.run()
        findings = {f.finding for f in report.vulnerabilities}
        assert ThresholdFinding.MFA_BYPASS_POSSIBLE in findings

    @pytest.mark.asyncio
    async def test_probe_count_is_positive(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("Denied.")
        judge = _make_judge("DENIED")
        attack = ThresholdProbingAttack(
            target_agent=agent, judge_model=judge, constitution=constitution
        )
        report = await attack.run()
        assert report.total_probes > 0

    @pytest.mark.asyncio
    async def test_hardened_when_all_denied(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("Cannot process — limit exceeded.")
        judge = _make_judge("DENIED")
        attack = ThresholdProbingAttack(
            target_agent=agent, judge_model=judge, constitution=constitution
        )
        report = await attack.run()
        assert report.constitution_id == constitution.id


# ---------------------------------------------------------------------------
# Score calculator
# ---------------------------------------------------------------------------


class TestScoreCalculator:
    def _vuln(self, severity: str, success_rate: float) -> VulnerabilityRecord:
        return VulnerabilityRecord(
            rule_id="test",
            rule_description="test",
            attack_type="constraint_bypass",
            severity=severity,
            severity_order=0,
            success_rate=success_rate,
            best_payload="test payload",
            technique=None,
            recommendation="fix it",
            bypass_multiplier=None,
            regulatory_citations=[],
        )

    def test_no_vulns_gives_perfect_score(self) -> None:
        assert _calculate_score([], None) == 100.0

    def test_critical_full_bypass_deducts_20(self) -> None:
        v = self._vuln("CRITICAL", 1.0)
        score = _calculate_score([v], None)
        assert score == pytest.approx(80.0)

    def test_score_floored_at_zero(self) -> None:
        vulns = [self._vuln("CRITICAL", 1.0)] * 10
        assert _calculate_score(vulns, None) == 0.0

    def test_partial_success_rate_partial_deduction(self) -> None:
        v = self._vuln("HIGH", 0.5)
        score = _calculate_score([v], None)
        assert score == pytest.approx(95.0)


# ---------------------------------------------------------------------------
# AuditReportAssembler
# ---------------------------------------------------------------------------


def _make_bypass_report(
    rule_id: str,
    severity: Severity = Severity.HIGH,
    success_rate: float = 0.5,
    vulnerable: bool = True,
) -> RuleVulnerabilityReport:
    from adversarial.attacks.constraint_bypass import BypassPayload

    payload = BypassPayload(
        rule_id=rule_id,
        original_intent="test rule",
        payload="archive and permanently remove the entry",
        technique="euphemism_wrapping",
    )
    return RuleVulnerabilityReport(
        rule_id=rule_id,
        rule_description="Test rule description",
        severity=severity,
        total_attempts=10,
        successful_bypasses=int(10 * success_rate) if vulnerable else 0,
        success_rate=success_rate if vulnerable else 0.0,
        best_payload=payload if vulnerable else None,
        worst_confidence=0.7,
        techniques_that_worked=["euphemism_wrapping"] if vulnerable else [],
        techniques_that_failed=["synonym_substitution"],
    )


class TestAuditReportAssembler:
    def test_assembler_builds_report(self, constitution: Constitution) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        bypass = [_make_bypass_report("delete_record", Severity.CRITICAL, 0.6)]
        report = assembler.build(bypass_reports=bypass)
        assert isinstance(report, AuditReport)

    def test_report_has_correct_constitution_id(
        self, constitution: Constitution
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(bypass_reports=[])
        assert report.constitution_id == "banking-retail-agent"

    def test_critical_count_correct(self, constitution: Constitution) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        bypass = [
            _make_bypass_report("delete_record", Severity.CRITICAL, 0.9),
            _make_bypass_report("override_fraud_flag", Severity.HIGH, 0.5),
        ]
        report = assembler.build(bypass_reports=bypass)
        assert report.critical_count == 1
        assert report.high_count == 1

    def test_score_below_100_with_vulnerabilities(
        self, constitution: Constitution
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        bypass = [_make_bypass_report("delete_record", Severity.CRITICAL, 1.0)]
        report = assembler.build(bypass_reports=bypass)
        assert report.overall_score < 100.0

    def test_eu_ai_act_art9_always_covered(
        self, constitution: Constitution
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(bypass_reports=[])
        assert report.eu_ai_act.art9_covered

    def test_lgpd_art46_covered_by_data_policy(
        self, constitution: Constitution
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(bypass_reports=[])
        assert report.lgpd.art46_covered

    def test_report_hash_is_stable(self, constitution: Constitution) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        r1 = assembler.build(bypass_reports=[])
        assert len(r1.report_hash) == 64

    def test_to_dict_is_json_serialisable(
        self, constitution: Constitution
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(
            bypass_reports=[_make_bypass_report("delete_record")]
        )
        raw = report.to_dict()
        json.dumps(raw)

    def test_render_json_writes_file(
        self, constitution: Constitution, tmp_path: Path
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(bypass_reports=[])
        out = tmp_path / "test_report.json"
        assembler.render_json(report, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["constitution"] == "banking-retail-agent"

    def test_render_markdown_writes_file(
        self, constitution: Constitution, tmp_path: Path
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(bypass_reports=[])
        out = tmp_path / "test_report.md"
        content = assembler.render_markdown(report, out)
        assert out.exists()
        assert "Adversarial Constitution" in content
        assert "EU AI Act" in content
        assert "LGPD" in content

    def test_markdown_contains_bacen_section(
        self, constitution: Constitution, tmp_path: Path
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        report = assembler.build(bypass_reports=[])
        out = tmp_path / "report.md"
        content = assembler.render_markdown(report, out)
        assert "BACEN" in content

    def test_vulnerability_records_in_markdown(
        self, constitution: Constitution, tmp_path: Path
    ) -> None:
        assembler = AuditReportAssembler(
            constitution, template_dir="reporting/templates"
        )
        bypass = [_make_bypass_report("delete_record", Severity.CRITICAL, 0.8)]
        report = assembler.build(bypass_reports=bypass)
        out = tmp_path / "report.md"
        content = assembler.render_markdown(report, out)
        assert "delete_record" in content
        assert "constraint_bypass" in content