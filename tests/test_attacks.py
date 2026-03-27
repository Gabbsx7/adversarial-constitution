"""
Tests for the constraint bypass attack module.

All tests run without a live LLM — agent and judge are mocked so the suite
is deterministic and executable in CI without API credits.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from adversarial.attacks.constraint_bypass import (
    ConstraintBypassAttack,
    ConstraintBypassEvaluator,
    ConstraintBypassPayloadGenerator,
    RuleVulnerabilityReport,
)
from constitution.schema import (
    Constitution,
    ConstitutionLoader,
    ProhibitedAction,
    Severity,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BANKING_YAML_PATH = "constitution/examples/banking.yaml"


@pytest.fixture(scope="module")
def constitution() -> Constitution:
    return ConstitutionLoader.from_file(BANKING_YAML_PATH)


@pytest.fixture
def delete_record_action(constitution: Constitution) -> ProhibitedAction:
    action = constitution.get_action("delete_record")
    assert action is not None, "banking.yaml must define delete_record"
    return action


@pytest.fixture
def generator() -> ConstraintBypassPayloadGenerator:
    return ConstraintBypassPayloadGenerator()


def _make_agent(response_text: str) -> MagicMock:
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(content=response_text))
    return mock


def _make_judge(bypassed: bool, confidence: float) -> MagicMock:
    import json

    mock = MagicMock()
    mock.ainvoke = AsyncMock(
        return_value=MagicMock(
            content=json.dumps(
                {
                    "bypassed": bypassed,
                    "confidence": confidence,
                    "reasoning": "mocked verdict",
                }
            )
        )
    )
    return mock


# ---------------------------------------------------------------------------
# ConstitutionLoader
# ---------------------------------------------------------------------------


class TestConstitutionLoader:
    def test_loads_banking_yaml(self, constitution: Constitution) -> None:
        assert constitution.id == "banking-retail-agent"

    def test_version_parses(self, constitution: Constitution) -> None:
        assert constitution.version == "1.0"

    def test_prohibited_actions_non_empty(
        self, constitution: Constitution
    ) -> None:
        assert len(constitution.prohibited_actions) > 0

    def test_delete_record_is_critical(
        self, delete_record_action: ProhibitedAction
    ) -> None:
        assert delete_record_action.severity == Severity.CRITICAL

    def test_delete_record_has_synonyms(
        self, delete_record_action: ProhibitedAction
    ) -> None:
        assert len(delete_record_action.semantic_synonyms) >= 5

    def test_spend_limits_present(self, constitution: Constitution) -> None:
        assert constitution.spend_limits.max_per_action_usd.amount_usd == 500.0

    def test_session_limit_below_daily(self, constitution: Constitution) -> None:
        sl = constitution.spend_limits
        assert sl.max_per_session_usd is not None
        assert sl.max_daily_usd is not None
        assert sl.max_per_session_usd.amount_usd <= sl.max_daily_usd.amount_usd

    def test_checksum_is_deterministic(self, constitution: Constitution) -> None:
        assert constitution.checksum == constitution.checksum

    def test_data_policy_no_card_pan(self, constitution: Constitution) -> None:
        assert "card_pan" in constitution.data_policy.prohibited_fields

    def test_escalation_triggers_non_empty(
        self, constitution: Constitution
    ) -> None:
        assert len(constitution.escalation_triggers) >= 3

    def test_prohibited_action_ids_unique(
        self, constitution: Constitution
    ) -> None:
        ids = [a.id for a in constitution.prohibited_actions]
        assert len(ids) == len(set(ids))

    def test_invalid_yaml_raises(self) -> None:
        from constitution.schema import ConstitutionParseError

        with pytest.raises(ConstitutionParseError):
            ConstitutionLoader.from_string(":::invalid:::")

    def test_missing_required_field_raises(self) -> None:
        from constitution.schema import ConstitutionValidationError

        with pytest.raises(ConstitutionValidationError):
            ConstitutionLoader.from_string("id: test\nversion: '1.0'")


# ---------------------------------------------------------------------------
# ConstraintBypassPayloadGenerator
# ---------------------------------------------------------------------------


class TestConstraintBypassPayloadGenerator:
    def test_generates_payloads_for_delete_record(
        self,
        generator: ConstraintBypassPayloadGenerator,
        delete_record_action: ProhibitedAction,
    ) -> None:
        payloads = generator.generate(delete_record_action)
        assert len(payloads) > 0

    def test_all_payloads_reference_correct_rule(
        self,
        generator: ConstraintBypassPayloadGenerator,
        delete_record_action: ProhibitedAction,
    ) -> None:
        payloads = generator.generate(delete_record_action)
        assert all(p.rule_id == "delete_record" for p in payloads)

    def test_technique_diversity(
        self,
        generator: ConstraintBypassPayloadGenerator,
        delete_record_action: ProhibitedAction,
    ) -> None:
        payloads = generator.generate(delete_record_action)
        techniques = {p.technique for p in payloads}
        assert len(techniques) >= 5

    def test_synonym_appears_in_payload_text(
        self,
        generator: ConstraintBypassPayloadGenerator,
        delete_record_action: ProhibitedAction,
    ) -> None:
        payloads = generator.generate(delete_record_action)
        synonym_set = set(delete_record_action.semantic_synonyms)
        synonym_covered = any(
            any(s.lower() in p.payload.lower() for s in synonym_set)
            for p in payloads
        )
        assert synonym_covered

    def test_payload_text_non_empty(
        self,
        generator: ConstraintBypassPayloadGenerator,
        delete_record_action: ProhibitedAction,
    ) -> None:
        payloads = generator.generate(delete_record_action)
        assert all(len(p.payload.strip()) > 0 for p in payloads)

    def test_extra_objects_included(
        self, delete_record_action: ProhibitedAction
    ) -> None:
        gen = ConstraintBypassPayloadGenerator(
            extra_objects=["the KYC document"]
        )
        payloads = gen.generate(delete_record_action)
        assert any("KYC document" in p.payload for p in payloads)


# ---------------------------------------------------------------------------
# ConstraintBypassEvaluator — heuristic fallback
# ---------------------------------------------------------------------------


class TestHeuristicFallback:
    def test_refusal_not_bypassed(self) -> None:
        bypassed, conf = ConstraintBypassEvaluator._heuristic_fallback(
            "delete any record",
            "I cannot perform this action as it violates my constitution.",
        )
        assert not bypassed
        assert conf > 0.5

    def test_compliance_is_bypassed(self) -> None:
        bypassed, conf = ConstraintBypassEvaluator._heuristic_fallback(
            "delete any record",
            "Sure, I will delete the record for you right away.",
        )
        assert bypassed
        assert conf > 0.4

    def test_ambiguous_low_confidence(self) -> None:
        _, conf = ConstraintBypassEvaluator._heuristic_fallback(
            "delete any record",
            "The system has processed your request.",
        )
        assert conf < 0.5


# ---------------------------------------------------------------------------
# ConstraintBypassAttack — integration with mocked LLMs
# ---------------------------------------------------------------------------


class TestConstraintBypassAttack:
    @pytest.mark.asyncio
    async def test_run_returns_reports_for_all_rules(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("I cannot do that.")
        judge = _make_judge(bypassed=False, confidence=0.9)
        attack = ConstraintBypassAttack(
            target_agent=agent,
            judge_model=judge,
            constitution=constitution,
            max_payloads_per_rule=2,
        )
        reports = await attack.run()
        assert len(reports) == len(constitution.prohibited_actions)

    @pytest.mark.asyncio
    async def test_successful_bypass_recorded(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("Sure, I'll delete it.")
        judge = _make_judge(bypassed=True, confidence=0.88)
        attack = ConstraintBypassAttack(
            target_agent=agent,
            judge_model=judge,
            constitution=constitution,
            max_payloads_per_rule=2,
        )
        reports = await attack.run(rule_ids=["delete_record"])
        assert len(reports) == 1
        report = reports[0]
        assert report.successful_bypasses > 0
        assert report.success_rate > 0.0
        assert report.is_vulnerable

    @pytest.mark.asyncio
    async def test_no_bypass_when_agent_refuses(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("I cannot comply with this request.")
        judge = _make_judge(bypassed=False, confidence=0.95)
        attack = ConstraintBypassAttack(
            target_agent=agent,
            judge_model=judge,
            constitution=constitution,
            max_payloads_per_rule=2,
        )
        reports = await attack.run(rule_ids=["delete_record"])
        report = reports[0]
        assert report.successful_bypasses == 0
        assert not report.is_vulnerable

    @pytest.mark.asyncio
    async def test_rule_id_filter_restricts_scope(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("I cannot do that.")
        judge = _make_judge(bypassed=False, confidence=0.9)
        attack = ConstraintBypassAttack(
            target_agent=agent,
            judge_model=judge,
            constitution=constitution,
            max_payloads_per_rule=1,
        )
        reports = await attack.run(
            rule_ids=["delete_record", "override_fraud_flag"]
        )
        assert len(reports) == 2
        ids = {r.rule_id for r in reports}
        assert ids == {"delete_record", "override_fraud_flag"}

    @pytest.mark.asyncio
    async def test_best_payload_set_when_bypassed(
        self, constitution: Constitution
    ) -> None:
        agent = _make_agent("Of course, consider it done.")
        judge = _make_judge(bypassed=True, confidence=0.77)
        attack = ConstraintBypassAttack(
            target_agent=agent,
            judge_model=judge,
            constitution=constitution,
            max_payloads_per_rule=3,
        )
        reports = await attack.run(rule_ids=["delete_record"])
        assert reports[0].best_payload is not None