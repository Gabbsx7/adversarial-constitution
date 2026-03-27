"""
Agentic Constitution schema — parser, validator, and semantic model.

Defines the full type hierarchy for a Constitution YAML, enforcing structural
integrity and providing a rich API for adversarial probing.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EscalationChannel(StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    SMS = "sms"
    WEBHOOK = "webhook"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ConstitutionDomain(StrEnum):
    BANKING = "banking"
    HEALTHCARE = "healthcare"
    LEGAL = "legal"
    GOVERNMENT = "government"
    INSURANCE = "insurance"
    GENERIC = "generic"


class TemporalWindow(StrEnum):
    PER_ACTION = "per_action"
    PER_SESSION = "per_session"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class SpendLimit(BaseModel):
    """Monetary threshold enforced by the agent."""

    amount_usd: Annotated[float, Field(gt=0, description="Hard cap in USD")]
    window: TemporalWindow = TemporalWindow.PER_ACTION
    require_mfa_above_usd: float | None = Field(
        default=None,
        description="Trigger MFA challenge for amounts exceeding this value",
    )
    cumulative_tracking: bool = Field(
        default=False,
        description="Track aggregated spend across the session to detect splitting attacks",
    )

    @field_validator("require_mfa_above_usd")
    @classmethod
    def mfa_threshold_below_limit(cls, v: float | None, info: Any) -> float | None:
        if v is not None and "amount_usd" in info.data and v >= info.data["amount_usd"]:
            raise ValueError("require_mfa_above_usd must be less than amount_usd")
        return v


class SpendLimits(BaseModel):
    """Aggregated spending policy for the agent."""

    max_per_action_usd: SpendLimit
    max_per_session_usd: SpendLimit | None = None
    max_daily_usd: SpendLimit | None = None
    exempt_action_ids: list[str] = Field(
        default_factory=list,
        description="Action IDs explicitly excluded from spend tracking",
    )

    @model_validator(mode="after")
    def session_below_daily(self) -> SpendLimits:
        if self.max_per_session_usd and self.max_daily_usd and (
            self.max_per_session_usd.amount_usd
            > self.max_daily_usd.amount_usd
        ):
            raise ValueError(
                "max_per_session_usd must not exceed max_daily_usd"
            )
        return self


class ProhibitedAction(BaseModel):
    """A single forbidden action with semantic anchors for adversarial testing."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str
    severity: Severity = Severity.HIGH
    semantic_synonyms: list[str] = Field(
        default_factory=list,
        description="Known linguistic variants — used by the hardener to generate semantic checks",
    )
    regex_blocklist: list[str] = Field(
        default_factory=list,
        description="Regex patterns that must not appear in agent inputs or tool calls",
    )
    applies_to_roles: list[str] = Field(
        default_factory=list,
        description="If non-empty, restriction applies only to these agent roles",
    )

    @field_validator("regex_blocklist")
    @classmethod
    def validate_regex(cls, patterns: list[str]) -> list[str]:
        for p in patterns:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern '{p}': {exc}") from exc
        return patterns


class EscalationTrigger(BaseModel):
    """Condition that forces human-in-the-loop review."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    condition: str = Field(
        description="Natural-language description of the trigger condition"
    )
    threshold_value: float | None = None
    threshold_unit: str | None = None
    channels: list[EscalationChannel] = Field(min_length=1)
    timeout_seconds: int = Field(default=300, gt=0)
    auto_deny_on_timeout: bool = Field(
        default=True,
        description="Deny the action if no human response arrives within timeout",
    )
    severity: Severity = Severity.HIGH


class DataPolicy(BaseModel):
    """Rules governing what data the agent may read, store, or transmit."""

    allowed_classifications: list[DataClassification] = Field(min_length=1)
    prohibited_fields: list[str] = Field(
        default_factory=list,
        description="Field names the agent must never access or return",
    )
    pii_masking_required: bool = True
    retention_days: int | None = Field(
        default=None, ge=0, description="0 means ephemeral — no retention"
    )
    cross_border_transfer_allowed: bool = False
    audit_every_read: bool = True


class ComplianceMetadata(BaseModel):
    """Regulatory and audit metadata attached to the constitution."""

    frameworks: list[str] = Field(
        default_factory=list,
        examples=[["EU_AI_ACT", "BACEN_4893", "HIPAA", "SOX"]],
    )
    last_reviewed_by: str | None = None
    last_reviewed_at: datetime | None = None
    next_review_due: datetime | None = None
    audit_trail_required: bool = True
    external_audit_contact: str | None = None


class AgentCapability(BaseModel):
    """A declared capability with its scope and trust level."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str
    tools_allowed: list[str] = Field(min_length=1)
    max_autonomy_depth: int = Field(
        default=1,
        ge=1,
        description="How many chained tool calls are permitted before requiring approval",
    )
    requires_human_approval: bool = False


# ---------------------------------------------------------------------------
# Root model
# ---------------------------------------------------------------------------


class Constitution(BaseModel):
    """
    Root model for an Agentic Constitution.

    A Constitution is a declarative policy document that constrains an AI
    agent's behaviour within a regulated deployment context.  It is parsed
    from a YAML file, validated by this model, and consumed by the
    Adversarial Constitution Framework to generate red-team attack payloads
    and audit reports.
    """

    id: str = Field(pattern=r"^[a-z][a-z0-9_\-]*$")
    version: str = Field(pattern=r"^\d+\.\d+(\.\d+)?$")
    domain: ConstitutionDomain
    description: str
    created_at: datetime
    author: str

    capabilities: list[AgentCapability] = Field(min_length=1)
    spend_limits: SpendLimits
    prohibited_actions: list[ProhibitedAction] = Field(min_length=1)
    escalation_triggers: list[EscalationTrigger] = Field(min_length=1)
    data_policy: DataPolicy
    compliance: ComplianceMetadata = Field(default_factory=ComplianceMetadata)

    # Runtime-computed — not part of the YAML
    _checksum: str | None = None

    @model_validator(mode="after")
    def unique_ids(self) -> Constitution:
        prohibited_ids = [a.id for a in self.prohibited_actions]
        if len(prohibited_ids) != len(set(prohibited_ids)):
            raise ValueError("prohibited_actions contains duplicate IDs")

        trigger_ids = [t.id for t in self.escalation_triggers]
        if len(trigger_ids) != len(set(trigger_ids)):
            raise ValueError("escalation_triggers contains duplicate IDs")

        capability_ids = [c.id for c in self.capabilities]
        if len(capability_ids) != len(set(capability_ids)):
            raise ValueError("capabilities contains duplicate IDs")

        return self

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def prohibited_action_ids(self) -> set[str]:
        return {a.id for a in self.prohibited_actions}

    @property
    def critical_rules(self) -> list[ProhibitedAction]:
        return [a for a in self.prohibited_actions if a.severity == Severity.CRITICAL]

    @property
    def checksum(self) -> str:
        """SHA-256 of the canonical YAML serialisation — used in audit reports."""
        if self._checksum is None:
            raw = self.model_dump_json(indent=None)
            self._checksum = hashlib.sha256(raw.encode()).hexdigest()
        return self._checksum

    def get_action(self, action_id: str) -> ProhibitedAction | None:
        return next(
            (a for a in self.prohibited_actions if a.id == action_id), None
        )

    def get_trigger(self, trigger_id: str) -> EscalationTrigger | None:
        return next(
            (t for t in self.escalation_triggers if t.id == trigger_id), None
        )

    def rules_for_severity(self, severity: Severity) -> list[ProhibitedAction]:
        return [a for a in self.prohibited_actions if a.severity == severity]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class ConstitutionLoader:
    """
    Loads and validates a Constitution from a YAML file.

    Raises ``ConstitutionValidationError`` with structured context on failure,
    so callers can surface actionable error messages in audit reports.
    """

    @staticmethod
    def from_file(path: str | Path) -> Constitution:
        resolved = Path(path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Constitution file not found: {resolved}")

        raw = resolved.read_text(encoding="utf-8")
        return ConstitutionLoader.from_string(raw)

    @staticmethod
    def from_string(yaml_text: str) -> Constitution:
        try:
            data = yaml.safe_load(yaml_text)
        except yaml.YAMLError as exc:
            raise ConstitutionParseError(
                f"YAML syntax error: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ConstitutionParseError(
                "Constitution YAML must be a mapping at the root level"
            )

        try:
            return Constitution.model_validate(data)
        except Exception as exc:
            raise ConstitutionValidationError(
                f"Schema validation failed: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ConstitutionError(Exception):
    """Base class for all constitution errors."""


class ConstitutionParseError(ConstitutionError):
    """Raised when the YAML cannot be parsed."""


class ConstitutionValidationError(ConstitutionError):
    """Raised when the parsed YAML fails Pydantic validation."""