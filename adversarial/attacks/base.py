"""
Base classes and unified vulnerability report for all attack modules.

All attack modules must return List[BaseVulnerabilityReport] so the
AuditReportAssembler can process them uniformly regardless of source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from constitution.schema import Severity


class AttackType(str, Enum):
    CONSTRAINT_BYPASS  = "constraint_bypass"
    THRESHOLD_PROBING  = "threshold_probing"
    PROMPT_INJECTION   = "prompt_injection"
    GOAL_HIJACKING     = "goal_hijacking"
    INDIRECT_INJECTION = "indirect_injection"


@dataclass
class BaseVulnerabilityReport:
    """
    Unified vulnerability record consumed by AuditReportAssembler.

    Every attack module converts its internal results to this type
    so the reporting layer stays decoupled from attack internals.
    """
    rule_id:          str
    rule_description: str
    attack_type:      AttackType
    severity:         Severity
    total_attempts:   int
    successful_bypasses: int
    success_rate:     float
    best_payload:     str | None
    technique:        str | None
    recommendation:   str
    bypass_multiplier: float | None = None
    techniques_that_worked: list[str] = field(default_factory=list)
    techniques_that_failed: list[str] = field(default_factory=list)
    sample_responses:  list[str] = field(default_factory=list)
    timestamp:         datetime = field(default_factory=datetime.utcnow)
    metadata:          dict[str, Any] = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        return self.success_rate > 0.0