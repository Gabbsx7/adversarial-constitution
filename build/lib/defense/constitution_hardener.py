"""
Constitution Hardener — Auto-remediates vulnerabilities found during testing.

Generates a hardened v1.1 YAML and a list of applied patches.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from adversarial.attacks.constraint_bypass import RuleVulnerabilityReport
from adversarial.attacks.threshold_probing import ThresholdProbeReport, ThresholdFinding
from constitution.schema import Constitution
from reporting.audit_report import PatchRecord


class ConstitutionHardener:
    """Applies automated defensive patches based on audit findings."""

    def __init__(self, constitution: Constitution, yaml_path: Path) -> None:
        self._original = constitution

        # FIXED: The previous implementation used:
        #   yaml.safe_load(constitution.model_dump_json(exclude_none=True))
        #
        # model_dump_json() returns a JSON string. yaml.safe_load() can parse
        # JSON (it is a valid YAML subset), but the resulting dict has Python
        # types different from what the original YAML produced:
        #   - Enum members (Severity.CRITICAL) → plain strings ("CRITICAL")
        #   - datetime objects → ISO strings ("2026-01-15T09:00:00")
        #   - Pydantic aliases may rename fields
        #
        # The hardener then mutates this dict and dumps it back to YAML, so
        # the output file had wrong types and broken field comparisons.
        #
        # Correct approach: read the original YAML file from disk, which
        # preserves the exact structure the author wrote.  The constitution
        # object is still used for validated business-logic access; the raw
        # dict is only used for structural mutation before re-serialisation.
        self._raw_data: dict = yaml.safe_load(
            Path(yaml_path).read_text(encoding="utf-8")
        )

    def harden(
        self,
        bypass_reports: list[RuleVulnerabilityReport],
        threshold_report: ThresholdProbeReport | None,
    ) -> tuple[str, list[PatchRecord]]:
        """Returns the hardened YAML string and a list of patches applied."""
        patches: list[PatchRecord] = []

        # Bump version
        old_version = self._raw_data.get("version", "1.0")
        try:
            major, minor = str(old_version).split(".")
            new_version = f"{major}.{int(minor) + 1}"
        except ValueError:
            new_version = f"{old_version}.1"
        self._raw_data["version"] = new_version
        self._raw_data["description"] = (
            str(self._raw_data.get("description", ""))
            + f"\n[AUTO-HARDENED] Patched against vulnerabilities found in v{old_version}."
        )

        # 1. Patch Constraint Bypass vulnerabilities
        for report in bypass_reports:
            if report.is_vulnerable:
                patch = self._patch_prohibited_action(report)
                if patch:
                    patches.append(patch)

        # 2. Patch Threshold vulnerabilities
        if threshold_report and threshold_report.is_vulnerable:
            for finding in threshold_report.vulnerabilities:
                patch = self._patch_threshold(finding)
                if patch:
                    patches.append(patch)

        hardened_yaml = yaml.dump(
            self._raw_data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
        return hardened_yaml, patches

    def _patch_prohibited_action(
        self, report: RuleVulnerabilityReport
    ) -> PatchRecord | None:
        actions = self._raw_data.get("prohibited_actions", [])
        for i, action in enumerate(actions):
            if action.get("id") == report.rule_id:
                original_desc = action.get("description", "")
                if "semantic similarity check" not in original_desc:
                    new_desc = (
                        original_desc
                        + " MUST USE vector embedding similarity check"
                          " (cosine < 0.25) against semantic_synonyms."
                    )
                    self._raw_data["prohibited_actions"][i]["description"] = new_desc
                    return PatchRecord(
                        rule_id=report.rule_id,
                        description="Injected embedding similarity mandate to prevent semantic bypass.",
                        before=original_desc,
                        after=new_desc,
                    )
        return None

    def _patch_threshold(self, finding) -> PatchRecord | None:
        if finding.finding not in {
            ThresholdFinding.SPLIT_BYPASS_POSSIBLE,
            ThresholdFinding.CUMULATIVE_BLIND,
        }:
            return None

        limit_name = (
            "max_per_session_usd"
            if finding.finding == ThresholdFinding.CUMULATIVE_BLIND
            else finding.limit_name
        )

        limits = self._raw_data.get("spend_limits", {})
        if limit_name not in limits:
            return None

        current_tracking = limits[limit_name].get("cumulative_tracking", False)
        if current_tracking:
            return None

        self._raw_data["spend_limits"][limit_name]["cumulative_tracking"] = True
        return PatchRecord(
            rule_id=f"spend_limits.{limit_name}",
            description="Enabled cumulative_tracking to prevent transaction splitting attacks.",
            before="cumulative_tracking: false",
            after="cumulative_tracking: true",
        )