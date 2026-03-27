"""
Rich progress bar for the adversarial audit campaign.

Shows:
  - Overall campaign progress (attacks completed / total)
  - Current attack module and rule being tested
  - Live bypass rate per rule
  - ETA based on elapsed time
  - Final summary table on completion

Falls back gracefully to plain logging if `rich` is not installed.

Usage:
    from adversarial.cli.progress import AuditProgress

    progress = AuditProgress(total_rules=9, attack_modules=5)
    progress.start()

    progress.set_attack("Constraint Bypass", rule_id="delete_record")
    progress.update(attempts=20, bypasses=7)
    progress.complete_rule("delete_record", success_rate=0.35, severity="CRITICAL")

    progress.stop()
    progress.print_summary()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Rich availability check
# ---------------------------------------------------------------------------

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
    from rich.text import Text
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Result record
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    rule_id:      str
    attack_type:  str
    severity:     str
    success_rate: float
    attempts:     int
    bypasses:     int
    duration_s:   float

    @property
    def status_icon(self) -> str:
        if self.success_rate == 0:
            return "✅"
        if self.severity == "CRITICAL":
            return "🔴"
        if self.severity == "HIGH":
            return "🟠"
        return "🟡"


# ---------------------------------------------------------------------------
# Progress tracker (rich)
# ---------------------------------------------------------------------------

class AuditProgress:
    """
    Live progress display for the full audit campaign.

    Works with or without `rich` installed — falls back to plain print.
    """

    def __init__(
        self,
        total_rules:    int,
        attack_modules: int = 5,
        console:        Any = None,
    ) -> None:
        self.total_rules    = total_rules
        self.attack_modules = attack_modules
        self._results:      list[RuleResult] = []
        self._current_rule: str  = ""
        self._current_attack: str = ""
        self._rule_start:   float = 0.0
        self._campaign_start: float = time.monotonic()
        self._attempts:     int  = 0
        self._bypasses:     int  = 0

        if _RICH_AVAILABLE:
            self._console  = console or Console()
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=self._console,
                refresh_per_second=4,
            )
            self._campaign_task = self._progress.add_task(
                "Audit campaign", total=total_rules * attack_modules
            )
            self._rule_task = self._progress.add_task(
                "Current rule", total=100, visible=False
            )
            self._live: Any = None
        else:
            self._progress = None  # type: ignore

    def start(self) -> None:
        self._campaign_start = time.monotonic()
        if _RICH_AVAILABLE and self._progress:
            self._live = Live(self._progress, refresh_per_second=4)
            self._live.start()
        else:
            print("[audit] Campaign started")

    def stop(self) -> None:
        if _RICH_AVAILABLE and self._live:
            self._live.stop()

    def set_attack(self, attack_name: str, rule_id: str = "") -> None:
        self._current_attack = attack_name
        self._current_rule   = rule_id
        self._rule_start     = time.monotonic()
        self._attempts       = 0
        self._bypasses       = 0

        if _RICH_AVAILABLE and self._progress:
            desc = f"[{attack_name}] {rule_id}" if rule_id else attack_name
            self._progress.update(self._rule_task, description=desc, visible=True, completed=0)
        else:
            print(f"[audit] {attack_name} → {rule_id}")

    def update(self, attempts: int = 1, bypasses: int = 0) -> None:
        self._attempts += attempts
        self._bypasses += bypasses

        if _RICH_AVAILABLE and self._progress and self._attempts > 0:
            rate = self._bypasses / self._attempts * 100
            self._progress.update(
                self._rule_task,
                completed=min(self._attempts, 100),
                description=(
                    f"[bold]{self._current_attack}[/bold] "
                    f"{self._current_rule} "
                    f"[{'red' if rate > 30 else 'green'}]{rate:.0f}% bypass[/]"
                ),
            )

    def complete_rule(
        self,
        rule_id:      str,
        success_rate: float,
        severity:     str = "HIGH",
        attack_type:  str = "",
    ) -> None:
        duration = time.monotonic() - self._rule_start
        result = RuleResult(
            rule_id=rule_id,
            attack_type=attack_type or self._current_attack,
            severity=severity,
            success_rate=success_rate,
            attempts=self._attempts,
            bypasses=self._bypasses,
            duration_s=duration,
        )
        self._results.append(result)

        if _RICH_AVAILABLE and self._progress:
            self._progress.advance(self._campaign_task)
        else:
            icon = "VULN" if success_rate > 0 else "OK"
            print(
                f"[audit] [{icon}] {rule_id} — "
                f"{success_rate*100:.0f}% bypass ({duration:.1f}s)"
            )

    def print_summary(self) -> None:
        elapsed = time.monotonic() - self._campaign_start
        total   = len(self._results)
        vulns   = [r for r in self._results if r.success_rate > 0]
        crits   = [r for r in vulns if r.severity == "CRITICAL"]

        if _RICH_AVAILABLE:
            self._console.print()
            table = Table(
                title="Audit Campaign Results",
                show_header=True,
                header_style="bold",
            )
            table.add_column("Rule",        style="dim", width=28)
            table.add_column("Attack",      width=20)
            table.add_column("Severity",    width=10)
            table.add_column("Bypass Rate", justify="right", width=12)
            table.add_column("Status",      justify="center", width=6)

            for r in sorted(self._results, key=lambda x: -x.success_rate):
                bypass_str = f"{r.success_rate*100:.0f}%"
                if r.success_rate > 0.5:
                    bypass_color = "red"
                elif r.success_rate > 0:
                    bypass_color = "yellow"
                else:
                    bypass_color = "green"

                table.add_row(
                    r.rule_id,
                    r.attack_type,
                    r.severity,
                    f"[{bypass_color}]{bypass_str}[/{bypass_color}]",
                    r.status_icon,
                )

            self._console.print(table)
            self._console.print(
                f"\n[bold]Campaign complete[/bold] in {elapsed:.0f}s — "
                f"{len(vulns)}/{total} rules vulnerable, "
                f"[red]{len(crits)} CRITICAL[/red]"
            )
        else:
            print(f"\n{'='*60}")
            print(f"Campaign complete in {elapsed:.0f}s")
            print(f"Rules tested:    {total}")
            print(f"Vulnerable:      {len(vulns)}")
            print(f"Critical:        {len(crits)}")
            for r in sorted(self._results, key=lambda x: -x.success_rate):
                icon = r.status_icon
                print(f"  {icon} {r.rule_id:30s} {r.success_rate*100:5.0f}%")
            print(f"{'='*60}\n")