# agentseal/guard.py
"""
Guard — one-command machine security scan.

Chains machine discovery, skill scanning, and MCP config checking into
a single zero-config experience. The user types `agentseal guard` and
gets a complete security report of their machine.

All operations are synchronous and local — no network requests needed
(except optional blocklist update). No async, no LLM calls.
"""

import time
from datetime import datetime, timezone
from typing import Callable, Optional

from agentseal.baselines import BaselineStore
from agentseal.guard_models import (
    BaselineChangeResult,
    GuardReport,
    ToxicFlowResult,
)
from agentseal.machine_discovery import scan_machine
from agentseal.mcp_checker import MCPConfigChecker
from agentseal.skill_scanner import SkillScanner
from agentseal.toxic_flows import analyze_toxic_flows


# Progress callback type: (phase: str, detail: str) -> None
ProgressFn = Callable[[str, str], None]


class Guard:
    """One-command machine security scan."""

    def __init__(
        self,
        semantic: bool = True,
        verbose: bool = False,
        on_progress: Optional[ProgressFn] = None,
    ):
        self.semantic = semantic
        self.verbose = verbose
        self._progress = on_progress or (lambda *a: None)

    def run(self) -> GuardReport:
        """Execute full guard scan. Returns a GuardReport with all findings."""
        start = time.monotonic()

        # Phase 1: Discover agents, MCP servers, and skills
        self._progress("discover", "Scanning for AI agents, skills, and MCP servers...")
        agents, mcp_servers, skill_paths = scan_machine()

        installed_count = sum(1 for a in agents if a.status == "found")
        self._progress(
            "discover",
            f"Found {installed_count} agents, {len(skill_paths)} skills, "
            f"{len(mcp_servers)} MCP servers",
        )

        # Phase 2: Scan skills
        self._progress("skills", f"Scanning {len(skill_paths)} skills for threats...")
        scanner = SkillScanner(semantic=self.semantic)
        skill_results = []
        for i, path in enumerate(skill_paths):
            self._progress("skills", f"[{i + 1}/{len(skill_paths)}] {path.name}")
            skill_results.append(scanner.scan_file(path))

        # Phase 3: Check MCP configs
        self._progress("mcp", f"Checking {len(mcp_servers)} MCP server configurations...")
        checker = MCPConfigChecker()
        mcp_results = checker.check_all(mcp_servers)

        # Phase 4: Toxic flow analysis
        toxic_flow_results: list[ToxicFlowResult] = []
        if len(mcp_servers) >= 2:
            self._progress("flows", "Analyzing MCP server capability combinations...")
            raw_flows = analyze_toxic_flows(mcp_servers)
            for flow in raw_flows:
                toxic_flow_results.append(ToxicFlowResult(
                    risk_level=flow.risk_level,
                    risk_type=flow.risk_type,
                    title=flow.title,
                    description=flow.description,
                    servers_involved=flow.servers_involved,
                    remediation=flow.remediation,
                ))
            if toxic_flow_results:
                self._progress("flows", f"Found {len(toxic_flow_results)} toxic flow(s)")
            else:
                self._progress("flows", "No dangerous capability combinations found")

        # Phase 5: Baseline check (rug pull detection)
        baseline_results: list[BaselineChangeResult] = []
        if mcp_servers:
            self._progress("baselines", "Checking MCP server baselines...")
            store = BaselineStore()
            changes = store.check_all(mcp_servers)
            for change in changes:
                baseline_results.append(BaselineChangeResult(
                    server_name=change.server_name,
                    agent_type=change.agent_type,
                    change_type=change.change_type,
                    detail=change.detail,
                ))
            if baseline_results:
                self._progress("baselines", f"{len(baseline_results)} baseline change(s) detected")
            else:
                self._progress("baselines", "All baselines verified")

        duration = time.monotonic() - start

        return GuardReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 2),
            agents_found=agents,
            skill_results=skill_results,
            mcp_results=mcp_results,
            toxic_flows=toxic_flow_results,
            baseline_changes=baseline_results,
        )
