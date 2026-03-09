# agentseal/guard_models.py
"""
Data models for the guard command — machine-level security scanning.

These are separate from schemas.py because guard operates at a different level:
schemas.py is about probe results (testing agent behavior via LLM),
guard_models.py is about static analysis of the local machine (skills, configs, MCP).
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class GuardVerdict(str, Enum):
    """Verdict for a single scanned item (skill, MCP server, etc.)."""
    SAFE = "safe"
    WARNING = "warning"
    DANGER = "danger"
    ERROR = "error"


# ═══════════════════════════════════════════════════════════════════════
# SKILL SCANNING MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SkillFinding:
    """A single finding from skill analysis."""
    code: str               # e.g. "SKILL-001"
    title: str              # Human-readable: "Credential theft pattern"
    description: str        # Plain English: "This skill reads ~/.ssh/..."
    severity: str           # "critical", "high", "medium", "low"
    evidence: str           # The suspicious line or pattern found
    remediation: str        # "Remove this skill and rotate API keys"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class SkillResult:
    """Result of scanning one skill."""
    name: str
    path: str
    verdict: GuardVerdict
    findings: list[SkillFinding] = field(default_factory=list)
    blocklist_match: bool = False
    sha256: str = ""

    @property
    def top_finding(self) -> Optional[SkillFinding]:
        """Return the highest-severity finding, or None."""
        if not self.findings:
            return None
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.findings, key=lambda f: severity_order.get(f.severity, 99))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
            "blocklist_match": self.blocklist_match,
            "sha256": self.sha256,
        }


# ═══════════════════════════════════════════════════════════════════════
# MCP CONFIG SCANNING MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MCPFinding:
    """A single finding from MCP config analysis."""
    code: str               # e.g. "MCP-001"
    title: str              # "Filesystem access to ~/.ssh"
    description: str        # Plain English explanation
    severity: str           # "critical", "high", "medium", "low"
    remediation: str        # "Remove ~/.ssh from allowed paths"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "remediation": self.remediation,
        }


@dataclass
class MCPServerResult:
    """Result of checking one MCP server config."""
    name: str
    command: str
    source_file: str
    verdict: GuardVerdict
    findings: list[MCPFinding] = field(default_factory=list)

    @property
    def top_finding(self) -> Optional[MCPFinding]:
        if not self.findings:
            return None
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.findings, key=lambda f: severity_order.get(f.severity, 99))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "source_file": self.source_file,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
        }


# ═══════════════════════════════════════════════════════════════════════
# AGENT DISCOVERY MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AgentConfigResult:
    """Result of discovering one agent configuration on the machine."""
    name: str               # "Claude Desktop", "Cursor", etc.
    config_path: str        # Path to config file
    agent_type: str         # "claude-desktop", "cursor", "vscode", etc.
    mcp_servers: int        # Number of MCP servers configured
    skills_count: int       # Number of skills found
    status: str             # "found", "not_installed", "error"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "config_path": self.config_path,
            "agent_type": self.agent_type,
            "mcp_servers": self.mcp_servers,
            "skills_count": self.skills_count,
            "status": self.status,
        }


# ═══════════════════════════════════════════════════════════════════════
# TOXIC FLOW MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ToxicFlowResult:
    """A detected dangerous combination of server capabilities."""
    risk_level: str      # "high", "medium"
    risk_type: str       # "data_exfiltration", "remote_code_execution", etc.
    title: str
    description: str
    servers_involved: list[str]
    remediation: str

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level,
            "risk_type": self.risk_type,
            "title": self.title,
            "description": self.description,
            "servers_involved": self.servers_involved,
            "remediation": self.remediation,
        }


# ═══════════════════════════════════════════════════════════════════════
# BASELINE CHANGE MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BaselineChangeResult:
    """A detected change in an MCP server's baseline."""
    server_name: str
    agent_type: str
    change_type: str  # "config_changed", "binary_changed"
    detail: str

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "agent_type": self.agent_type,
            "change_type": self.change_type,
            "detail": self.detail,
        }


# ═══════════════════════════════════════════════════════════════════════
# GUARD REPORT (top-level result)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class GuardReport:
    """Complete guard scan report for a machine."""
    timestamp: str
    duration_seconds: float
    agents_found: list[AgentConfigResult]
    skill_results: list[SkillResult]
    mcp_results: list[MCPServerResult]
    toxic_flows: list[ToxicFlowResult] = field(default_factory=list)
    baseline_changes: list[BaselineChangeResult] = field(default_factory=list)

    @property
    def total_dangers(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.DANGER)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.DANGER)
        return skills + mcp

    @property
    def total_warnings(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.WARNING)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.WARNING)
        return skills + mcp

    @property
    def total_safe(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.SAFE)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.SAFE)
        return skills + mcp

    @property
    def has_critical(self) -> bool:
        return self.total_dangers > 0

    @property
    def all_actions(self) -> list[str]:
        """Collect all remediation actions, sorted by severity."""
        actions = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        all_findings: list[tuple[str, SkillFinding | MCPFinding]] = []
        for s in self.skill_results:
            for f in s.findings:
                all_findings.append((s.name, f))
        for m in self.mcp_results:
            for f in m.findings:
                all_findings.append((m.name, f))

        all_findings.sort(key=lambda x: severity_order.get(x[1].severity, 99))

        for item_name, finding in all_findings:
            actions.append(finding.remediation)

        return actions

    @property
    def total_toxic_flows(self) -> int:
        return len(self.toxic_flows)

    @property
    def total_baseline_changes(self) -> int:
        return len(self.baseline_changes)

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "agents_found": [a.to_dict() for a in self.agents_found],
            "skill_results": [s.to_dict() for s in self.skill_results],
            "mcp_results": [m.to_dict() for m in self.mcp_results],
            "summary": {
                "total_dangers": self.total_dangers,
                "total_warnings": self.total_warnings,
                "total_safe": self.total_safe,
            },
        }
        if self.toxic_flows:
            d["toxic_flows"] = [f.to_dict() for f in self.toxic_flows]
        if self.baseline_changes:
            d["baseline_changes"] = [c.to_dict() for c in self.baseline_changes]
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
