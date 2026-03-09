# agentseal/toxic_flows.py
"""
Lightweight toxic flow detection - static analysis only (no MCP runtime).

Classifies MCP servers by capability labels based on known package names
and server name heuristics. Detects dangerous combinations of capabilities
across servers that could enable data exfiltration, remote code execution,
or data destruction.

Wave 2 scope: classification from config only (names + args).
Phase 2 upgrade: replace with actual tool descriptions from list_tools().
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# Capability Labels
# ═══════════════════════════════════════════════════════════════════════

LABEL_PUBLIC_SINK = "public_sink"       # sends data externally
LABEL_DESTRUCTIVE = "destructive"       # modifies/deletes data
LABEL_UNTRUSTED = "untrusted_content"   # fetches external data
LABEL_PRIVATE = "private_data"          # reads sensitive data

ALL_LABELS = {LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE, LABEL_UNTRUSTED, LABEL_PRIVATE}


# ═══════════════════════════════════════════════════════════════════════
# Known Server Classifications
# ═══════════════════════════════════════════════════════════════════════

# Curated mapping of well-known MCP server packages to their capability labels.
KNOWN_SERVER_LABELS: dict[str, set[str]] = {
    # Filesystem
    "filesystem": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "fs": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    # Communication / sinks
    "slack": {LABEL_PUBLIC_SINK},
    "discord": {LABEL_PUBLIC_SINK},
    "email": {LABEL_PUBLIC_SINK},
    "gmail": {LABEL_PUBLIC_SINK},
    "smtp": {LABEL_PUBLIC_SINK},
    "sendgrid": {LABEL_PUBLIC_SINK},
    "twilio": {LABEL_PUBLIC_SINK},
    "telegram": {LABEL_PUBLIC_SINK},
    "teams": {LABEL_PUBLIC_SINK},
    "webhook": {LABEL_PUBLIC_SINK},
    # Code/project platforms
    "github": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "gitlab": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "bitbucket": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "linear": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "jira": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "notion": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "asana": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    # Databases
    "postgres": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "postgresql": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "mysql": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "sqlite": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "mongo": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "mongodb": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "redis": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "supabase": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    # Web / external content
    "fetch": {LABEL_UNTRUSTED},
    "puppeteer": {LABEL_UNTRUSTED},
    "playwright": {LABEL_UNTRUSTED},
    "browser": {LABEL_UNTRUSTED},
    "brave-search": {LABEL_UNTRUSTED},
    "tavily": {LABEL_UNTRUSTED},
    "web-search": {LABEL_UNTRUSTED},
    "scraper": {LABEL_UNTRUSTED},
    "crawl": {LABEL_UNTRUSTED},
    # Infrastructure
    "aws": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    "gcp": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    "azure": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    "docker": {LABEL_DESTRUCTIVE},
    "kubernetes": {LABEL_DESTRUCTIVE},
    "k8s": {LABEL_DESTRUCTIVE},
    "terraform": {LABEL_DESTRUCTIVE},
    # Execution
    "shell": {LABEL_DESTRUCTIVE, LABEL_UNTRUSTED},
    "terminal": {LABEL_DESTRUCTIVE, LABEL_UNTRUSTED},
    "exec": {LABEL_DESTRUCTIVE},
    "code-runner": {LABEL_DESTRUCTIVE},
    "sandbox": {LABEL_DESTRUCTIVE},
    # Memory / state
    "memory": {LABEL_PRIVATE},
    "knowledge": {LABEL_PRIVATE},
    "vector": {LABEL_PRIVATE},
    # Monitoring
    "sentry": {LABEL_PRIVATE},
    "datadog": {LABEL_PRIVATE},
    "grafana": {LABEL_PRIVATE},
    # Storage
    "s3": {LABEL_PRIVATE, LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE},
    "gcs": {LABEL_PRIVATE, LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE},
    "drive": {LABEL_PRIVATE, LABEL_PUBLIC_SINK},
    "dropbox": {LABEL_PRIVATE, LABEL_PUBLIC_SINK},
}


# Heuristic patterns for servers not in the known list.
_NAME_HEURISTICS: list[tuple[re.Pattern, set[str]]] = [
    (re.compile(r"(?:file|fs|disk)", re.I), {LABEL_PRIVATE, LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:mail|email|smtp)", re.I), {LABEL_PUBLIC_SINK}),
    (re.compile(r"(?:http|fetch|web|browser|scrape|crawl)", re.I), {LABEL_UNTRUSTED}),
    (re.compile(r"(?:db|sql|database|mongo|redis)", re.I), {LABEL_PRIVATE}),
    (re.compile(r"(?:exec|shell|command|terminal|run)", re.I), {LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:slack|discord|teams|telegram|chat)", re.I), {LABEL_PUBLIC_SINK}),
    (re.compile(r"(?:github|gitlab|bitbucket|jira|linear)", re.I), {LABEL_PUBLIC_SINK, LABEL_PRIVATE}),
    (re.compile(r"(?:aws|gcp|azure|cloud)", re.I), {LABEL_PRIVATE, LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:docker|k8s|kubernetes|terraform)", re.I), {LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:s3|gcs|storage|drive|dropbox)", re.I), {LABEL_PRIVATE, LABEL_PUBLIC_SINK}),
]


def classify_server(server: dict) -> set[str]:
    """Classify an MCP server by its capability labels.

    Checks known package names first, then falls back to name heuristics.
    """
    name = server.get("name", "").lower().strip()
    command = server.get("command", "").lower()
    args_str = " ".join(str(a) for a in server.get("args", []) if isinstance(a, str)).lower()

    # Check known server names (exact match)
    if name in KNOWN_SERVER_LABELS:
        return set(KNOWN_SERVER_LABELS[name])

    # Check if any known name appears in the server name
    for known, labels in KNOWN_SERVER_LABELS.items():
        if known in name:
            return set(labels)

    # Check if any known name appears in command or args (package names)
    search_text = f"{command} {args_str}"
    for known, labels in KNOWN_SERVER_LABELS.items():
        if known in search_text:
            return set(labels)

    # Fall back to heuristic patterns
    labels: set[str] = set()
    for pattern, heuristic_labels in _NAME_HEURISTICS:
        if pattern.search(name) or pattern.search(command) or pattern.search(args_str):
            labels |= heuristic_labels

    return labels


# ═══════════════════════════════════════════════════════════════════════
# Dangerous Combinations
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ToxicFlow:
    """A detected dangerous combination of server capabilities."""
    risk_level: str  # "high", "medium"
    risk_type: str   # "data_exfiltration", "remote_code_execution", "data_destruction", "full_chain"
    title: str
    description: str
    servers_involved: list[str]
    labels_involved: list[str]
    remediation: str


def _detect_combos(
    server_labels: dict[str, set[str]],
) -> list[ToxicFlow]:
    """Detect dangerous capability combinations across servers."""
    flows: list[ToxicFlow] = []

    # Collect all labels across all servers
    all_labels: set[str] = set()
    for labels in server_labels.values():
        all_labels |= labels

    # Servers by label
    by_label: dict[str, list[str]] = {}
    for name, labels in server_labels.items():
        for label in labels:
            by_label.setdefault(label, []).append(name)

    has_private = LABEL_PRIVATE in all_labels
    has_sink = LABEL_PUBLIC_SINK in all_labels
    has_untrusted = LABEL_UNTRUSTED in all_labels
    has_destructive = LABEL_DESTRUCTIVE in all_labels

    # Full chain: untrusted + private + sink (highest risk)
    if has_untrusted and has_private and has_sink:
        flows.append(ToxicFlow(
            risk_level="high",
            risk_type="full_chain",
            title="Full attack chain detected",
            description=(
                "This agent can fetch external content, read private data, "
                "and send data externally. An attacker could inject instructions "
                "via fetched content, read sensitive files, and exfiltrate them."
            ),
            servers_involved=sorted(set(
                by_label.get(LABEL_UNTRUSTED, []) +
                by_label.get(LABEL_PRIVATE, []) +
                by_label.get(LABEL_PUBLIC_SINK, [])
            )),
            labels_involved=[LABEL_UNTRUSTED, LABEL_PRIVATE, LABEL_PUBLIC_SINK],
            remediation=(
                "Scope filesystem access to non-sensitive directories. "
                "Remove or restrict external communication servers."
            ),
        ))
        return flows  # Full chain subsumes the individual combos

    # Data exfiltration: private + sink
    if has_private and has_sink:
        flows.append(ToxicFlow(
            risk_level="high",
            risk_type="data_exfiltration",
            title="Data exfiltration path detected",
            description=(
                "This agent can read private data and send it externally. "
                "A prompt injection could instruct the agent to read sensitive "
                "files and leak them via an external service."
            ),
            servers_involved=sorted(set(
                by_label.get(LABEL_PRIVATE, []) +
                by_label.get(LABEL_PUBLIC_SINK, [])
            )),
            labels_involved=[LABEL_PRIVATE, LABEL_PUBLIC_SINK],
            remediation=(
                "Scope filesystem access to non-sensitive directories only. "
                "Review which external services truly need write access."
            ),
        ))

    # Remote code execution: untrusted + destructive
    if has_untrusted and has_destructive:
        flows.append(ToxicFlow(
            risk_level="high",
            risk_type="remote_code_execution",
            title="Remote code execution path detected",
            description=(
                "This agent can fetch external content and execute destructive "
                "operations. Fetched content could contain malicious instructions "
                "that modify files, execute commands, or alter databases."
            ),
            servers_involved=sorted(set(
                by_label.get(LABEL_UNTRUSTED, []) +
                by_label.get(LABEL_DESTRUCTIVE, [])
            )),
            labels_involved=[LABEL_UNTRUSTED, LABEL_DESTRUCTIVE],
            remediation=(
                "Add confirmation steps before destructive operations. "
                "Restrict or sandbox the execution server."
            ),
        ))

    # Data destruction: private + destructive (from different servers)
    if has_private and has_destructive:
        private_servers = set(by_label.get(LABEL_PRIVATE, []))
        destructive_servers = set(by_label.get(LABEL_DESTRUCTIVE, []))
        # Only flag if the capability spans multiple servers
        # (a single server like filesystem inherently has both)
        if private_servers != destructive_servers:
            flows.append(ToxicFlow(
                risk_level="medium",
                risk_type="data_destruction",
                title="Data destruction path detected",
                description=(
                    "This agent can read private data from one source and "
                    "perform destructive operations on another. This could "
                    "lead to data corruption or deletion."
                ),
                servers_involved=sorted(private_servers | destructive_servers),
                labels_involved=[LABEL_PRIVATE, LABEL_DESTRUCTIVE],
                remediation=(
                    "Review whether both data read and write capabilities "
                    "are necessary. Consider read-only access where possible."
                ),
            ))

    return flows


def analyze_toxic_flows(servers: list[dict]) -> list[ToxicFlow]:
    """Analyze MCP servers for dangerous capability combinations.

    Args:
        servers: List of MCP server config dicts (as returned by scan_machine).

    Returns:
        List of detected toxic flows (empty if no dangerous combos found).
    """
    if len(servers) < 2:
        return []  # Need at least 2 servers for a cross-server flow

    server_labels: dict[str, set[str]] = {}
    for srv in servers:
        name = srv.get("name", "unknown")
        labels = classify_server(srv)
        if labels:
            server_labels[name] = labels

    if not server_labels:
        return []

    return _detect_combos(server_labels)
