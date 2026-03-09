# agentseal/baselines.py
"""
Rug pull detection via baseline fingerprinting.

On first scan, fingerprints MCP server configurations (command, args, env keys)
and optionally hashes installed binaries. On subsequent scans, detects changes
and alerts the user.

Storage: ~/.agentseal/baselines/{agent_type}/{server_name}.json

Wave 2 scope:
  - Level 1: Config hash (command + args + env keys)
  - Level 2: Binary hash (if resolvable locally)
  - Level 3: Tool signature hash (deferred to Phase 2 - requires MCP runtime)
"""

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _baselines_dir() -> Path:
    return Path.home() / ".agentseal" / "baselines"


def _config_fingerprint(server: dict) -> str:
    """Compute a deterministic hash of a server's config fields.

    Hashes: command, sorted args, sorted env keys (not values - they may
    contain secrets that rotate).
    """
    parts = [
        server.get("command", ""),
        json.dumps(sorted(str(a) for a in server.get("args", []) if isinstance(a, str))),
        json.dumps(sorted(str(k) for k in server.get("env", {}) if isinstance(k, str))),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _resolve_binary(command: str) -> Optional[Path]:
    """Try to find the actual binary for an MCP server command.

    Handles: direct paths, npx packages, uvx/pip packages.
    Returns None if the binary cannot be resolved.
    """
    if not command:
        return None

    # Direct path
    p = Path(command)
    if p.is_file():
        return p

    # Look up in PATH
    resolved = shutil.which(command)
    if resolved:
        return Path(resolved)

    return None


def _hash_binary(path: Path) -> Optional[str]:
    """Compute SHA256 of a binary file. Returns None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


@dataclass
class BaselineEntry:
    """Stored baseline for one MCP server."""
    server_name: str
    agent_type: str
    config_hash: str
    binary_hash: Optional[str]
    binary_path: Optional[str]
    command: str
    args: list[str]
    first_seen: str
    last_verified: str

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "agent_type": self.agent_type,
            "config_hash": self.config_hash,
            "binary_hash": self.binary_hash,
            "binary_path": self.binary_path,
            "command": self.command,
            "args": self.args,
            "first_seen": self.first_seen,
            "last_verified": self.last_verified,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BaselineEntry":
        return cls(
            server_name=d["server_name"],
            agent_type=d.get("agent_type", "unknown"),
            config_hash=d["config_hash"],
            binary_hash=d.get("binary_hash"),
            binary_path=d.get("binary_path"),
            command=d.get("command", ""),
            args=d.get("args", []),
            first_seen=d.get("first_seen", ""),
            last_verified=d.get("last_verified", ""),
        )


@dataclass
class BaselineChange:
    """Describes what changed in a server's baseline."""
    server_name: str
    agent_type: str
    change_type: str  # "config_changed", "binary_changed", "new_server", "server_removed"
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    detail: str = ""


class BaselineStore:
    """Manages baseline fingerprints for rug pull detection."""

    def __init__(self, baselines_dir: Optional[Path] = None):
        self._dir = baselines_dir or _baselines_dir()

    def _entry_path(self, agent_type: str, server_name: str) -> Path:
        # Sanitize names for filesystem safety
        safe_agent = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_type)
        safe_server = "".join(c if c.isalnum() or c in "-_" else "_" for c in server_name)
        return self._dir / safe_agent / f"{safe_server}.json"

    def load(self, agent_type: str, server_name: str) -> Optional[BaselineEntry]:
        """Load a stored baseline entry. Returns None if not found."""
        path = self._entry_path(agent_type, server_name)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return BaselineEntry.from_dict(data)
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def save(self, entry: BaselineEntry) -> None:
        """Save a baseline entry to disk."""
        path = self._entry_path(entry.agent_type, entry.server_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(entry.to_dict(), indent=2),
            encoding="utf-8",
        )

    def check_server(self, server: dict) -> Optional[BaselineChange]:
        """Check a single MCP server against its stored baseline.

        Returns:
            None if no change detected (or first time seen - baseline created).
            BaselineChange if something changed.
        """
        name = server.get("name", "unknown")
        agent_type = server.get("agent_type", "unknown")
        command = server.get("command", "")
        args = [str(a) for a in server.get("args", []) if isinstance(a, str)]
        now = datetime.now(timezone.utc).isoformat()

        config_hash = _config_fingerprint(server)

        # Try to resolve and hash the binary
        binary_path = _resolve_binary(command)
        binary_hash = _hash_binary(binary_path) if binary_path else None

        existing = self.load(agent_type, name)

        if existing is None:
            # First time seeing this server - create baseline
            self.save(BaselineEntry(
                server_name=name,
                agent_type=agent_type,
                config_hash=config_hash,
                binary_hash=binary_hash,
                binary_path=str(binary_path) if binary_path else None,
                command=command,
                args=args,
                first_seen=now,
                last_verified=now,
            ))
            return BaselineChange(
                server_name=name,
                agent_type=agent_type,
                change_type="new_server",
                detail=f"New MCP server '{name}' baselined.",
            )

        # Check for config changes
        if existing.config_hash != config_hash:
            change = BaselineChange(
                server_name=name,
                agent_type=agent_type,
                change_type="config_changed",
                old_value=existing.config_hash[:12],
                new_value=config_hash[:12],
                detail=f"Config for '{name}' changed (command/args/env modified).",
            )
            # Update baseline
            existing.config_hash = config_hash
            existing.command = command
            existing.args = args
            existing.last_verified = now
            self.save(existing)
            return change

        # Check for binary changes
        if binary_hash and existing.binary_hash and existing.binary_hash != binary_hash:
            change = BaselineChange(
                server_name=name,
                agent_type=agent_type,
                change_type="binary_changed",
                old_value=existing.binary_hash[:12],
                new_value=binary_hash[:12],
                detail=f"Binary for '{name}' changed. Possible supply chain attack.",
            )
            existing.binary_hash = binary_hash
            existing.last_verified = now
            self.save(existing)
            return change

        # No change - update verification timestamp
        existing.last_verified = now
        self.save(existing)
        return None

    def check_all(
        self, servers: list[dict], *, include_new: bool = False,
    ) -> list[BaselineChange]:
        """Check all servers. Returns list of changes (empty = no changes).

        Args:
            include_new: If True, also return "new_server" entries (first-time baselines).
        """
        changes = []
        for srv in servers:
            change = self.check_server(srv)
            if change is None:
                continue
            if change.change_type == "new_server" and not include_new:
                continue
            changes.append(change)
        return changes

    def reset(self) -> int:
        """Remove all baselines. Returns count of entries removed."""
        count = 0
        if self._dir.is_dir():
            for f in self._dir.rglob("*.json"):
                f.unlink()
                count += 1
        return count

    def list_entries(self) -> list[BaselineEntry]:
        """List all stored baseline entries."""
        entries = []
        if not self._dir.is_dir():
            return entries
        for f in self._dir.rglob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                entries.append(BaselineEntry.from_dict(data))
            except (json.JSONDecodeError, KeyError, OSError):
                continue
        return entries
