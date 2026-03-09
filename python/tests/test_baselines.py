# tests/test_baselines.py
"""
Tests for rug pull detection via baseline fingerprinting.
"""

import json
from pathlib import Path

import pytest

from agentseal.baselines import (
    BaselineChange,
    BaselineEntry,
    BaselineStore,
    _config_fingerprint,
    _hash_binary,
    _resolve_binary,
)


class TestConfigFingerprint:
    def test_deterministic(self):
        server = {"command": "npx", "args": ["server-fs", "/tmp"], "env": {"KEY": "val"}}
        h1 = _config_fingerprint(server)
        h2 = _config_fingerprint(server)
        assert h1 == h2

    def test_different_command_different_hash(self):
        a = {"command": "npx", "args": ["server-fs"], "env": {}}
        b = {"command": "uvx", "args": ["server-fs"], "env": {}}
        assert _config_fingerprint(a) != _config_fingerprint(b)

    def test_different_args_different_hash(self):
        a = {"command": "npx", "args": ["/tmp"], "env": {}}
        b = {"command": "npx", "args": ["/home"], "env": {}}
        assert _config_fingerprint(a) != _config_fingerprint(b)

    def test_different_env_keys_different_hash(self):
        a = {"command": "npx", "args": [], "env": {"KEY": "val"}}
        b = {"command": "npx", "args": [], "env": {"OTHER": "val"}}
        assert _config_fingerprint(a) != _config_fingerprint(b)

    def test_env_value_change_same_hash(self):
        """Env values are NOT hashed (they contain secrets that rotate)."""
        a = {"command": "npx", "args": [], "env": {"KEY": "old-secret"}}
        b = {"command": "npx", "args": [], "env": {"KEY": "new-secret"}}
        assert _config_fingerprint(a) == _config_fingerprint(b)

    def test_arg_order_insensitive(self):
        """Args are sorted, so order doesn't matter."""
        a = {"command": "npx", "args": ["b", "a"], "env": {}}
        b = {"command": "npx", "args": ["a", "b"], "env": {}}
        assert _config_fingerprint(a) == _config_fingerprint(b)

    def test_empty_server(self):
        h = _config_fingerprint({})
        assert isinstance(h, str)
        assert len(h) == 64  # SHA256 hex

    def test_non_string_args_filtered(self):
        a = {"command": "npx", "args": ["valid", 123, None], "env": {}}
        # Should not crash, just filter non-strings
        h = _config_fingerprint(a)
        assert isinstance(h, str)


class TestHashBinary:
    def test_hash_file(self, tmp_path):
        f = tmp_path / "binary"
        f.write_bytes(b"hello world")
        h = _hash_binary(f)
        assert h is not None
        assert len(h) == 64

    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a"
        f2 = tmp_path / "b"
        f1.write_bytes(b"same content")
        f2.write_bytes(b"same content")
        assert _hash_binary(f1) == _hash_binary(f2)

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a"
        f2 = tmp_path / "b"
        f1.write_bytes(b"content A")
        f2.write_bytes(b"content B")
        assert _hash_binary(f1) != _hash_binary(f2)

    def test_nonexistent_returns_none(self, tmp_path):
        assert _hash_binary(tmp_path / "nope") is None

    def test_permission_denied_returns_none(self, tmp_path):
        f = tmp_path / "locked"
        f.write_bytes(b"data")
        f.chmod(0o000)
        try:
            result = _hash_binary(f)
            # On some systems root can still read, so accept either
            assert result is None or isinstance(result, str)
        finally:
            f.chmod(0o644)


class TestBaselineEntry:
    def test_roundtrip(self):
        entry = BaselineEntry(
            server_name="fs",
            agent_type="claude-desktop",
            config_hash="abc123",
            binary_hash="def456",
            binary_path="/usr/local/bin/fs",
            command="npx",
            args=["server-fs"],
            first_seen="2026-01-01T00:00:00Z",
            last_verified="2026-01-01T00:00:00Z",
        )
        d = entry.to_dict()
        restored = BaselineEntry.from_dict(d)
        assert restored.server_name == "fs"
        assert restored.config_hash == "abc123"
        assert restored.binary_hash == "def456"

    def test_from_dict_defaults(self):
        d = {"server_name": "test", "config_hash": "abc"}
        entry = BaselineEntry.from_dict(d)
        assert entry.agent_type == "unknown"
        assert entry.binary_hash is None


class TestBaselineStore:
    def test_save_and_load(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        entry = BaselineEntry(
            server_name="test-server",
            agent_type="cursor",
            config_hash="abc123",
            binary_hash=None,
            binary_path=None,
            command="npx",
            args=["test"],
            first_seen="2026-01-01T00:00:00Z",
            last_verified="2026-01-01T00:00:00Z",
        )
        store.save(entry)
        loaded = store.load("cursor", "test-server")
        assert loaded is not None
        assert loaded.server_name == "test-server"
        assert loaded.config_hash == "abc123"

    def test_load_nonexistent_returns_none(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        assert store.load("cursor", "ghost") is None

    def test_load_corrupt_returns_none(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        path = tmp_path / "cursor" / "bad.json"
        path.parent.mkdir(parents=True)
        path.write_text("not json{{{")
        assert store.load("cursor", "bad") is None

    def test_check_new_server_creates_baseline(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        server = {
            "name": "my-server",
            "agent_type": "cursor",
            "command": "npx",
            "args": ["server-test"],
            "env": {},
        }
        change = store.check_server(server)
        assert change is not None
        assert change.change_type == "new_server"
        # Baseline should now exist
        assert store.load("cursor", "my-server") is not None

    def test_check_unchanged_returns_none(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        server = {
            "name": "stable",
            "agent_type": "cursor",
            "command": "npx",
            "args": ["server-test"],
            "env": {},
        }
        store.check_server(server)  # First check creates baseline
        change = store.check_server(server)  # Second check
        assert change is None

    def test_check_config_changed(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        server_v1 = {
            "name": "evolving",
            "agent_type": "cursor",
            "command": "npx",
            "args": ["server-v1"],
            "env": {},
        }
        store.check_server(server_v1)

        server_v2 = {
            "name": "evolving",
            "agent_type": "cursor",
            "command": "npx",
            "args": ["server-v2"],  # args changed
            "env": {},
        }
        change = store.check_server(server_v2)
        assert change is not None
        assert change.change_type == "config_changed"
        assert "evolving" in change.detail

    def test_check_all_no_changes(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        servers = [
            {"name": "a", "agent_type": "cursor", "command": "npx", "args": ["a"], "env": {}},
            {"name": "b", "agent_type": "cursor", "command": "npx", "args": ["b"], "env": {}},
        ]
        # Create baselines
        for s in servers:
            store.check_server(s)
        # Check again - no changes
        changes = store.check_all(servers)
        assert len(changes) == 0

    def test_check_all_detects_changes(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        servers = [
            {"name": "a", "agent_type": "cursor", "command": "npx", "args": ["a"], "env": {}},
            {"name": "b", "agent_type": "cursor", "command": "npx", "args": ["b"], "env": {}},
        ]
        for s in servers:
            store.check_server(s)

        # Modify server b
        servers[1]["args"] = ["b-modified"]
        changes = store.check_all(servers)
        assert len(changes) == 1
        assert changes[0].server_name == "b"

    def test_reset(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        server = {"name": "x", "agent_type": "t", "command": "c", "args": [], "env": {}}
        store.check_server(server)
        assert store.load("t", "x") is not None

        count = store.reset()
        assert count >= 1
        assert store.load("t", "x") is None

    def test_list_entries(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        for name in ["a", "b", "c"]:
            server = {"name": name, "agent_type": "test", "command": "cmd", "args": [], "env": {}}
            store.check_server(server)

        entries = store.list_entries()
        assert len(entries) == 3
        names = {e.server_name for e in entries}
        assert names == {"a", "b", "c"}

    def test_sanitizes_filenames(self, tmp_path):
        store = BaselineStore(baselines_dir=tmp_path)
        server = {
            "name": "evil/../../etc/passwd",
            "agent_type": "../../root",
            "command": "cmd",
            "args": [],
            "env": {},
        }
        store.check_server(server)  # Should not create files outside baselines dir
        # Verify no path traversal
        for f in tmp_path.rglob("*.json"):
            assert str(f).startswith(str(tmp_path))
