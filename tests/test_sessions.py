# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the universal session-store readers.

Uses hermetic temp dirs so tests never depend on the real user's session stores.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from termrecall.sessions import (
    SessionRecord,
    find_active_session_id,
    find_sessions_for_cwd,
    list_sessions,
    _read_codex_sessions,
    _read_pi_sessions,
    _read_opencode_sessions,
)


def _write_codex_rollout(home: Path, session_id: str, cwd: str, *, ts: str = "2026-08-20T10:00:00.000Z") -> Path:
    """Create a codex rollout file with a session_meta record."""
    path = home / ".codex/sessions/2026/08/20"
    path.mkdir(parents=True, exist_ok=True)
    fname = f"rollout-2026-08-20T10-00-00-{session_id}.jsonl"
    fpath = path / fname
    meta = {"timestamp": ts, "type": "session_meta", "payload": {"id": session_id, "cwd": cwd, "thread_name": "test"}}
    fpath.write_text(json.dumps(meta) + "\n")
    return fpath


def _write_pi_session(home: Path, session_id: str, cwd: str, *, ts: str = "2026-08-20T10-00-00-000Z") -> Path:
    """Create a pi session file in a cwd-derived slug directory."""
    slug = "--" + cwd.strip("/").replace("/", "-") + "--"
    sdir = home / ".pi/agent/sessions" / slug
    sdir.mkdir(parents=True, exist_ok=True)
    fname = f"{ts}_{session_id}.jsonl"
    fpath = sdir / fname
    fpath.write_text("{}\n")
    return fpath


def _write_opencode_db(home: Path, sessions: list[tuple[str, str, str]]) -> None:
    """Create an opencode SQLite DB with session rows (id, directory, title)."""
    dbdir = home / ".local/share/opencode"
    dbdir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(dbdir / "opencode.db"))
    conn.execute("CREATE TABLE session (id text PRIMARY KEY, directory text, title text, updated_at text)")
    for sid, directory, title in sessions:
        conn.execute("INSERT INTO session (id, directory, title, updated_at) VALUES (?,?,?,?)",
                     (sid, directory, title, "2026-08-20T10:00:00Z"))
    conn.commit()
    conn.close()


def test_codex_reader_extracts_id_and_cwd(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    records = _read_codex_sessions(tmp_path)
    assert len(records) == 1
    r = records[0]
    assert r.tool == "codex"
    assert r.session_id == "01a014ef-679a-7e53-9129-decaba38336f"
    assert r.cwd == "/srv/app"
    assert r.title == "test"


def test_codex_reader_normalizes_file_uri_cwd(tmp_path: Path) -> None:
    """codex stores cwd as file:// URI in some versions; normalize it."""
    path = tmp_path / ".codex/sessions/2026/08/20"
    path.mkdir(parents=True)
    meta = {"timestamp": "2026-08-20T10:00:00Z", "type": "session_meta",
            "payload": {"id": "01a014ef-679a-7e53-9129-decaba38336f", "cwd": "file:///srv/app"}}
    (path / "rollout-2026-08-20T10-00-00-01a014ef-679a-7e53-9129-decaba38336f.jsonl").write_text(json.dumps(meta) + "\n")
    records = _read_codex_sessions(tmp_path)
    assert records[0].cwd == "/srv/app"


def test_pi_reader_extracts_id_and_cwd(tmp_path: Path) -> None:
    _write_pi_session(tmp_path, "019f3cad-aa15-7d4c-8efc-2595db651980", "/home/user/myproject")
    records = _read_pi_sessions(tmp_path)
    assert len(records) == 1
    r = records[0]
    assert r.tool == "pi"
    assert r.session_id == "019f3cad-aa15-7d4c-8efc-2595db651980"
    assert r.cwd == "/home/user/myproject"


def test_opencode_reader_reads_session_table(tmp_path: Path) -> None:
    _write_opencode_db(tmp_path, [("sess-1", "/srv/app", "My App")])
    records = _read_opencode_sessions(tmp_path)
    assert len(records) == 1
    r = records[0]
    assert r.tool == "opencode"
    assert r.session_id == "sess-1"
    assert r.cwd == "/srv/app"
    assert r.title == "My App"


def test_find_sessions_for_cwd_returns_multiple_ordered(tmp_path: Path) -> None:
    """Multi-session: same cwd, multiple sessions, most-recent first."""
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app", ts="2026-08-20T09:00:00.000Z")
    _write_codex_rollout(tmp_path, "01a014f7-934a-7dd2-95fc-5ecfbb2eeafc", "/srv/app", ts="2026-08-20T12:00:00.000Z")
    matches = find_sessions_for_cwd("/srv/app", home=lambda: tmp_path)
    assert len(matches) == 2
    # Most recent first (12:00 > 09:00).
    assert matches[0].session_id == "01a014f7-934a-7dd2-95fc-5ecfbb2eeafc"
    assert matches[1].session_id == "01a014ef-679a-7e53-9129-decaba38336f"


def test_find_sessions_for_cwd_filters_by_exact_cwd(tmp_path: Path) -> None:
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    _write_codex_rollout(tmp_path, "01a014f7-934a-7dd2-95fc-5ecfbb2eeafc", "/srv/other")
    matches = find_sessions_for_cwd("/srv/app", home=lambda: tmp_path)
    assert len(matches) == 1
    assert matches[0].session_id == "01a014ef-679a-7e53-9129-decaba38336f"


def test_find_active_session_id_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("CODEX_SESSION_ID", "01a014ef-679a-7e53-9129-decaba38336f")
    assert find_active_session_id("codex") == "01a014ef-679a-7e53-9129-decaba38336f"


def test_find_active_session_id_returns_none_for_tools_without_env(monkeypatch) -> None:
    monkeypatch.delenv("CODEX_SESSION_ID", raising=False)
    assert find_active_session_id("codex") is None
    assert find_active_session_id("pi") is None
    assert find_active_session_id("hermes") is None


def test_list_sessions_across_all_tools(tmp_path: Path) -> None:
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    _write_pi_session(tmp_path, "019f3cad-aa15-7d4c-8efc-2595db651980", "/srv/app")
    all_sessions = list_sessions(home=lambda: tmp_path)
    assert len(all_sessions) == 2
    tools = {r.tool for r in all_sessions}
    assert tools == {"codex", "pi"}


def test_readers_handle_missing_store_gracefully(tmp_path: Path) -> None:
    """No session dir at all → empty list, no crash."""
    assert _read_codex_sessions(tmp_path) == []
    assert _read_pi_sessions(tmp_path) == []
    assert _read_opencode_sessions(tmp_path) == []
    assert list_sessions(home=lambda: tmp_path) == []


def test_readers_handle_corrupt_file_gracefully(tmp_path: Path) -> None:
    """A malformed rollout file is skipped, not fatal."""
    path = tmp_path / ".codex/sessions/2026/08/20"
    path.mkdir(parents=True)
    (path / "rollout-2026-08-20T10-00-00-01a014ef-679a-7e53-9129-decaba38336f.jsonl").write_text("not json\n")
    assert _read_codex_sessions(tmp_path) == []
