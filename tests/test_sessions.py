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


# ---------------------------------------------------------------------------
# Generic discovery (auto-detects unknown agent tools)
# ---------------------------------------------------------------------------

def _write_generic_jsonl_session(home: Path, tool: str, session_id: str, cwd: str, *, records: list[dict] | None = None) -> Path:
    """Write a session file for a fake tool in ~/.<tool>/sessions/."""
    sdir = home / f".{tool}" / "sessions"
    sdir.mkdir(parents=True, exist_ok=True)
    fpath = sdir / f"{session_id}.jsonl"
    lines = records if records is not None else [
        {"type": "mode", "sessionId": session_id},
        {"type": "user", "cwd": cwd, "text": "hi"},
    ]
    fpath.write_text("".join(json.dumps(r) + "\n" for r in lines))
    return fpath


def test_generic_discovery_detects_unknown_tool(tmp_path: Path) -> None:
    """A tool TermRecall has never heard of (deepseek) is auto-detected."""
    _write_generic_jsonl_session(tmp_path, "deepseek", "0a73a2fd-0351-7c92-9a3f-1a2b3c4d5e6f", "/srv/ds")
    sessions = list_sessions(home=lambda: tmp_path)
    ds = [r for r in sessions if r.tool == "deepseek"]
    assert len(ds) == 1
    assert ds[0].session_id == "0a73a2fd-0351-7c92-9a3f-1a2b3c4d5e6f"
    assert ds[0].cwd == "/srv/ds"


def test_generic_discovery_extracts_cwd_from_later_record(tmp_path: Path) -> None:
    """claude-code puts mode markers first; cwd appears on a later record."""
    sid = "0a73a2fd-0351-7c92-9a3f-1a2b3c4d5e6f"
    _write_generic_jsonl_session(tmp_path, "claude", sid, "/srv/cl", records=[
        {"type": "last-prompt", "leafUuid": "x", "sessionId": sid},
        {"type": "mode", "mode": "normal", "sessionId": sid},
        {"type": "permission-mode", "permissionMode": "auto", "sessionId": sid},
        {"type": "user", "cwd": "/srv/cl", "text": "hello"},
    ])
    sessions = list_sessions(home=lambda: tmp_path)
    cl = [r for r in sessions if r.tool == "claude"]
    assert len(cl) == 1
    assert cl[0].cwd == "/srv/cl"


def test_generic_discovery_normalizes_file_uri_cwd(tmp_path: Path) -> None:
    sid = "0a73a2fd-0351-7c92-9a3f-1a2b3c4d5e6f"
    _write_generic_jsonl_session(tmp_path, "myagent", sid, "ignored", records=[
        {"sessionId": sid, "cwd": "file:///srv/uri"},
    ])
    sessions = list_sessions(home=lambda: tmp_path)
    assert sessions[0].cwd == "/srv/uri"


def test_generic_discovery_falls_back_to_filename_uuid(tmp_path: Path) -> None:
    """A session file with no parseable id-in-record still yields the filename UUID."""
    sid = "0a73a2fd-0351-7c92-9a3f-1a2b3c4d5e6f"
    sdir = tmp_path / ".futureagent" / "sessions"
    sdir.mkdir(parents=True)
    (sdir / f"{sid}.jsonl").write_text("not json at all\n")
    sessions = list_sessions(home=lambda: tmp_path)
    fa = [r for r in sessions if r.tool == "futureagent"]
    assert len(fa) == 1
    assert fa[0].session_id == sid


def test_generic_discovery_skips_non_agent_dotdirs(tmp_path: Path) -> None:
    """~/.cache etc. are not scanned for sessions."""
    (tmp_path / ".cache" / "sub").mkdir(parents=True)
    (tmp_path / ".cache" / "sub" / "0a73a2fd-0351-7c92-9a3f-1a2b3c4d5e6f.jsonl").write_text("{}\n")
    assert list_sessions(home=lambda: tmp_path) == []


def test_generic_discovery_dedups_with_explicit_readers(tmp_path: Path, monkeypatch) -> None:
    """If a tool has both an explicit reader and generic files, no duplicates."""
    # codex rollout (explicit reader)
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    sessions = list_sessions(home=lambda: tmp_path)
    codex = [r for r in sessions if r.tool == "codex"]
    # Each session appears exactly once.
    assert len(codex) == len({r.session_id for r in codex})


# ---------------------------------------------------------------------------
# Session summary (rich context: first real user prompt + timestamps)
# ---------------------------------------------------------------------------

def _write_codex_rollout_with_records(home: Path, session_id: str, cwd: str, records: list[dict]) -> Path:
    """Write a codex-style rollout file with arbitrary records."""
    path = home / ".codex/sessions/2026/08/20"
    path.mkdir(parents=True, exist_ok=True)
    fpath = path / f"rollout-2026-08-20T10-00-00-{session_id}.jsonl"
    fpath.write_text("".join(json.dumps(r) + "\n" for r in records))
    return fpath


def test_summary_extracts_first_real_user_prompt(tmp_path: Path) -> None:
    sid = "01a014ef-679a-7e53-9129-decaba38336f"
    _write_codex_rollout_with_records(tmp_path, sid, "/srv/app", [
        {"timestamp": "2026-08-20T10:00:00Z", "type": "session_meta", "payload": {"id": sid, "cwd": "/srv/app"}},
        {"timestamp": "2026-08-20T10:01:00Z", "type": "event_msg", "payload": {"role": "user", "content": [{"type": "input_text", "text": "<environment_context>\n  <cwd>/srv/app</cwd>"}]}},
        {"timestamp": "2026-08-20T10:02:00Z", "type": "event_msg", "payload": {"role": "user", "content": [{"type": "input_text", "text": "fix the login bug"}]}},
        {"timestamp": "2026-08-20T10:30:00Z", "type": "event_msg", "payload": {"role": "assistant", "content": [{"type": "output_text", "text": "done"}]}},
    ])
    sessions = list_sessions(home=lambda: tmp_path)
    assert len(sessions) == 1
    r = sessions[0]
    assert r.summary == "fix the login bug"
    assert r.first_activity == "2026-08-20T10:00:00Z"
    assert r.last_activity == "2026-08-20T10:30:00Z"
    assert r.record_count == 4


def test_summary_skips_codex_agent_history_preamble(tmp_path: Path) -> None:
    sid = "01a014ef-679a-7e53-9129-decaba38336f"
    _write_codex_rollout_with_records(tmp_path, sid, "/srv/app", [
        {"timestamp": "2026-08-20T10:00:00Z", "type": "session_meta", "payload": {"id": sid, "cwd": "/srv/app"}},
        {"timestamp": "2026-08-20T10:01:00Z", "type": "event_msg", "payload": {"role": "user", "content": [{"type": "input_text", "text": "The following is the Codex agent history whose request action you are assessing."}]}},
        {"timestamp": "2026-08-20T10:02:00Z", "type": "event_msg", "payload": {"role": "user", "content": [{"type": "input_text", "text": "review this PR"}]}},
    ])
    sessions = list_sessions(home=lambda: tmp_path)
    assert sessions[0].summary == "review this PR"


def test_summary_extracts_claude_style_nested_message(tmp_path: Path) -> None:
    """claude nests user text under message.content (list of {type,text})."""
    sid = "8c9c7be7-0aa4-4d8f-85c5-5cab292766f0"
    _write_generic_jsonl_session(tmp_path, "claude", sid, "/srv/cl", records=[
        {"type": "mode", "sessionId": sid, "timestamp": "2026-07-10T07:00:00Z"},
        {"type": "user", "sessionId": sid, "timestamp": "2026-07-10T07:01:00Z",
         "message": {"content": [{"type": "text", "text": "build the dashboard"}]}},
    ])
    sessions = list_sessions(home=lambda: tmp_path)
    assert sessions[0].summary == "build the dashboard"
    assert sessions[0].first_activity == "2026-07-10T07:00:00Z"
    assert sessions[0].last_activity == "2026-07-10T07:01:00Z"


def test_summary_empty_when_no_real_prompt(tmp_path: Path) -> None:
    """A session with only assistant/metadata records has an empty summary."""
    sid = "01a014ef-679a-7e53-9129-decaba38336f"
    _write_codex_rollout_with_records(tmp_path, sid, "/srv/app", [
        {"timestamp": "2026-08-20T10:00:00Z", "type": "session_meta", "payload": {"id": sid, "cwd": "/srv/app"}},
        {"timestamp": "2026-08-20T10:01:00Z", "type": "event_msg", "payload": {"role": "assistant", "content": [{"type": "output_text", "text": "hello"}]}},
    ])
    sessions = list_sessions(home=lambda: tmp_path)
    assert sessions[0].summary == ""
    assert sessions[0].record_count == 2


# ---------------------------------------------------------------------------
# pi summary extraction (message.content[].text, nested under "message")
# ---------------------------------------------------------------------------

def _write_pi_nested_message_session(home: Path, session_id: str, cwd: str, first_msg: str) -> None:
    """Write a pi-style session where the user turn is nested under
    record["message"]["role"]=="user" + record["message"]["content"][].text."""
    slug = "--" + cwd.strip("/").replace("/", "-") + "--"
    sdir = home / ".pi/agent/sessions" / slug
    sdir.mkdir(parents=True, exist_ok=True)
    records = [
        {"type": "session", "id": session_id, "cwd": cwd, "timestamp": "2026-08-20T10:00:00Z"},
        {"type": "message", "id": "m1", "timestamp": "2026-08-20T10:01:00Z",
         "message": {"role": "user", "content": [{"type": "text", "text": first_msg}]}},
    ]
    (sdir / f"2026-08-20T10-00-00-000Z_{session_id}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records))


def test_pi_summary_extracts_nested_message_content(tmp_path: Path) -> None:
    """pi nests user text under record.message.content[].text; the summary
    scanner must read it there, not at the top level."""
    sid = "01a01518-be23-71da-a6c9-df192b278fa6"
    _write_pi_nested_message_session(tmp_path, sid, "/srv/api", "=== IP: 111.228.37.42 ===")
    sessions = list_sessions(home=lambda: tmp_path)
    pi = [r for r in sessions if r.tool == "pi"]
    assert len(pi) == 1
    assert pi[0].summary == "=== IP: 111.228.37.42 ==="
