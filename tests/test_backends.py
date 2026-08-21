# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the dual-backend restore chain (capture → timestamp fallback)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from termrecall.backends import (
    Backend,
    RestoreCandidate,
    candidates_from_capture,
    candidates_from_timestamp,
    relative_time,
    resolve_candidates,
)


def _write_codex_rollout(home: Path, session_id: str, cwd: str, *, ts: str = "2026-08-20T10:00:00Z") -> None:
    path = home / ".codex/sessions/2026/08/20"
    path.mkdir(parents=True, exist_ok=True)
    meta = {"timestamp": ts, "type": "session_meta", "payload": {"id": session_id, "cwd": cwd}}
    (path / f"rollout-2026-08-20T10-00-00-{session_id}.jsonl").write_text(json.dumps(meta) + "\n")


def test_timestamp_backend_discovers_sessions(tmp_path: Path) -> None:
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    cands = candidates_from_timestamp(tmp_path)
    assert len(cands) == 1
    assert cands[0].tool == "codex"
    assert cands[0].cwd == "/srv/app"
    assert cands[0].session_id == "01a014ef-679a-7e53-9129-decaba38336f"
    assert cands[0].source == "timestamp"


def test_timestamp_backend_picks_most_recent_per_folder(tmp_path: Path) -> None:
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app", ts="2026-08-20T09:00:00Z")
    _write_codex_rollout(tmp_path, "01a014f7-934a-7dd2-95fc-5ecfbb2eeafc", "/srv/app", ts="2026-08-20T12:00:00Z")
    cands = candidates_from_timestamp(tmp_path)
    # One candidate per folder, most-recent selected.
    assert len(cands) == 1
    assert cands[0].session_id == "01a014f7-934a-7dd2-95fc-5ecfbb2eeafc"


def test_timestamp_backend_never_crashes_on_missing_store(tmp_path: Path) -> None:
    # No stores at all — returns empty, doesn't raise.
    assert candidates_from_timestamp(tmp_path) == []


def test_relative_time_renders_ago_strings() -> None:
    assert relative_time("") == "unknown"
    assert relative_time("not-a-date") == "unknown"
    # Recent (a few seconds ago) → just now or Ns ago.
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    assert "ago" in relative_time(recent) or relative_time(recent) == "just now"


def test_auto_falls_back_to_timestamp_when_capture_empty(tmp_path: Path) -> None:
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    cands, source = resolve_candidates(Backend.AUTO, tmp_path, capture_workspace_items=None)
    assert source == "timestamp"
    assert len(cands) == 1


def test_auto_uses_capture_when_available(tmp_path: Path) -> None:
    # A fake capture workspace item.
    class FakeShell:
        command = None
    class FakeItem:
        item_id = "capture-1"
        shell = FakeShell()
        directory = Path("/srv/captured")
    cands, source = resolve_candidates(Backend.AUTO, tmp_path, capture_workspace_items=[FakeItem()])
    assert source == "capture"
    assert len(cands) == 1
    assert cands[0].cwd == "/srv/captured"


def test_capture_pinned_falls_back_to_timestamp(tmp_path: Path) -> None:
    # --backend capture but server has no workspace → timestamp, not nothing.
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    cands, source = resolve_candidates(Backend.CAPTURE, tmp_path, capture_workspace_items=None)
    assert source == "timestamp"
    assert len(cands) == 1


def test_timestamp_pinned_ignores_capture(tmp_path: Path) -> None:
    _write_codex_rollout(tmp_path, "01a014ef-679a-7e53-9129-decaba38336f", "/srv/app")
    class FakeItem:
        item_id = "capture-1"
        class shell: command = None
        directory = Path("/srv/captured")
    cands, source = resolve_candidates(Backend.TIMESTAMP, tmp_path, capture_workspace_items=[FakeItem()])
    assert source == "timestamp"
    assert all(c.source == "timestamp" for c in cands)
