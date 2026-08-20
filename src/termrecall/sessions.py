# SPDX-License-Identifier: GPL-3.0-or-later
"""Universal session-store readers for agent CLI tools.

Each reader introspects a tool's on-disk session store and returns a list of
``SessionRecord`` objects keyed by cwd.  This lets TermRecall find the right
session to resume for any recorded working directory, deterministically,
without relying on cwd-mtime heuristics or capture-time session-id recording.

A session-store reader is the core of the resume engine: it answers "given
this cwd, which session(s) did this tool create here, and which is the most
recent?"  The probe (adapters/resume.py) then builds the resume argv from that.

Supported stores (verified 2026-08-20):
  - codex: ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl (session_meta.payload)
  - pi:    ~/.pi/agent/sessions/<cwd-slug>/*.jsonl (filename UUID)
  - opencode: ~/.local/share/opencode/opencode.db (session table)
  - hermes: ~/.hermes/state.db (sessions table)

Each reader is a pure function over the filesystem/DB; no tool subprocess is
invoked, so there is no attack surface and no network dependency.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """One session discovered in a tool's session store."""

    tool: str          # e.g. "codex"
    session_id: str    # the tool's own session identifier
    cwd: str           # absolute working directory the session ran in
    title: str         # human-readable title/summary (may be "")
    last_activity: str  # ISO-8601 timestamp (or "" if unknown)
    source_path: str   # path to the store entry (file or db)


class HomeResolver(Protocol):
    def __call__(self) -> Path: ...


def _default_home() -> Path:
    return Path.home()


# ---------------------------------------------------------------------------
# codex
# ---------------------------------------------------------------------------

_CODEX_SESSIONS_DIR = ".codex/sessions"
# rollout-<ISO-ts>-<uuid>.jsonl  — the UUID is the session id.
_CODEX_ROLLOUT_RE = re.compile(
    r"rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:-\d{3}Z?)?-?"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"\.jsonl$"
)


def _read_codex_sessions(home: Path) -> list[SessionRecord]:
    """Read codex session rollout files and extract id + cwd from session_meta."""
    root = home / _CODEX_SESSIONS_DIR
    records: list[SessionRecord] = []
    if not root.is_dir():
        return records
    for path in root.rglob("rollout-*.jsonl"):
        match = _CODEX_ROLLOUT_RE.search(path.name)
        if match is None:
            continue
        file_session_id = match.group(1)
        try:
            with path.open("rb") as handle:
                first_line = handle.readline()
            if not first_line:
                continue
            meta = json.loads(first_line)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict) or meta.get("type") != "session_meta":
            continue
        payload = meta.get("payload")
        if not isinstance(payload, dict):
            continue
        session_id = str(payload.get("id") or file_session_id)
        cwd = str(payload.get("cwd") or "")
        # codex stores cwd as a file:// URI or a bare path; normalize.
        if cwd.startswith("file://"):
            cwd = cwd[len("file://"):]
        title = str(payload.get("thread_name") or "")
        last_activity = str(meta.get("timestamp") or "")
        records.append(SessionRecord(
            "codex", session_id, cwd, title, last_activity, str(path)
        ))
    return records


# ---------------------------------------------------------------------------
# pi
# ---------------------------------------------------------------------------

_PI_SESSIONS_DIR = ".pi/agent/sessions"
# <ISO-ts>_<uuid>.jsonl
_PI_SESSION_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T[\d-]+Z)_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$"
)


def _slug_to_path(slug: str) -> str:
    """Convert a pi session-dir slug back to an absolute path.

    pi encodes ``/home/user/my dir`` as ``--home-user-my-dir--`` (leading ``--``,
    ``/`` → ``-``, trailing ``--``).  This reverses it.
    """
    s = slug
    if s.startswith("--"):
        s = s[2:]
    if s.endswith("--"):
        s = s[:-2]
    return "/" + s.replace("-", "/") if s else "/"


def _read_pi_sessions(home: Path) -> list[SessionRecord]:
    """Read pi session directories (cwd-keyed) and extract UUIDs from filenames."""
    root = home / _PI_SESSIONS_DIR
    records: list[SessionRecord] = []
    if not root.is_dir():
        return records
    for session_dir in root.iterdir():
        if not session_dir.is_dir():
            continue
        cwd = _slug_to_path(session_dir.name)
        for path in session_dir.iterdir():
            match = _PI_SESSION_RE.search(path.name)
            if match is None:
                continue
            timestamp, session_id = match.group(1), match.group(2)
            records.append(SessionRecord(
                "pi", session_id, cwd, "", timestamp, str(path)
            ))
    return records


# ---------------------------------------------------------------------------
# opencode
# ---------------------------------------------------------------------------

_OPENCODE_DB = ".local/share/opencode/opencode.db"


def _read_opencode_sessions(home: Path) -> list[SessionRecord]:
    """Read opencode's SQLite session table (directory column = cwd)."""
    db = home / _OPENCODE_DB
    records: list[SessionRecord] = []
    if not db.is_file():
        return records
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, directory, title, updated_at FROM session "
            "WHERE directory IS NOT NULL ORDER BY updated_at DESC"
        )
        for row in cursor.fetchall():
            records.append(SessionRecord(
                "opencode",
                str(row["id"]),
                str(row["directory"]),
                str(row["title"] or ""),
                str(row["updated_at"] or ""),
                str(db),
            ))
        conn.close()
    except (sqlite3.Error, OSError):
        pass
    return records


# ---------------------------------------------------------------------------
# hermes
# ---------------------------------------------------------------------------

_HERMES_DB = ".hermes/state.db"


def _read_hermes_sessions(home: Path) -> list[SessionRecord]:
    """Read hermes' SQLite session store."""
    db = home / _HERMES_DB
    records: list[SessionRecord] = []
    if not db.is_file():
        return records
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # hermes schema may vary; try common column names.
        try:
            cursor.execute(
                "SELECT id, cwd, title, updated_at FROM sessions "
                "WHERE cwd IS NOT NULL ORDER BY updated_at DESC"
            )
        except sqlite3.OperationalError:
            cursor.execute(
                "SELECT id, directory as cwd, title, updated_at FROM sessions "
                "WHERE directory IS NOT NULL ORDER BY updated_at DESC"
            )
        for row in cursor.fetchall():
            records.append(SessionRecord(
                "hermes",
                str(row["cwd"]),
                str(row["cwd"]),
                str(row["title"] or ""),
                str(row["updated_at"] or ""),
                str(db),
            ))
        conn.close()
    except (sqlite3.Error, OSError):
        pass
    return records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_READERS = {
    "codex": _read_codex_sessions,
    "pi": _read_pi_sessions,
    "opencode": _read_opencode_sessions,
    "hermes": _read_hermes_sessions,
}


def list_sessions(
    tool: str | None = None,
    *,
    home: HomeResolver = _default_home,
) -> list[SessionRecord]:
    """Enumerate sessions across all supported tools (or one tool).

    Returns every session discovered in the tool(s)' on-disk store.  No
    subprocess is spawned; this is a pure read of files/SQLite.
    """
    home_path = home()
    tools = [tool] if tool else list(_READERS)
    records: list[SessionRecord] = []
    for name in tools:
        reader = _READERS.get(name)
        if reader is not None:
            records.extend(reader(home_path))
    return records


def find_sessions_for_cwd(
    cwd: str,
    *,
    tool: str | None = None,
    home: HomeResolver = _default_home,
) -> list[SessionRecord]:
    """Find sessions that ran in ``cwd``, most-recent first.

    Handles the multi-session case: if a user ran codex in the same directory
    multiple times, all matching sessions are returned ordered by last
    activity (descending).  The caller can then resume the most recent, or
    offer the user a picker.
    """
    target = os.path.normpath(cwd)
    matching = [
        r for r in list_sessions(tool=tool, home=home)
        if r.cwd and os.path.normpath(r.cwd) == target
    ]
    matching.sort(key=lambda r: r.last_activity or "", reverse=True)
    return matching


def find_active_session_id(tool: str) -> str | None:
    """Find the currently-running session id for ``tool`` via env vars.

    codex exposes ``CODEX_SESSION_ID`` in the process environment.  Other tools
    don't expose a live env var; for them this returns None and the caller
    falls back to ``find_sessions_for_cwd``.
    """
    env_var = {
        "codex": "CODEX_SESSION_ID",
    }.get(tool)
    if env_var is None:
        return None
    return os.environ.get(env_var)
