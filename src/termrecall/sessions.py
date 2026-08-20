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
    summary: str       # first real user prompt (truncated) — the richest context
    first_activity: str  # ISO-8601 timestamp of the first record (or "")
    last_activity: str   # ISO-8601 timestamp of the last record (or "")
    record_count: int  # number of records in the session (rough size indicator)
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
        records.append(_make_file_record("codex", session_id, path, cwd, title))
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
    """Read pi session directories and extract UUIDs + the REAL cwd.

    pi stores sessions under ``~/.pi/agent/sessions/<cwd-slug>/`` where the slug
    collapses both ``/`` and ``_`` to ``-`` — so the slug is AMBIGUOUS (the dir
    ``ideas_to_practical_implementation`` and ``ideas/to/practical/implementation``
    produce the same slug).  We therefore never decode the slug back to a path;
    instead we read the authoritative cwd from inside each session file (pi
    records the real cwd in the first record), falling back to the filename UUID
    only when the file has no parseable cwd.
    """
    root = home / _PI_SESSIONS_DIR
    records: list[SessionRecord] = []
    if not root.is_dir():
        return records
    for session_dir in root.iterdir():
        if not session_dir.is_dir():
            continue
        for path in session_dir.iterdir():
            match = _PI_SESSION_RE.search(path.name)
            if match is None:
                continue
            # Single-pass scan reads id+cwd+summary from the file content. The
            # filename's timestamp+uuid give us the session id as a fallback.
            session_id_file = match.group(2)
            session_id, cwd, summary, first_ts, last_ts, count = _scan_session_full(path)
            if session_id is None:
                session_id = session_id_file
            # pi's cwd is reliably encoded in the directory slug when the file
            # itself carries no cwd record.  The slug is ambiguous (_ and /
            # both become -), so prefer the file's cwd; fall back to the slug
            # only when the file has none.
            if not cwd:
                cwd = _slug_to_path(session_dir.name)
            records.append(SessionRecord(
                tool="pi", session_id=session_id, cwd=cwd or "",
                title="", summary=summary, first_activity=first_ts,
                last_activity=last_ts, record_count=count, source_path=str(path),
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
                "",
                "",
                str(row["updated_at"] or ""),
                0,
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
                "",
                "",
                str(row["updated_at"] or ""),
                0,
                str(db),
            ))
        conn.close()
    except (sqlite3.Error, OSError):
        pass
    return records


# ---------------------------------------------------------------------------
# Generic discovery engine (auto-detects unknown agent tools)
# ---------------------------------------------------------------------------

# Pattern for a session-id-bearing filename: a UUID (v1-v8) anywhere in it.
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
# Directories under ~ that are NOT agent session stores even if they look like one.
_NON_AGENT_DOTDIRS = {
    ".cache", ".config", ".local", ".gnupg", ".ssh", ".bashrc",
    ".mozilla", ".thunderbird", ".steam", ".wine", ".npm", ".cargo",
    ".rustup", ".nvm", ".pyenv", ".rbenv", ".gradle", ".android", ".java",
    ".docker", ".vscode", ".idea", ".git", ".pip", ".conda", ".virtualenvs",
    ".fontconfig", ".pki", ".local/share", ".local/state",
}
# Candidate session files: .jsonl with a UUID in the name, under a hidden dir.
_SESSION_FILE_RE = re.compile(r".*\.jsonl$", re.I)
import time as _time

# Cache list_sessions results keyed by home path; invalidated by mtime of the
# home dir's parent (cheap stat).  Prevents re-scanning 300+ files on every
# per-item find_sessions_for_cwd call during a single restore.
_SESSION_CACHE: dict[tuple[str, float], list[SessionRecord]] = {}
_SESSION_CACHE_TTL = 5.0  # seconds; a restore runs in well under this


# Maximum records to scan when extracting a summary (first user prompt) + the
# full timestamp span + record count.  200 is enough to find a real user prompt
# while staying cheap (readline + json on small lines).
_SUMMARY_SCAN_LIMIT = 40
# Truncate the summary so the restore UI stays scannable.
_SUMMARY_MAX_CHARS = 160


def _extract_text(value: object) -> str:
    """Pull a human-readable text string out of a content field (str or list)."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("text") or item.get("input_text")
                if isinstance(text, str):
                    parts.append(text)
        return " ".join(parts)
    return ""


def _is_real_prompt(text: str) -> bool:
    """Heuristic: skip tool-generated context/preamble blocks.

    Skips environment wrappers (``<environment_context``), any other XML-ish
    tool preambles (leading ``<``), and known codex internal preambles about
    agent history, so the summary is the first genuine user instruction.
    """
    if not text:
        return False
    stripped = text.lstrip()
    if stripped.startswith("<environment_context") or stripped.startswith("<"):
        return False
    # codex injects an agent-history preamble on subagent/assess turns.
    lower = stripped[:80].casefold()
    if lower.startswith("the following is the codex agent history"):
        return False
    if lower.startswith("the following is the"):
        return False
    # Skip empty/whitespace or pure-metadata.
    return len(stripped.strip()) >= 3


def _summarize_session_file(path: Path) -> tuple[str, str, str, int]:
    """Scan a JSONL session file and return (summary, first_ts, last_ts, count).

    The summary is the first real user message.  Works across any agent tool
    that stores user prompts as JSONL records with a recognizable role/content.
    """
    summary = ""
    first_ts = ""
    last_ts = ""
    count = 0
    try:
        with path.open("rb") as handle:
            for _ in range(_SUMMARY_SCAN_LIMIT):
                line = handle.readline()
                if not line:
                    break
                count += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                ts = record.get("timestamp")
                if isinstance(ts, str):
                    if not first_ts:
                        first_ts = ts
                    last_ts = ts
                if not summary:
                    payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
                    role = payload.get("role") or record.get("role")
                    # claude-code marks user turns with type=="user" (no role field).
                    if role is None and record.get("type") == "user":
                        role = "user"
                    if role == "user":
                        # Gather text from payload.content (codex) or
                        # record.message.content (claude).
                        text = _extract_text(payload.get("content"))
                        msg = record.get("message")
                        if isinstance(msg, dict) and not text:
                            text = _extract_text(msg.get("content"))
                        # Skip tool-generated context blocks and keep scanning
                        # for the first REAL user prompt.
                        if _is_real_prompt(text):
                            summary = text[:_SUMMARY_MAX_CHARS]
    except (OSError, json.JSONDecodeError):
        pass
    return summary, first_ts, last_ts, count


def _scan_session_full(path: Path) -> tuple[str | None, str | None, str, str, str, int]:
    """Single-pass scan: extract session_id, cwd, summary, timestamps, count.

    Combines what _scan_first_record_for_session_cwd and _summarize_session_file
    did separately, so each file is read exactly once.  Returns
    (session_id, cwd, summary, first_ts, last_ts, count).
    """
    session_id: str | None = None
    cwd: str | None = None
    summary = ""
    first_ts = ""
    last_ts = ""
    count = 0
    try:
        with path.open("rb") as handle:
            for _ in range(_SUMMARY_SCAN_LIMIT):
                line = handle.readline()
                if not line:
                    break
                count += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                ts = record.get("timestamp")
                if isinstance(ts, str):
                    if not first_ts:
                        first_ts = ts
                    last_ts = ts
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
                # session id
                if session_id is None:
                    for key in ("sessionId", "session_id", "id"):
                        value = payload.get(key)
                        if isinstance(value, str) and _UUID_RE.fullmatch(value):
                            session_id = value
                            break
                    nested = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
                    if session_id is None and isinstance(nested.get("id"), str) and _UUID_RE.fullmatch(nested["id"]):
                        session_id = nested["id"]
                # cwd
                if cwd is None:
                    for key in ("cwd", "directory", "workdir", "project_path"):
                        value = payload.get(key)
                        if isinstance(value, str):
                            if value.startswith("file://"):
                                value = value[len("file://"):]
                            if value.startswith("/"):
                                cwd = value
                                break
                # summary (first real user prompt)
                if not summary:
                    role = payload.get("role") or record.get("role")
                    if role is None and record.get("type") == "user":
                        role = "user"
                    if role == "user":
                        text = _extract_text(payload.get("content"))
                        msg = record.get("message")
                        if isinstance(msg, dict) and not text:
                            text = _extract_text(msg.get("content"))
                        if _is_real_prompt(text):
                            summary = text[:_SUMMARY_MAX_CHARS]
                if session_id and cwd and summary:
                    break
    except (OSError, json.JSONDecodeError):
        pass
    return session_id, cwd, summary, first_ts, last_ts, count


def _make_file_record(tool: str, session_id: str, path: Path, cwd: str, title: str = "") -> SessionRecord:
    """Build a SessionRecord from a JSONL session file with rich metadata."""
    summary, first_ts, last_ts, count = _summarize_session_file(path)
    return SessionRecord(
        tool=tool,
        session_id=session_id,
        cwd=cwd,
        title=title,
        summary=summary,
        first_activity=first_ts,
        last_activity=last_ts,
        record_count=count,
        source_path=str(path),
    )



def _scan_first_record_for_session_cwd(path: Path) -> tuple[str | None, str | None]:
    """Read the first JSON line of a session file; return (session_id, cwd).

    Looks for common field names across agent tools: sessionId, session_id, id
    (in a meta record), and cwd/directory/workdir.  Returns (None, None) if the
    file isn't parseable or carries no usable fields.
    """
    session_id: str | None = None
    cwd: str | None = None
    try:
        with path.open("rb") as handle:
            # Scan up to 30 records so a cwd appearing later than the id (as in
            # claude-code, whose first records are mode/permission markers) is
            # still captured. Cheap: readline + json on small lines.
            for _ in range(30):
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
                for key in ("sessionId", "session_id", "id"):
                    value = payload.get(key)
                    if isinstance(value, str) and _UUID_RE.fullmatch(value):
                        session_id = session_id or value
                nested = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
                if isinstance(nested.get("id"), str) and _UUID_RE.fullmatch(nested["id"]):
                    session_id = session_id or nested["id"]
                for key in ("cwd", "directory", "workdir", "project_path"):
                    value = payload.get(key)
                    if isinstance(value, str):
                        if value.startswith("file://"):
                            value = value[len("file://"):]
                        if value.startswith("/"):
                            cwd = cwd or value
                if session_id and cwd:
                    return session_id, cwd
    except (OSError, json.JSONDecodeError):
        pass
    return session_id, cwd


def _discover_generic_sessions(home: Path) -> list[SessionRecord]:
    """Auto-detect session stores for any agent tool under ~.

    Scans hidden directories (~/.<tool>/) for .jsonl files containing a UUID
    session id, reading the cwd from inside each file's first records.  This
    discovers tools TermRecall has never heard of (claude-code, deepseek,
    gemini-cli, aider, etc.) as long as they store sessions as JSONL with an
    embedded session id and cwd.  No per-tool code is required.
    """
    records: list[SessionRecord] = []
    for dotdir in home.iterdir():
        if not dotdir.is_dir() or not dotdir.name.startswith("."):
            continue
        if dotdir.name in _NON_AGENT_DOTDIRS:
            continue
        tool_name = dotdir.name[1:]  # strip leading "."
        # Skip very large dirs (avoid scanning .cache/.local subtrees that
        # slipped past the allowlist) and non-agent dirs.
        try:
            session_files = list(dotdir.rglob("*.jsonl"))
        except OSError:
            continue
        # Limit to avoid pathological dirs; session stores are small.
        if len(session_files) > 2000:
            continue
        for path in session_files:
            # Require a UUID in the filename or path (session-id-bearing file).
            if not _UUID_RE.search(str(path)):
                continue
            # Single-pass scan: extract id, cwd, AND summary from one read of
            # the file (the old code read it twice via two separate scanners).
            session_id, cwd, summary, first_ts, last_ts, count = _scan_session_full(path)
            if session_id is None:
                # Fall back to the UUID in the filename.
                m = _UUID_RE.search(path.name)
                if m:
                    session_id = m.group(0)
            if session_id is None:
                continue
            records.append(SessionRecord(
                tool=tool_name, session_id=session_id, cwd=cwd or "",
                title="", summary=summary, first_activity=first_ts,
                last_activity=last_ts, record_count=count, source_path=str(path),
            ))
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

    Combines the explicit per-tool readers (codex, pi, opencode, hermes) with
    a generic discovery pass that auto-detects ANY agent tool under the home
    directory (claude-code, deepseek, gemini-cli, aider, ...) by scanning for
    session-id-bearing JSONL files.  No subprocess is spawned; this is a pure
    read of files/SQLite.
    """
    home_path = home()
    tools = [tool] if tool else list(_READERS)
    records: list[SessionRecord] = []
    seen: set[tuple[str, str]] = set()
    for name in tools:
        reader = _READERS.get(name)
        if reader is not None:
            for record in reader(home_path):
                key = (record.tool, record.session_id)
                if key not in seen:
                    seen.add(key)
                    records.append(record)
    # Generic discovery: only run when not filtered to a single known tool, so
    # unknown tools (claude, deepseek, gemini, aider, ...) are auto-detected.
    if tool is None:
        for record in _discover_generic_sessions(home_path):
            key = (record.tool, record.session_id)
            if key not in seen:
                seen.add(key)
                records.append(record)
    return records


def _list_sessions_cached(home_path: Path) -> list[SessionRecord]:
    """Cached list_sessions over the full home, so a single restore (which
    calls find_sessions_for_cwd once per item) does not re-scan 300+ files
    each time.  Keyed by home-dir mtime so a freshly-written session (which
    bumps the mtime) invalidates the cache automatically.
    """
    try:
        mtime = home_path.stat().st_mtime
    except OSError:
        mtime = 0.0
    cache_key = (str(home_path), mtime)
    cached = _SESSION_CACHE.get(cache_key)
    if cached is not None:
        return cached
    records = list_sessions(home=lambda: home_path)
    _SESSION_CACHE[cache_key] = records
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
    activity (descending).  Uses a short-lived cache so that a single
    restore (which calls this once per item) does not re-scan 300+ files.
    """
    home_path = home()
    target = os.path.normpath(cwd)
    all_records = _list_sessions_cached(home_path) if tool is None else list_sessions(tool=tool, home=home)
    matching = [
        r for r in all_records
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
