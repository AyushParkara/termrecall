# SPDX-License-Identifier: GPL-3.0-or-later
"""Dual restore backends with a graceful fallback chain.

TermRecall can discover restorable sessions from two sources, tried in order:

1. **capture** — the background server's recorded workspace (knows the exact
   open-tab set at crash time, but only for sessions begun after install and
   only while the server is running).
2. **timestamp** — the agent tools' own on-disk session stores, grouped by
   working directory and sorted by last-activity (works retroactively, needs
   nothing running, but shows *candidates* per folder rather than the exact
   open tabs).

``--backend auto`` (the default) tries capture first and falls back to
timestamp when the server is unreachable or has no workspace.  This means no
single failing component stops restore: if the daemon is down, timestamp takes
over; if a tool's store is unreadable, that folder is simply skipped.  An
explicit ``--backend capture`` or ``--backend timestamp`` pins one source.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from termrecall.model import CommandDisposition, CommandRecord, RestorationLevel, ShellRecord
from termrecall.sessions import SessionRecord, list_sessions

from datetime import datetime, timezone


def relative_time(ts: str) -> str:
    """Render an ISO timestamp as a human 'ago' string (e.g. '3m ago').

    Empty/unknown timestamps become 'unknown'.  Never raises.
    """
    if not ts:
        return "unknown"
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        secs = (datetime.now(timezone.utc) - t).total_seconds()
    except (ValueError, TypeError):
        return "unknown"
    if secs < 0:
        return "just now"
    if secs < 60:
        return f"{int(secs)}s ago"
    if secs < 3600:
        return f"{int(secs / 60)}m ago"
    if secs < 86400:
        return f"{int(secs / 3600)}h ago"
    return f"{int(secs / 86400)}d ago"


class Backend(StrEnum):
    AUTO = "auto"
    CAPTURE = "capture"
    TIMESTAMP = "timestamp"


@dataclass(frozen=True, slots=True)
class RestoreCandidate:
    """A single restorable session discovered by any backend.

    Mirrors the fields the restore UI needs, so both backends produce the same
    shape and the CLI never has to know which source it came from.
    """
    item_id: str            # stable id (tool + session_id) for selection
    tool: str
    session_id: str
    cwd: str
    summary: str
    first_activity: str
    last_activity: str
    resume_command: str     # the argv the server/CLI resolved, or ""
    source: str             # "capture" | "timestamp"


def _resume_command_for(tool: str, session_id: str | None) -> str:
    """Build the resume argv for a tool+session (best-effort; empty on failure)."""
    try:
        from termrecall.adapters.resume import build_resume_argv, find_resume_adapter
        match = find_resume_adapter(tool)
        if match is None:
            return ""
        return " ".join(build_resume_argv(match, session_id))
    except Exception:
        return ""


def candidates_from_timestamp(home: Path) -> list[RestoreCandidate]:
    """Discover restorable sessions from the tools' own stores, no background.

    Groups all sessions by (tool, cwd) and picks the most-recent per group, so
    each working directory contributes at most one default candidate (the one
    you most likely had open).  All other sessions in that folder are still
    available to the picker, which lists them by recency.
    """
    try:
        sessions = list_sessions(home=lambda: home)
    except (OSError, ValueError):
        return []
    # Group by (tool, cwd); keep the most-recent in each group as the default.
    by_group: dict[tuple[str, str], list[SessionRecord]] = {}
    for rec in sessions:
        if not rec.cwd:
            continue
        by_group.setdefault((rec.tool, rec.cwd), []).append(rec)
    candidates: list[RestoreCandidate] = []
    for (tool, cwd), group in by_group.items():
        group.sort(key=lambda r: r.last_activity or "", reverse=True)
        # Surface EVERY session (not just the most-recent) so multiple tabs in
        # the same folder all appear — if you had 2 pi tabs in api_scraping,
        # both show up.  The most-recent is first in its group.
        for rec in group:
            candidates.append(RestoreCandidate(
                item_id=f"{tool}-{rec.session_id[:12]}",
                tool=tool,
                session_id=rec.session_id,
                cwd=cwd,
                summary=rec.summary,
                first_activity=rec.first_activity,
                last_activity=rec.last_activity,
                resume_command=_resume_command_for(tool, rec.session_id),
                source="timestamp",
            ))
    # Most-recently-active first.
    candidates.sort(key=lambda c: c.last_activity or "", reverse=True)
    return candidates


def candidates_from_capture(workspace_items) -> list[RestoreCandidate]:
    """Convert a capture-backend RecoveryWorkspace into candidates.

    ``workspace_items`` is the sequence of RecoveryItem the server reconciled.
    Each becomes a candidate carrying the server-resolved resume_command.
    """
    candidates: list[RestoreCandidate] = []
    if workspace_items is None:
        return candidates
    for item in workspace_items:
        try:
            command = item.shell.command
            tool = ""
            session_id = ""
            if command is not None and command.executable:
                from termrecall.classifier import _parse_one_simple_command
                tool = _parse_one_simple_command(command.executable).executable
            candidates.append(RestoreCandidate(
                item_id=item.item_id,
                tool=tool,
                session_id=session_id,
                cwd=str(item.directory),
                summary="",
                first_activity="",
                last_activity="",
                resume_command=getattr(item, "_resume_command", "") or "",
                source="capture",
            ))
        except Exception:
            continue
    return candidates


def resolve_candidates(
    backend: Backend,
    home: Path,
    capture_workspace_items=None,
) -> tuple[list[RestoreCandidate], str]:
    """Run the fallback chain and return (candidates, source_used).

    Never raises: if the preferred source fails or is empty, it falls through
    to the next so one broken component never stops restore.  Returns the
    source name actually used ("capture" / "timestamp") for diagnostics.
    """
    if backend is Backend.TIMESTAMP:
        return candidates_from_timestamp(home), "timestamp"
    if backend is Backend.CAPTURE:
        if capture_workspace_items is not None:
            captured = candidates_from_capture(capture_workspace_items)
            if captured:
                return captured, "capture"
        # Even when pinned to capture, fall back to timestamp rather than
        # returning nothing — explicit-but-resilient, not brittle.
        return candidates_from_timestamp(home), "timestamp"
    # auto: capture first, timestamp on failure/empty.
    if capture_workspace_items is not None:
        captured = candidates_from_capture(capture_workspace_items)
        if captured:
            return captured, "capture"
    return candidates_from_timestamp(home), "timestamp"
