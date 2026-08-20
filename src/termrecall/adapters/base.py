# SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from termrecall.model import Outcome, RestorationLevel

# Centralized launch wrapper.  ``exec "$@"`` runs the approved command tokens
# directly as an argv (bash never re-parses them as shell syntax), which
# eliminates the double-shell-evaluation bypass that a login-shell wrapper
# enabled.  After the command exits its status is captured and an interactive
# shell is dropped into.
_COMMAND_WRAPPER = 'exec "$@"; status=$?; exec bash -i'


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    tabs: bool
    directories: bool
    windows: bool
    panes: bool
    scrollback: bool
    command_launch: bool
    deterministic_grouping: bool


@dataclass(frozen=True, slots=True)
class LaunchItem:
    item_id: str
    cwd: Path
    approved_command: str | None


@dataclass(frozen=True, slots=True)
class LaunchAction:
    item_ids: Sequence[str]
    argv: Sequence[str]
    level: RestorationLevel
    warnings: Sequence[str]


@runtime_checkable
class TerminalAdapter(Protocol):
    def detect(self) -> bool: ...

    def capabilities(self) -> AdapterCapabilities: ...

    def plan(self, items: Sequence[LaunchItem]) -> Sequence[LaunchAction]: ...

    def execute(
        self, actions: Sequence[LaunchAction], attempt_id: str
    ) -> Sequence[Outcome]: ...


# ---------------------------------------------------------------------------
# Multi-tab grouping helpers
# ---------------------------------------------------------------------------

# Per-tab terminal options built by adapters.  ``--window-token`` and
# ``--tab-token`` are the argv tokens that begin a new window / tab for the
# terminal (e.g. ("--window",) for gnome/xfce4, () for kitty/ghostty which use
# a session file).  ``tab_options(item)`` returns the per-tab argv (working-dir
# + command) so a single grouped launch emits one window with N tabs.
import shlex


def _tab_argv_for(item: LaunchItem, *, wrapper: str, wrapper_args: tuple[str, ...]) -> tuple[str, ...]:
    """Build the per-tab argv fragment for one LaunchItem.

    Emits ``bash -c <wrapper> bash <cmd tokens>`` so the approved command runs
    directly via ``exec "$@"``.  Returns an empty tuple when the cwd is unusable
    (the adapter marks the item UNAVAILABLE instead).
    """
    if not item.cwd.is_absolute() or not item.cwd.is_dir():
        return ()
    argv: list[str] = []
    if item.approved_command is not None:
        argv += ("bash", "-c", wrapper, *wrapper_args, *shlex.split(item.approved_command))
    return tuple(argv)
