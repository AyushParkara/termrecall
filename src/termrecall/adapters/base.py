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
