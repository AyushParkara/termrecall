# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Callable, Sequence

from termrecall.adapters.base import (
    AdapterCapabilities,
    LaunchAction,
    LaunchItem,
    _COMMAND_WRAPPER,
)
from termrecall.model import Outcome, OutcomeKind, RestorationLevel

_GROUPING_WARNING = "grouping unsupported"
_UNAVAILABLE_WARNING = "terminal executable unavailable"
# Konsole launch must return promptly so restore requests cannot hang forever.
DEFAULT_LAUNCH_TIMEOUT = 10.0

Runner = Callable[..., subprocess.CompletedProcess[str]]
Resolver = Callable[[str], str | None]


class KonsoleAdapter:
    name = "konsole"

    def __init__(
        self,
        which: Resolver,
        runner: Runner | None = None,
        *,
        launch_timeout: float = DEFAULT_LAUNCH_TIMEOUT,
    ) -> None:
        if launch_timeout <= 0:
            raise ValueError("launch timeout must be positive")
        self._which = which
        self._runner = runner
        self._launch_timeout = launch_timeout

    def detect(self) -> bool:
        return self._which("konsole") is not None

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            tabs=True,
            directories=True,
            windows=False,
            panes=False,
            scrollback=False,
            command_launch=True,
            deterministic_grouping=True,
        )

    def plan(self, items: Sequence[LaunchItem]) -> Sequence[LaunchAction]:
        executable = self._which("konsole")
        if executable is None:
            return tuple(
                LaunchAction((item.item_id,), (), RestorationLevel.UNAVAILABLE, (_UNAVAILABLE_WARNING,))
                for item in items
            )
        item_ids: list[str] = []
        argv: list[str] = [executable]
        levels: set[RestorationLevel] = set()
        missing: list[str] = []
        for index, item in enumerate(items):
            if not item.cwd.is_absolute() or not item.cwd.is_dir():
                missing.append(item.item_id)
                continue
            if index > 0:
                argv.append("--new-tab")
            argv += ("--workdir", str(item.cwd))
            if item.approved_command is not None:
                argv += ("-e", "bash", "-c", _COMMAND_WRAPPER, "bash", *shlex.split(item.approved_command))
                levels.add(RestorationLevel.RECONSTRUCTED)
            else:
                levels.add(RestorationLevel.PARTIAL)
            item_ids.append(item.item_id)
        if not item_ids:
            return tuple(
                LaunchAction((iid,), (), RestorationLevel.UNAVAILABLE, (_UNAVAILABLE_WARNING,))
                for iid in (missing or [i.item_id for i in items])
            )
        level = (
            RestorationLevel.RECONSTRUCTED if RestorationLevel.RECONSTRUCTED in levels
            else RestorationLevel.PARTIAL if RestorationLevel.PARTIAL in levels
            else RestorationLevel.UNAVAILABLE
        )
        warnings = () if not missing else tuple(f"{iid}: directory unavailable" for iid in missing)
        return (LaunchAction(tuple(item_ids), tuple(argv), level, warnings),)
    def execute(
        self, actions: Sequence[LaunchAction], attempt_id: str
    ) -> Sequence[Outcome]:
        del attempt_id
        outcomes: list[Outcome] = []
        for action in actions:
            if not action.argv:
                outcomes.extend(
                    Outcome(item_id, OutcomeKind.SKIP, f"{item_id}: terminal unavailable")
                    for item_id in action.item_ids
                )
                continue
            try:
                result = self._run(action.argv)
            except FileNotFoundError:
                outcomes.extend(
                    Outcome(item_id, OutcomeKind.SKIP, f"{item_id}: terminal unavailable")
                    for item_id in action.item_ids
                )
                continue
            except subprocess.TimeoutExpired:
                outcomes.extend(
                    Outcome(
                        item_id,
                        OutcomeKind.FAILURE,
                        f"{item_id}: terminal launch timed out; retryable",
                    )
                    for item_id in action.item_ids
                )
                continue

            kind = OutcomeKind.SUCCESS if result.returncode == 0 else OutcomeKind.FAILURE
            message = (
                "terminal launch succeeded"
                if result.returncode == 0
                else f"terminal launch failed with status {result.returncode}"
            )
            outcomes.extend(
                Outcome(item_id, kind, f"{item_id}: {message}")
                for item_id in action.item_ids
            )
        return tuple(outcomes)

    def _run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if self._runner is not None:
            return self._runner(argv, timeout=self._launch_timeout)
        return subprocess.run(
            argv,
            shell=False,
            text=True,
            capture_output=True,
            timeout=self._launch_timeout,
        )
