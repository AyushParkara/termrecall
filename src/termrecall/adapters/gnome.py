# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence

from termrecall.adapters.base import (
    AdapterCapabilities,
    LaunchAction,
    LaunchItem,
)
from termrecall.model import Outcome, OutcomeKind, RestorationLevel

_COMMAND_WRAPPER = (
    'command=$1; bash -lc "$command"; status=$?; exec bash -i; exit "$status"'
)
_GROUPING_WARNING = "grouping unsupported"
_UNAVAILABLE_WARNING = "terminal executable unavailable"
# GNOME Terminal launch must return promptly so restore requests cannot hang forever.
DEFAULT_LAUNCH_TIMEOUT = 10.0

Runner = Callable[..., subprocess.CompletedProcess[str]]
Resolver = Callable[[str], str | None]


class GnomeTerminalAdapter:
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
        return self._which("gnome-terminal") is not None

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            tabs=True,
            directories=True,
            windows=False,
            panes=False,
            scrollback=False,
            command_launch=True,
            deterministic_grouping=False,
        )

    def plan(self, items: Sequence[LaunchItem]) -> Sequence[LaunchAction]:
        executable = self._which("gnome-terminal")
        actions: list[LaunchAction] = []
        for item in items:
            if not item.cwd.is_absolute() or not item.cwd.is_dir():
                raise ValueError("cwd must be an absolute existing directory")
            if executable is None:
                actions.append(
                    LaunchAction(
                        (item.item_id,),
                        (),
                        RestorationLevel.UNAVAILABLE,
                        (_UNAVAILABLE_WARNING,),
                    )
                )
                continue

            argv: tuple[str, ...] = (
                executable,
                "--working-directory",
                str(item.cwd),
            )
            level = RestorationLevel.PARTIAL
            if item.approved_command is not None:
                argv += (
                    "--",
                    "bash",
                    "-lc",
                    _COMMAND_WRAPPER,
                    "termrecall",
                    item.approved_command,
                )
                level = RestorationLevel.RECONSTRUCTED
            actions.append(
                LaunchAction(
                    (item.item_id,), argv, level, (_GROUPING_WARNING,)
                )
            )
        return tuple(actions)

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
