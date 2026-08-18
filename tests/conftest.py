# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio

from termrecall.adapters.base import AdapterCapabilities, LaunchAction
from termrecall.bridge import Bridge
from termrecall.checkpoint import CheckpointManager
from termrecall.client import ServiceClient
from termrecall.model import (
    Outcome,
    OutcomeKind,
    ProcessIdentity,
    RestorationLevel,
    Snapshot,
)
from termrecall.processes import ProcessProbe, ProcessStatus
from termrecall.protocol import (
    DiscardRequest,
    RestoreExecuteRequest,
    RestoreListRequest,
    RestoreRetryRequest,
    SnapshotRequest,
)
from termrecall.server import TermRecallServer
from termrecall.state import EngineState
from termrecall.store import SnapshotStore

TEST_BOOT_ID = "11111111-1111-1111-1111-111111111111"
PRIOR_BOOT_ID = "22222222-2222-2222-2222-222222222222"


class DeterministicClock:
    def __init__(self) -> None:
        self.time = 0.0
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []

    def now(self) -> float:
        return self.time

    async def sleep(self, delay: float) -> None:
        if delay <= 0:
            await asyncio.sleep(0)
            return
        future = asyncio.get_running_loop().create_future()
        self._sleepers.append((self.time + delay, future))
        try:
            await future
        finally:
            self._sleepers = [item for item in self._sleepers if item[1] is not future]

    async def advance(self, delay: float) -> None:
        for _ in range(5):
            await asyncio.sleep(0)
        self.time += delay
        for due, future in tuple(self._sleepers):
            if due <= self.time and not future.done():
                future.set_result(None)
        for _ in range(10):
            await asyncio.sleep(0)

    async def wake(self) -> None:
        await self.advance(0)


class RecordingAdapter:
    name = "gnome-terminal"

    def __init__(self) -> None:
        self.actions: list[LaunchAction] = []
        self.failures: set[str] = set()

    def detect(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(True, True, False, False, False, True, False)

    def plan(self, items):
        actions = tuple(
            LaunchAction(
                (item.item_id,),
                (
                    "/usr/bin/gnome-terminal",
                    "--working-directory",
                    str(item.cwd),
                    *(() if item.approved_command is None else ("--", "bash", "-lc", "command=$1; bash -lc \"$command\"", "termrecall", item.approved_command)),
                ),
                RestorationLevel.RECONSTRUCTED
                if item.approved_command is not None
                else RestorationLevel.PARTIAL,
                ("grouping unsupported",),
            )
            for item in items
        )
        self.actions.extend(actions)
        return actions

    def execute(self, actions, attempt_id):
        del attempt_id
        return tuple(
            Outcome(
                item_id,
                OutcomeKind.FAILURE if item_id in self.failures else OutcomeKind.SUCCESS,
                f"{item_id}: " + ("launch failed" if item_id in self.failures else "launch succeeded"),
            )
            for action in actions
            for item_id in action.item_ids
        )


@dataclass
class ShellDriver:
    harness: "SystemHarness"
    id: str
    identity: ProcessIdentity
    bridge: Bridge
    command_sequence: int = 0

    async def send(self, event_type: str, **fields: object) -> bool:
        payload = json.dumps(
            {"schema_version": 1, "type": event_type, "shell_id": self.id, **fields},
            separators=(",", ":"),
        ).encode() + b"\n"
        return await asyncio.to_thread(self.bridge.process_frame, payload)

    async def command_started(self, sequence: int, command: str) -> bool:
        self.command_sequence = sequence
        return await self.send("command_started", command_sequence=sequence, command=command)

    async def explicit_exit(self) -> bool:
        return await self.send("explicit_exit")


class SystemHarness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.home = root / "home"
        self.runtime = root / "run" / "termrecall"
        self.state = root / "state" / "termrecall"
        self.config = root / "config" / "termrecall"
        for path in (self.home, self.runtime.parent, self.state.parent, self.config.parent):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.store = SnapshotStore(self.state)
        self.clock = DeterministicClock()
        self.checkpoints: CheckpointManager | None = None
        self.checkpoint_stop = asyncio.Event()
        self.checkpoint_task: asyncio.Task[None] | None = None
        self.adapter = RecordingAdapter()
        self.statuses: dict[ProcessIdentity, ProcessStatus] = {}
        self.checkpoints = CheckpointManager(
            self.store,
            lambda: self.server.state.snapshot,
            self.clock.now,
            self.clock.sleep,
        )
        self.server = TermRecallServer(
            self.runtime / "service.sock",
            os.getuid(),
            EngineState(Snapshot(1, 0, 0.0, ()), {}, 0),
            self.checkpoints,
            self.store,
            adapter=self.adapter,
            current_boot_id=TEST_BOOT_ID,
            home=self.home,
            process_probe=lambda identity: ProcessProbe(
                self.statuses.get(identity, ProcessStatus.UNKNOWN)
            ),
        )
        self.shells: list[ShellDriver] = []

    @property
    def socket_path(self) -> Path:
        return self.runtime / "service.sock"

    async def start(self) -> None:
        await self.server.start()
        self.checkpoint_task = asyncio.create_task(
            self.checkpoints.run(self.checkpoint_stop),
            name="system-harness-checkpoints",
        )
        await asyncio.sleep(0)

    async def close(self) -> None:
        for shell in self.shells:
            shell.bridge.close()
        self.checkpoint_stop.set()
        self.checkpoints._changed.set()
        if self.checkpoint_task is not None:
            await self.checkpoint_task
            self.checkpoint_task = None
        await self.server.close()

    async def register_shell(
        self, cwd: str | Path, *, boot_id: str = TEST_BOOT_ID, pid: int | None = None
    ) -> ShellDriver:
        directory = Path(cwd)
        directory.mkdir(parents=True, exist_ok=True)
        number = len(self.shells) + 1
        identity = ProcessIdentity(boot_id, pid or (10_000 + number), 20_000 + number)
        shell_id = f"shell-identifier-{number}"
        bridge = Bridge(self.socket_path, shell_id, identity)
        diagnostics: list[str] = []
        bridge.diagnostic = diagnostics.append
        shell = ShellDriver(self, shell_id, identity, bridge)
        assert await shell.send("prompt_ready", cwd=str(directory)), (
            diagnostics,
            tuple(self.server.state.registrations),
            bridge.capability,
            bridge.next_sequence,
        )
        self.statuses[identity] = ProcessStatus.ALIVE
        self.shells.append(shell)
        return shell

    def mark_process(self, identity: ProcessIdentity, status: ProcessStatus) -> None:
        self.statuses[identity] = status

    async def snapshot(self) -> None:
        response = await asyncio.to_thread(ServiceClient(self.socket_path).request, SnapshotRequest())
        assert response.durable_generation == self.server.state.dirty_generation

    async def list_recovery(self):
        return await asyncio.to_thread(ServiceClient(self.socket_path).request, RestoreListRequest())

    async def restore(self, workspace_id: str, selected, approved):
        return await asyncio.to_thread(
            ServiceClient(self.socket_path).request,
            RestoreExecuteRequest(workspace_id, tuple(selected), tuple(approved)),
        )

    async def retry(self, workspace_id: str, attempt_id: str, approved=()):
        return await asyncio.to_thread(
            ServiceClient(self.socket_path).request,
            RestoreRetryRequest(workspace_id, attempt_id, tuple(approved)),
        )

    async def discard(self, workspace_id: str):
        return await asyncio.to_thread(
            ServiceClient(self.socket_path).request, DiscardRequest(workspace_id, True)
        )


@pytest.fixture
def xdg_env(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return {
        "HOME": str(home),
        "XDG_RUNTIME_DIR": str(tmp_path / "run"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
    }


@pytest.fixture
def bash_runner():
    def run(script: str, env: dict[str, str], timeout: float = 3.0):
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-i", "-c", script],
            env={**os.environ, **env},
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    return run


@pytest_asyncio.fixture
async def system_harness(tmp_path: Path):
    harness = SystemHarness(tmp_path)
    await harness.start()
    try:
        yield harness
    finally:
        await harness.close()
