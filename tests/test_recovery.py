# SPDX-License-Identifier: GPL-3.0-or-later

from dataclasses import replace
from pathlib import Path

import pytest

from termrecall.adapters.base import AdapterCapabilities, LaunchAction, LaunchItem
from termrecall.model import (
    CommandDisposition,
    CommandRecord,
    Outcome,
    ProcessIdentity,
    RecoveryItemRecord,
    RecoveryRecord,
    RestorationLevel,
    ShellRecord,
    Snapshot,
    TerminationKind,
)
from termrecall.processes import ProcessProbe, ProcessStatus
from termrecall.recovery import RecoveryReason, build_attempt, reconcile, resolve_directory

BOOT_A = "11111111-1111-1111-1111-111111111111"
BOOT_B = "22222222-2222-2222-2222-222222222222"


def shell(
    *,
    shell_id: str = "shell-a",
    boot_id: str = BOOT_A,
    cwd: str = "/",
    termination: TerminationKind | None = None,
    command: CommandRecord | None = None,
) -> ShellRecord:
    return ShellRecord(
        shell_id,
        ProcessIdentity(boot_id, 42, 900),
        "gnome-terminal",
        cwd,
        3,
        command,
        termination,
    )


def snapshot(*shells: ShellRecord) -> Snapshot:
    return Snapshot(1, 7, 13.5, shells)


def test_previous_boot_bypasses_probe_and_sorts_items(tmp_path: Path) -> None:
    calls: list[ProcessIdentity] = []
    result = reconcile(
        snapshot(shell(shell_id="z", cwd=str(tmp_path)), shell(shell_id="a", cwd=str(tmp_path))),
        BOOT_B,
        lambda identity: calls.append(identity) or ProcessProbe(ProcessStatus.ALIVE),
        tmp_path,
    )
    assert result is not None
    assert calls == []
    assert [item.shell.shell_id for item in result.items] == ["a", "z"]
    assert {item.reason for item in result.items} == {RecoveryReason.PREVIOUS_BOOT}
    assert len(result.workspace_id) == 24


def test_explicit_exit_is_excluded_across_boots(tmp_path: Path) -> None:
    assert reconcile(snapshot(shell(termination=TerminationKind.EXPLICIT_EXIT)), BOOT_B, lambda _: None, tmp_path) is None


@pytest.mark.parametrize(
    ("status", "expected_reason", "diagnostics"),
    [
        (ProcessStatus.ALIVE, None, ()),
        (ProcessStatus.DEAD, RecoveryReason.SAME_BOOT_DEAD, ()),
        (ProcessStatus.UNKNOWN, None, ("process status unknown for shell shell-a; not recoverable",)),
    ],
)
def test_same_boot_tri_state(status, expected_reason, diagnostics, tmp_path: Path) -> None:
    result = reconcile(snapshot(shell(boot_id=BOOT_A, cwd=str(tmp_path))), BOOT_A, lambda _: ProcessProbe(status), tmp_path)
    if expected_reason is None and not diagnostics:
        assert result is None
    elif expected_reason is None:
        assert result is not None
        assert result.items == ()
        assert result.diagnostics == diagnostics
    else:
        assert result is not None
        assert result.items[0].reason is expected_reason


def test_reconcile_permission_or_malformed_probe_unknown_and_pid_reuse_dead(tmp_path: Path) -> None:
    unknown = reconcile(snapshot(shell(cwd=str(tmp_path))), BOOT_A, lambda _: ProcessProbe(ProcessStatus.UNKNOWN, "permission or malformed"), tmp_path)
    reused = reconcile(snapshot(shell(cwd=str(tmp_path))), BOOT_A, lambda _: ProcessProbe(ProcessStatus.DEAD, "start time differs"), tmp_path)
    assert unknown is not None and unknown.items == ()
    assert unknown.diagnostics == ("process status unknown for shell shell-a; not recoverable",)
    assert reused is not None and reused.items[0].reason is RecoveryReason.SAME_BOOT_DEAD


def test_resolve_directory_uses_nearest_real_accessible_parent(tmp_path: Path) -> None:
    existing = tmp_path / "kept"
    existing.mkdir()
    recorded = existing / "gone" / "app"
    directory, warning = resolve_directory(recorded, tmp_path)
    assert directory == existing
    assert warning == f"{recorded} missing; using {existing}"


def test_resolve_directory_rejects_file_and_final_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    file_path = target / "file"
    file_path.write_text("x")
    link = target / "link"
    link.symlink_to(target, target_is_directory=True)
    assert resolve_directory(file_path, tmp_path)[0] == target
    assert resolve_directory(link, tmp_path)[0] == target


def test_resolve_directory_falls_back_to_valid_home(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("termrecall.recovery.os.access", lambda path, mode: path == home)
    directory, warning = resolve_directory(tmp_path / "gone" / "app", home)
    assert directory == home
    assert warning == f"{tmp_path / 'gone' / 'app'} missing; using {home}"


class RecordingAdapter:
    name = "recording"

    def __init__(self) -> None:
        self.items: tuple[LaunchItem, ...] = ()

    def detect(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(True, True, False, False, False, True, False)

    def plan(self, items):
        self.items = tuple(items)
        return tuple(LaunchAction((item.item_id,), ("terminal",), RestorationLevel.PARTIAL, ()) for item in items)

    def execute(self, actions, attempt_id):
        return tuple(Outcome(item_id, "success", "restored") for action in actions for item_id in action.item_ids)


def test_build_attempt_resolves_only_current_selected_approved_commands(tmp_path: Path) -> None:
    replayable = CommandRecord(1, "python -m http.server", "python -m http.server", CommandDisposition.REPLAYABLE, True)
    redacted = CommandRecord(1, "sensitive command redacted", None, CommandDisposition.REDACTED, True)
    items = (
        RecoveryItemRecord("approved", shell(shell_id="a", cwd=str(tmp_path), command=replayable), "previous_boot"),
        RecoveryItemRecord("unapproved", shell(shell_id="b", cwd=str(tmp_path), command=replayable), "previous_boot"),
        RecoveryItemRecord("redacted", shell(shell_id="c", cwd=str(tmp_path), command=redacted), "previous_boot"),
    )
    record = RecoveryRecord(1, "workspace", 7, 13.5, items, (), ())
    adapter = RecordingAdapter()
    attempt, _ = build_attempt(record, ("approved", "unapproved", "redacted"), {"approved", "redacted"}, adapter, lambda name: "/usr/bin/python" if name == "python" else None)
    assert attempt.selected_item_ids == ("approved", "unapproved", "redacted")
    assert [item.approved_command for item in adapter.items] == ["python -m http.server", None, None]


def test_persisted_unsupported_adapter_degrades_to_unavailable_without_launch(
    tmp_path: Path,
) -> None:
    command = CommandRecord(1, "sleep 10", "sleep 10", CommandDisposition.REPLAYABLE, True)
    unsupported = replace(shell(cwd=str(tmp_path), command=command), adapter="wezterm")
    record = RecoveryRecord(
        1,
        "workspace",
        7,
        13.5,
        (RecoveryItemRecord("item", unsupported, "previous_boot"),),
        (),
        (),
    )
    adapter = RecordingAdapter()

    attempt, actions = build_attempt(
        record,
        ("item",),
        {"item"},
        adapter,
        lambda _: "/usr/bin/sleep",
        home=tmp_path,
    )

    assert attempt.selected_item_ids == ("item",)
    assert adapter.items == ()
    assert actions[0].item_ids == ("item",)
    assert actions[0].argv == ()
    assert actions[0].level is RestorationLevel.UNAVAILABLE
    assert "unsupported adapter" in actions[0].warnings


def test_build_attempt_downgrades_missing_executable(tmp_path: Path) -> None:
    command = CommandRecord(1, "missing --serve", "missing --serve", CommandDisposition.REPLAYABLE, True)
    record = RecoveryRecord(1, "workspace", 7, 13.5, (RecoveryItemRecord("item", shell(cwd=str(tmp_path), command=command), "previous_boot"),), (), ())
    adapter = RecordingAdapter()
    _, actions = build_attempt(record, ("item",), {"item"}, adapter, lambda _: None)
    assert adapter.items[0].approved_command is None
    assert "executable unavailable" in actions[0].warnings
