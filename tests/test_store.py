import json
import os
import stat
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from termrecall.model import (
    CommandDisposition,
    CommandRecord,
    Outcome,
    OutcomeKind,
    ProcessIdentity,
    RecoveryItemRecord,
    RecoveryRecord,
    RestoreAttempt,
    ShellRecord,
    Snapshot,
)
from termrecall.store import (
    MAX_RECOVERY_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_TOMBSTONE_BYTES,
    MIGRATIONS,
    SnapshotStore,
    UnsafeStatePath,
    UnsupportedSchemaVersion,
)


def snapshot(generation: int) -> Snapshot:
    return Snapshot(1, generation, float(generation), ())


def recovery(*, workspace_id: str = "workspace-a", two_items: bool = False) -> RecoveryRecord:
    command = CommandRecord(
        1,
        "python -m http.server",
        "python -m http.server",
        CommandDisposition.REPLAYABLE,
        True,
    )
    shell = ShellRecord(
        "shell-a",
        ProcessIdentity("boot-a", 42, 900),
        "gnome-terminal",
        "/srv/app",
        1,
        command,
        None,
    )
    items = [RecoveryItemRecord("item-a", shell, "prior_boot")]
    if two_items:
        items.append(RecoveryItemRecord("item-b", replace(shell, shell_id="shell-b"), "prior_boot"))
    return RecoveryRecord(1, workspace_id, 4, 13.5, tuple(items), (), ())


def test_close_is_idempotent_and_context_manager_closes_fds(tmp_path: Path) -> None:
    with SnapshotStore(tmp_path / "state") as store:
        state_fd = store._state_fd
        lock_fd = store._lock_fd
        store.write(snapshot(1))

    with pytest.raises(OSError):
        os.fstat(state_fd)
    with pytest.raises(OSError):
        os.fstat(lock_fd)
    store.close()


def test_closed_store_rejects_all_public_operations(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.close()

    operations = (
        lambda: store.write(snapshot(1)),
        store.load_latest,
        store.list_valid,
        store.load_recovery,
        lambda: store.write_recovery(recovery()),
        lambda: store.commit_outcomes(
            "workspace-a",
            RestoreAttempt("attempt-a", "workspace-a", ("item-a",), (), ()),
            (),
        ),
        lambda: store.complete_or_discard("workspace-a", discard=True),
    )
    for operation in operations:
        with pytest.raises(RuntimeError, match="closed"):
            operation()


def test_write_creates_private_file_and_round_trips(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")

    path = store.write(snapshot(1))

    assert path.stat().st_mode & 0o777 == 0o600
    assert store.load_latest() == snapshot(1)
    assert store.list_valid() == (snapshot(1),)
    store.close()


def test_create_parents_builds_private_hierarchy_below_trusted_root(tmp_path: Path) -> None:
    state = tmp_path / "fresh" / "xdg-state" / "termrecall"

    store = SnapshotStore(state, create_parents=True, root_boundary=tmp_path)

    assert state.is_dir()
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o700
        for path in (tmp_path / "fresh", tmp_path / "fresh" / "xdg-state", state)
    )
    store.close()


def test_create_parents_rejects_symlink_ancestor_without_touching_target(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    marker = external / "operator-owned"
    marker.write_text("untouched", encoding="utf-8")
    link = tmp_path / "xdg-state"
    link.symlink_to(external, target_is_directory=True)

    with pytest.raises(UnsafeStatePath, match="ancestor"):
        SnapshotStore(
            link / "termrecall",
            create_parents=True,
            root_boundary=tmp_path,
        )

    assert marker.read_text(encoding="utf-8") == "untouched"
    assert not (external / "termrecall").exists()


def test_create_parents_refuses_paths_outside_root_boundary(tmp_path: Path) -> None:
    with pytest.raises(UnsafeStatePath, match="boundary"):
        SnapshotStore(
            tmp_path.parent / "outside" / "termrecall",
            create_parents=True,
            root_boundary=tmp_path,
        )


def test_create_parents_rejects_writable_existing_ancestor(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)

    with pytest.raises(UnsafeStatePath, match="mode"):
        SnapshotStore(
            unsafe / "state" / "termrecall",
            create_parents=True,
            root_boundary=tmp_path,
        )

    assert not (unsafe / "state").exists()


def test_rejects_symlink_and_unsafe_directory_metadata(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(UnsafeStatePath):
        SnapshotStore(link)

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(UnsafeStatePath, match="mode"):
        SnapshotStore(unsafe)


def test_symlink_in_state_directory_ancestry_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(UnsafeStatePath, match="ancestor"):
        SnapshotStore(linked_parent / "state")

    assert not (real_parent / "state").exists()


def test_open_directory_fd_anchors_operations_after_path_swap(tmp_path: Path) -> None:
    state = tmp_path / "state"
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    store = SnapshotStore(state)
    original = tmp_path / "original"
    state.rename(original)
    state.symlink_to(attacker, target_is_directory=True)

    store.write(snapshot(1))

    assert (original / "checkpoint-00000000000000000001.json").is_file()
    assert list(attacker.iterdir()) == []
    store.close()


def test_temp_file_is_fchmoded_and_verified_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    calls: list[str] = []
    real_fchmod = os.fchmod
    real_fstat = os.fstat

    def fchmod(fd: int, mode: int) -> None:
        calls.append(f"fchmod:{mode:o}")
        real_fchmod(fd, mode)

    def fstat(fd: int) -> os.stat_result:
        calls.append("fstat")
        return real_fstat(fd)

    monkeypatch.setattr(os, "fchmod", fchmod)
    monkeypatch.setattr(os, "fstat", fstat)
    store.write(snapshot(1))

    assert "fchmod:600" in calls
    assert calls.index("fchmod:600") < len(calls) - 1
    store.close()


def test_private_mode_is_exact_under_restrictive_umask(tmp_path: Path) -> None:
    previous = os.umask(0o777)
    try:
        with SnapshotStore(tmp_path / "state") as store:
            path = store.write(snapshot(1))
            assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert stat.S_IMODE((tmp_path / "state" / ".store.lock").stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_reads_reject_non_private_checkpoint_recovery_and_tombstone(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    checkpoint = store.write(snapshot(1))
    checkpoint.chmod(0o640)
    assert store.load_latest() is None
    assert any("mode" in diagnostic for diagnostic in store.diagnostics)

    record = recovery()
    store.write_recovery(record)
    recovery_path = tmp_path / "state" / "recovery.json"
    recovery_path.chmod(0o640)
    with pytest.raises(UnsafeStatePath, match="mode"):
        store.load_recovery()
    recovery_path.chmod(0o600)

    store.complete_or_discard("workspace-a", discard=True)
    tombstone = tmp_path / "state" / "recovery-discard.json"
    tombstone.chmod(0o640)
    stale = tmp_path / "state" / "recovery.json"
    stale.write_bytes(recovery_path.read_bytes() if recovery_path.exists() else json.dumps({
        "schema_version": 1,
        "workspace_id": "workspace-a",
        "source_generation": 4,
        "created_at": 13.5,
        "items": [],
        "attempts": [],
        "completed_item_ids": [],
    }).encode())
    stale.chmod(0o600)
    with pytest.raises(UnsafeStatePath, match="mode"):
        store.load_recovery()
    store.close()


def test_atomic_write_fsyncs_file_before_replace_and_directory_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    calls: list[str] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def fsync(fd: int) -> None:
        calls.append("directory-sync" if fd == store._state_fd else "file-sync")
        real_fsync(fd)

    def atomic_replace(src: str, dst: str, **kwargs: object) -> None:
        calls.append("replace")
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", atomic_replace)

    store.write(snapshot(1))

    assert calls.index("file-sync") < calls.index("replace") < calls.index("directory-sync")
    store.close()


def test_replace_failure_preserves_predecessor_and_cleans_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write(snapshot(1))
    monkeypatch.setattr(os, "replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("boom")))

    with pytest.raises(OSError, match="boom"):
        store.write(snapshot(2))

    assert store.load_latest() == snapshot(1)
    assert not any(path.name.startswith(".tmp-") for path in (tmp_path / "state").iterdir())
    store.close()


def test_oversized_newest_checkpoint_falls_back_without_unbounded_read(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write(snapshot(1))
    oversized = tmp_path / "state" / "checkpoint-00000000000000000002.json"
    oversized.write_bytes(b"{" + b" " * MAX_SNAPSHOT_BYTES + b"}")
    oversized.chmod(0o600)

    assert store.load_latest() == snapshot(1)
    assert any("size limit" in diagnostic for diagnostic in store.diagnostics)
    store.close()


def test_read_catches_file_growth_past_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write(snapshot(1))
    newest = store.write(snapshot(2))
    real_read = os.read
    injected = False

    def growing_read(fd: int, count: int) -> bytes:
        nonlocal injected
        if not injected and os.fstat(fd).st_ino == newest.stat().st_ino:
            injected = True
            return b"x" * (MAX_SNAPSHOT_BYTES + 1)
        return real_read(fd, count)

    monkeypatch.setattr(os, "read", growing_read)

    assert store.load_latest() == snapshot(1)
    assert any("size limit" in diagnostic for diagnostic in store.diagnostics)
    store.close()


def test_serialized_write_limits_apply_to_each_record_type(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    with pytest.raises(ValueError, match="snapshot.*size limit"):
        store._atomic_json_write(
            "checkpoint-00000000000000000001.json",
            {"schema_version": 1, "padding": "x" * MAX_SNAPSHOT_BYTES},
            lambda value: value,
            maximum=MAX_SNAPSHOT_BYTES,
            kind="snapshot",
        )
    with pytest.raises(ValueError, match="recovery.*size limit"):
        store._atomic_json_write(
            "recovery.json",
            {"schema_version": 1, "padding": "x" * MAX_RECOVERY_BYTES},
            lambda value: value,
            maximum=MAX_RECOVERY_BYTES,
            kind="recovery",
        )
    with pytest.raises(ValueError, match="tombstone.*size limit"):
        store._atomic_json_write(
            "recovery-discard.json",
            {"schema_version": 1, "padding": "x" * MAX_TOMBSTONE_BYTES},
            lambda value: value,
            maximum=MAX_TOMBSTONE_BYTES,
            kind="tombstone",
        )
    store.close()


def test_corrupt_newest_falls_back_and_future_schema_blocks_fallback(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write(snapshot(1))
    newest = store.write(snapshot(2))
    newest.write_bytes(b"truncated")
    assert store.load_latest() == snapshot(1)
    assert store.diagnostics

    newest.write_text('{"schema_version":2}', encoding="utf-8")
    with pytest.raises(UnsupportedSchemaVersion, match="2"):
        store.load_latest()
    assert newest.exists()
    store.close()


def test_older_future_schema_does_not_hide_newer_supported_checkpoint(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    older = store.write(snapshot(1))
    older.write_text('{"schema_version":2}', encoding="utf-8")
    store.write(snapshot(2))

    assert store.load_latest() == snapshot(2)
    assert store.list_valid() == (snapshot(2),)
    assert older.exists()
    store.close()


def test_schema_zero_without_migration_is_rejected_explicitly(tmp_path: Path) -> None:
    assert MIGRATIONS == {}
    store = SnapshotStore(tmp_path / "state")
    path = store.write(snapshot(1))
    path.write_text('{"schema_version":0}', encoding="utf-8")

    with pytest.raises(UnsupportedSchemaVersion, match="no migration.*0"):
        store.load_latest()
    store.close()


def test_retains_newest_ten_valid_checkpoints(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    for generation in range(1, 13):
        store.write(snapshot(generation))

    assert [item.generation for item in store.list_valid()] == list(range(3, 13))
    assert sorted(path.name for path in (tmp_path / "state").glob("checkpoint-*.json")) == [
        f"checkpoint-{generation:020d}.json" for generation in range(3, 13)
    ]
    store.close()


def test_concurrent_checkpoint_writers_share_retention_transaction(tmp_path: Path) -> None:
    state = tmp_path / "state"
    stores = (SnapshotStore(state), SnapshotStore(state))
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def write_range(store: SnapshotStore, generations: range) -> None:
        try:
            barrier.wait()
            for generation in generations:
                store.write(snapshot(generation))
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=write_range, args=(stores[0], range(1, 21, 2))),
        threading.Thread(target=write_range, args=(stores[1], range(2, 21, 2))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    valid = stores[0].list_valid()
    assert len(valid) <= 10
    assert [item.generation for item in valid] == list(range(11, 21))
    assert len(list(state.glob("checkpoint-*.json"))) <= 10
    for store in stores:
        store.close()


def test_prune_ignores_checkpoint_that_disappears_while_lock_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    for generation in range(1, 11):
        store.write(snapshot(generation))
    real_unlink = os.unlink
    disappeared = False

    def unlink_then_report_missing(name: str, **kwargs: object) -> None:
        nonlocal disappeared
        if name.startswith("checkpoint-") and not disappeared:
            disappeared = True
            real_unlink(name, **kwargs)
            raise FileNotFoundError(name)
        real_unlink(name, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink_then_report_missing)

    store.write(snapshot(11))

    assert disappeared
    assert len(store.list_valid()) <= 10
    store.close()


def test_same_instance_checkpoint_reader_waits_for_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write(snapshot(1))
    replace_entered = threading.Event()
    allow_replace = threading.Event()
    read_done = threading.Event()
    result: list[Snapshot | None] = []
    real_replace = os.replace

    def delayed_replace(src: str, dst: str, **kwargs: object) -> None:
        if dst.endswith("02.json"):
            replace_entered.set()
            assert allow_replace.wait(5)
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", delayed_replace)
    writer = threading.Thread(target=store.write, args=(snapshot(2),))
    reader = threading.Thread(
        target=lambda: (result.append(store.load_latest()), read_done.set())
    )
    writer.start()
    assert replace_entered.wait(5)
    reader.start()
    time.sleep(0.1)
    assert not read_done.is_set()
    allow_replace.set()
    writer.join(timeout=5)
    reader.join(timeout=5)

    assert result == [snapshot(2)]
    store.close()


def test_checkpoint_load_waits_for_write_and_prune_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    writer = SnapshotStore(state)
    reader = SnapshotStore(state)
    writer.write(snapshot(1))
    replace_entered = threading.Event()
    allow_replace = threading.Event()
    read_done = threading.Event()
    result: list[Snapshot | None] = []
    real_replace = os.replace

    def delayed_replace(src: str, dst: str, **kwargs: object) -> None:
        if dst.endswith("02.json"):
            replace_entered.set()
            assert allow_replace.wait(5)
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", delayed_replace)
    write_thread = threading.Thread(target=writer.write, args=(snapshot(2),))
    read_thread = threading.Thread(
        target=lambda: (result.append(reader.load_latest()), read_done.set())
    )
    write_thread.start()
    assert replace_entered.wait(5)
    read_thread.start()
    time.sleep(0.1)
    assert not read_done.is_set()
    allow_replace.set()
    write_thread.join(timeout=5)
    read_thread.join(timeout=5)

    assert result == [snapshot(2)]
    writer.close()
    reader.close()


def test_write_rejects_unsafe_existing_destination(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    destination = state / "checkpoint-00000000000000000001.json"
    destination.write_text("attacker-controlled", encoding="utf-8")
    destination.chmod(0o644)

    with pytest.raises(UnsafeStatePath, match="mode"):
        store.write(snapshot(1))

    assert destination.read_text(encoding="utf-8") == "attacker-controlled"
    store.close()


def test_recovery_round_trip_uses_atomic_private_file(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    record = recovery()

    store.write_recovery(record)

    assert store.load_recovery() == record
    assert (tmp_path / "state" / "recovery.json").stat().st_mode & 0o777 == 0o600
    store.close()


def test_write_recovery_preserves_existing_unresolved_bytes(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    original = recovery(workspace_id="workspace-a")
    store.write_recovery(original)
    path = tmp_path / "state" / "recovery.json"
    original_bytes = path.read_bytes()

    store.write_recovery(recovery(workspace_id="workspace-b"))

    assert path.read_bytes() == original_bytes
    assert store.load_recovery() == original
    store.close()


def test_internal_recovery_update_requires_workspace_and_expected_generation(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    original = recovery()
    store.write_recovery(original)
    path = tmp_path / "state" / "recovery.json"
    original_bytes = path.read_bytes()
    changed_generation = replace(original, source_generation=5)

    with pytest.raises(ValueError, match="workspace"):
        store._update_recovery(original, expected_workspace_id="other", expected_generation=4)
    assert path.read_bytes() == original_bytes
    with pytest.raises(ValueError, match="generation"):
        store._update_recovery(original, expected_workspace_id="workspace-a", expected_generation=3)
    assert path.read_bytes() == original_bytes
    with pytest.raises(ValueError, match="replacement.*generation"):
        store._update_recovery(
            changed_generation,
            expected_workspace_id="workspace-a",
            expected_generation=4,
        )
    assert path.read_bytes() == original_bytes

    updated = replace(original, created_at=14.5)
    store._update_recovery(updated, expected_workspace_id="workspace-a", expected_generation=4)
    assert store.load_recovery() == updated
    store.close()


def test_commit_outcomes_validates_and_durably_merges_attempt(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write_recovery(recovery())
    outcome = Outcome("item-a", OutcomeKind.SUCCESS, "restored")
    attempt = RestoreAttempt("attempt-a", "workspace-a", ("item-a",), ("item-a",), ())

    updated = store.commit_outcomes("workspace-a", attempt, (outcome,))

    assert updated.attempts == (replace(attempt, outcomes=(outcome,)),)
    assert updated.completed_item_ids == ("item-a",)
    assert store.load_recovery() == updated
    with pytest.raises(ValueError, match="workspace"):
        store.commit_outcomes("other", attempt, ())
    with pytest.raises(ValueError, match="item"):
        bad = RestoreAttempt("attempt-b", "workspace-a", ("missing",), (), ())
        store.commit_outcomes("workspace-a", bad, ())
    store.close()


def test_same_instance_concurrent_outcome_commits_preserve_both_attempts(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write_recovery(recovery(two_items=True))
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def commit(item_id: str, attempt_id: str) -> None:
        try:
            barrier.wait()
            attempt = RestoreAttempt(attempt_id, "workspace-a", (item_id,), (), ())
            store.commit_outcomes(
                "workspace-a", attempt, (Outcome(item_id, OutcomeKind.SUCCESS, "restored"),)
            )
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=commit, args=("item-a", "attempt-a")),
        threading.Thread(target=commit, args=("item-b", "attempt-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    final = store.load_recovery()
    assert final is not None
    assert {attempt.attempt_id for attempt in final.attempts} == {"attempt-a", "attempt-b"}
    assert set(final.completed_item_ids) == {"item-a", "item-b"}
    store.close()


def test_concurrent_outcome_commits_preserve_both_attempts(tmp_path: Path) -> None:
    state = tmp_path / "state"
    seed = SnapshotStore(state)
    seed.write_recovery(recovery(two_items=True))
    seed.close()
    stores = (SnapshotStore(state), SnapshotStore(state))
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def commit(store: SnapshotStore, item_id: str, attempt_id: str) -> None:
        try:
            barrier.wait()
            attempt = RestoreAttempt(attempt_id, "workspace-a", (item_id,), (), ())
            store.commit_outcomes(
                "workspace-a", attempt, (Outcome(item_id, OutcomeKind.SUCCESS, "restored"),)
            )
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=commit, args=(stores[0], "item-a", "attempt-a")),
        threading.Thread(target=commit, args=(stores[1], "item-b", "attempt-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    final = stores[0].load_recovery()
    assert final is not None
    assert {attempt.attempt_id for attempt in final.attempts} == {"attempt-a", "attempt-b"}
    assert set(final.completed_item_ids) == {"item-a", "item-b"}
    for store in stores:
        store.close()


def test_same_instance_second_thread_cannot_unlock_transaction_for_third_store(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    shared = SnapshotStore(state)
    third = SnapshotStore(state)
    outer_entered = threading.Event()
    allow_outer_exit = threading.Event()
    second_done = threading.Event()
    third_entered = threading.Event()

    def hold_outer() -> None:
        with shared._transaction():
            outer_entered.set()
            assert allow_outer_exit.wait(5)

    def use_same_instance() -> None:
        assert outer_entered.wait(5)
        with shared._transaction():
            pass
        second_done.set()

    def use_third_store() -> None:
        with third._transaction():
            third_entered.set()

    outer = threading.Thread(target=hold_outer)
    second = threading.Thread(target=use_same_instance)
    outsider = threading.Thread(target=use_third_store)
    outer.start()
    assert outer_entered.wait(5)
    second.start()
    time.sleep(0.1)
    outsider.start()
    time.sleep(0.1)

    assert not second_done.is_set()
    assert not third_entered.is_set()
    allow_outer_exit.set()
    outer.join(timeout=5)
    second.join(timeout=5)
    outsider.join(timeout=5)

    assert second_done.is_set()
    assert third_entered.is_set()
    shared.close()
    third.close()


def test_nested_transaction_holds_flock_until_outer_exit(tmp_path: Path) -> None:
    state = tmp_path / "state"
    nested_store = SnapshotStore(state)
    second_store = SnapshotStore(state)
    inner_exited = threading.Event()
    allow_outer_exit = threading.Event()
    second_entered = threading.Event()

    def nest_and_hold_outer() -> None:
        with nested_store._transaction():
            with nested_store._transaction():
                pass
            inner_exited.set()
            assert allow_outer_exit.wait(5)

    def enter_second_store() -> None:
        assert inner_exited.wait(5)
        with second_store._transaction():
            second_entered.set()

    owner = threading.Thread(target=nest_and_hold_outer)
    contender = threading.Thread(target=enter_second_store)
    owner.start()
    assert inner_exited.wait(5)
    contender.start()
    time.sleep(0.1)

    assert not second_entered.is_set()
    allow_outer_exit.set()
    owner.join(timeout=5)
    contender.join(timeout=5)

    assert not owner.is_alive()
    assert not contender.is_alive()
    assert second_entered.is_set()
    nested_store.close()
    second_store.close()


def test_nested_transaction_exception_restores_depth_and_releases_outer_lock(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    contender = SnapshotStore(state)

    with pytest.raises(RuntimeError, match="nested failure"):
        with store._transaction():
            with store._transaction():
                raise RuntimeError("nested failure")

    assert store._transaction_depth == 0
    entered = threading.Event()

    def enter_contender() -> None:
        with contender._transaction():
            entered.set()

    thread = threading.Thread(target=enter_contender)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert entered.is_set()
    store.close()
    contender.close()


def test_nested_transaction_is_reentrant(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    entered = threading.Event()

    def nest() -> None:
        with store._transaction():
            with store._transaction():
                entered.set()

    thread = threading.Thread(target=nest)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert entered.is_set()
    store.close()


def test_completion_waits_for_inflight_commit_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    seed = SnapshotStore(state)
    seed.write_recovery(recovery())
    seed.close()
    committing = SnapshotStore(state)
    completing = SnapshotStore(state)
    replacement_entered = threading.Event()
    allow_replacement = threading.Event()
    completion_done = threading.Event()
    real_replace = os.replace

    def delayed_replace(src: str, dst: str, **kwargs: object) -> None:
        if dst == "recovery.json":
            replacement_entered.set()
            assert allow_replacement.wait(5)
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", delayed_replace)
    attempt = RestoreAttempt("attempt-a", "workspace-a", ("item-a",), (), ())
    commit_thread = threading.Thread(
        target=committing.commit_outcomes,
        args=("workspace-a", attempt, (Outcome("item-a", OutcomeKind.SUCCESS, "restored"),)),
    )
    completion_thread = threading.Thread(
        target=lambda: (completing.complete_or_discard("workspace-a", discard=False), completion_done.set())
    )
    commit_thread.start()
    assert replacement_entered.wait(5)
    completion_thread.start()
    time.sleep(0.1)
    assert not completion_done.is_set()
    allow_replacement.set()
    commit_thread.join(timeout=5)
    completion_thread.join(timeout=5)

    assert completion_done.is_set()
    assert not (state / "recovery.json").exists()
    committing.close()
    completing.close()


def test_commit_rejects_duplicate_attempt_and_mismatched_outcomes(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write_recovery(recovery())
    attempt = RestoreAttempt("attempt-a", "workspace-a", ("item-a",), (), ())
    store.commit_outcomes("workspace-a", attempt, ())

    with pytest.raises(ValueError, match="attempt"):
        store.commit_outcomes("workspace-a", attempt, ())
    with pytest.raises(ValueError, match="selected"):
        other = RestoreAttempt("attempt-b", "workspace-a", ("item-a",), (), ())
        store.commit_outcomes(
            "workspace-a", other, (Outcome("item-b", OutcomeKind.SUCCESS, "wrong"),)
        )
    store.close()


def test_completion_requires_all_items_terminal_and_writes_tombstone_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write_recovery(recovery(two_items=True))
    outcome = Outcome("item-a", OutcomeKind.SUCCESS, "restored")
    attempt = RestoreAttempt("attempt-a", "workspace-a", ("item-a",), (), ())
    store.commit_outcomes("workspace-a", attempt, (outcome,))
    with pytest.raises(ValueError, match="terminally successful"):
        store.complete_or_discard("workspace-a", discard=False)

    second = Outcome("item-b", OutcomeKind.WARNING, "partial")
    attempt2 = RestoreAttempt("attempt-b", "workspace-a", ("item-b",), (), ())
    store.commit_outcomes("workspace-a", attempt2, (second,))
    observed: list[bool] = []
    real_unlink = os.unlink

    def unlink(name: str, **kwargs: object) -> None:
        observed.append((tmp_path / "state" / "recovery-completion.json").exists())
        real_unlink(name, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    store.complete_or_discard("workspace-a", discard=False)

    assert observed == [True]
    assert store.load_recovery() is None
    tombstone = json.loads((tmp_path / "state" / "recovery-completion.json").read_text())
    assert tombstone["schema_version"] == 1
    assert tombstone["workspace_id"] == "workspace-a"
    assert tombstone["disposition"] == "completed"
    assert isinstance(tombstone["timestamp"], float)
    store.close()


def test_existing_terminal_tombstone_prevents_stale_recovery_resurrection(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write_recovery(recovery())
    store.complete_or_discard("workspace-a", discard=True)
    (tmp_path / "state" / "recovery.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "workspace_id": "workspace-a",
                "source_generation": 4,
                "created_at": 13.5,
                "items": [],
                "attempts": [],
                "completed_item_ids": [],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "state" / "recovery.json").chmod(0o600)

    assert store.load_recovery() is None
    assert not (tmp_path / "state" / "recovery.json").exists()
    store.close()


def test_stale_recovery_cleanup_fsyncs_and_retries_after_unlink_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    store = SnapshotStore(state)
    record = recovery()
    store.write_recovery(record)
    store.complete_or_discard("workspace-a", discard=True)
    stale = state / "recovery.json"
    stale.write_text(json.dumps({
        "schema_version": 1,
        "workspace_id": "workspace-a",
        "source_generation": 4,
        "created_at": 13.5,
        "items": [],
        "attempts": [],
        "completed_item_ids": [],
    }), encoding="utf-8")
    stale.chmod(0o600)
    real_unlink = os.unlink
    failed = False

    def crash_once(name: str, **kwargs: object) -> None:
        nonlocal failed
        if name == "recovery.json" and not failed:
            failed = True
            raise OSError("crash during cleanup")
        real_unlink(name, **kwargs)

    monkeypatch.setattr(os, "unlink", crash_once)
    with pytest.raises(OSError, match="crash during cleanup"):
        store.load_recovery()
    assert stale.exists()

    syncs: list[int] = []
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        syncs.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    assert store.load_recovery() is None
    assert not stale.exists()
    assert store._state_fd in syncs
    store.close()


def test_init_cleans_stale_recovery_covered_by_tombstone(tmp_path: Path) -> None:
    state = tmp_path / "state"
    first = SnapshotStore(state)
    first.write_recovery(recovery())
    first.complete_or_discard("workspace-a", discard=True)
    stale = state / "recovery.json"
    stale.write_text(json.dumps({
        "schema_version": 1,
        "workspace_id": "workspace-a",
        "source_generation": 4,
        "created_at": 13.5,
        "items": [],
        "attempts": [],
        "completed_item_ids": [],
    }), encoding="utf-8")
    stale.chmod(0o600)
    first.close()

    reopened = SnapshotStore(state)

    assert not stale.exists()
    assert reopened.load_recovery() is None
    reopened.close()


def test_discard_writes_tombstone_then_removes_command_bearing_record(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "state")
    store.write_recovery(recovery())

    store.complete_or_discard("workspace-a", discard=True)

    assert store.load_recovery() is None
    assert not (tmp_path / "state" / "recovery.json").exists()
    tombstone = json.loads((tmp_path / "state" / "recovery-discard.json").read_text())
    assert tombstone["disposition"] == "discarded"
    store.close()


def test_tombstone_write_failure_leaves_recovery_unresolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "state")
    record = recovery()
    store.write_recovery(record)
    real_replace = os.replace

    def replace_file(src: str, dst: str, **kwargs: object) -> None:
        if dst == "recovery-discard.json":
            raise OSError("crash boundary")
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace_file)
    with pytest.raises(OSError, match="crash boundary"):
        store.complete_or_discard("workspace-a", discard=True)

    assert store.load_recovery() == record
    store.close()
