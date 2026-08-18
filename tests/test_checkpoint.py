# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from termrecall.checkpoint import CheckpointManager
from termrecall.model import Snapshot


class FakeClock:
    def __init__(self) -> None:
        self.time = 0.0
        self.sleep_calls: list[float] = []
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []

    def now(self) -> float:
        return self.time

    async def sleep(self, delay: float) -> None:
        self.sleep_calls.append(delay)
        if delay <= 0:
            await asyncio.sleep(0)
            return
        future = asyncio.get_running_loop().create_future()
        self._sleepers.append((self.time + delay, future))
        try:
            await future
        finally:
            self._sleepers = [(at, item) for at, item in self._sleepers if item is not future]

    async def advance(self, delay: float) -> None:
        for _ in range(5):
            await asyncio.sleep(0)
        self.time += delay
        for at, future in tuple(self._sleepers):
            if at <= self.time and not future.done():
                future.set_result(None)
        for _ in range(5):
            await asyncio.sleep(0)


class RecordingStore:
    def __init__(self, failures: int = 0, message: str = "disk unavailable") -> None:
        self.writes: list[Snapshot] = []
        self.attempt_times: list[float] = []
        self.failures = failures
        self.message = message
        self.active = 0
        self.maximum_active = 0
        self.started = asyncio.Event()
        self.completed = asyncio.Event()
        self.completions = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._clock: FakeClock | None = None

    def attach(self, clock: FakeClock) -> None:
        self._clock = clock
        self._loop = asyncio.get_running_loop()

    def write(self, snapshot: Snapshot) -> None:
        assert self._clock is not None and self._loop is not None
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.attempt_times.append(self._clock.now())
        self._loop.call_soon_threadsafe(self.started.set)
        try:
            if self.failures:
                self.failures -= 1
                raise RuntimeError(self.message)
            self.writes.append(snapshot)
        finally:
            self.active -= 1
            self.completions += 1
            self._loop.call_soon_threadsafe(self.completed.set)

    async def wait_for_attempts(self, count: int) -> None:
        while len(self.attempt_times) < count:
            self.started.clear()
            await self.started.wait()

    async def wait_for_completions(self, count: int) -> None:
        while self.completions < count:
            self.completed.clear()
            await self.completed.wait()


class BlockingStore(RecordingStore):
    def __init__(self) -> None:
        super().__init__()
        self.release_write = asyncio.Event()

    def write(self, snapshot: Snapshot) -> None:
        assert self._clock is not None and self._loop is not None
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.attempt_times.append(self._clock.now())
        self._loop.call_soon_threadsafe(self.started.set)
        future = asyncio.run_coroutine_threadsafe(self.release_write.wait(), self._loop)
        try:
            future.result()
            self.writes.append(snapshot)
        finally:
            self.active -= 1


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def snapshot_supplier():
    current = Snapshot(1, 0, 0.0, ())

    def supply() -> Snapshot:
        return current

    def set_generation(generation: int) -> None:
        nonlocal current
        current = replace(current, generation=generation)

    supply.set_generation = set_generation
    return supply


async def start_manager(manager: CheckpointManager, store: RecordingStore, clock: FakeClock):
    store.attach(clock)
    stop = asyncio.Event()
    task = asyncio.create_task(manager.run(stop))
    await asyncio.sleep(0)
    return stop, task


async def stop_manager(stop: asyncio.Event, task: asyncio.Task[None], clock: FakeClock) -> None:
    stop.set()
    await clock.advance(0)
    await task


@pytest.mark.asyncio
async def test_dirty_mark_between_schedule_check_and_wait_is_not_lost(
    fake_clock, snapshot_supplier
) -> None:
    store = RecordingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    schedule_checked = asyncio.Event()
    resume_run = asyncio.Event()
    original_next_write_time = manager._next_write_time

    async def pause_after_schedule_check():
        due_at = await original_next_write_time()
        schedule_checked.set()
        await resume_run.wait()
        return due_at

    manager._next_write_time = pause_after_schedule_check
    store.attach(fake_clock)
    stop = asyncio.Event()
    run_task = asyncio.create_task(manager.run(stop))
    try:
        await schedule_checked.wait()
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        resume_run.set()
        await fake_clock.advance(0.250)
        await asyncio.wait_for(store.wait_for_attempts(1), timeout=0.1)
    finally:
        stop.set()
        resume_run.set()
        await fake_clock.advance(0)
        await run_task


@pytest.mark.asyncio
async def test_event_just_before_start_delay_does_not_postpone_first_write(
    fake_clock, snapshot_supplier
) -> None:
    store = RecordingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        await fake_clock.advance(0.249)
        snapshot_supplier.set_generation(2)
        await manager.mark_dirty(2)
        await fake_clock.advance(0.001)
        await store.wait_for_attempts(1)
        await store.wait_for_completions(1)
        assert store.attempt_times == pytest.approx([0.250])
        assert [snapshot.generation for snapshot in store.writes] == [2]
    finally:
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_events_coalesce_into_one_write(fake_clock, snapshot_supplier) -> None:
    store = RecordingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        snapshot_supplier.set_generation(2)
        await manager.mark_dirty(2)
        await fake_clock.advance(0.250)
        await store.wait_for_attempts(1)
        await store.wait_for_completions(1)
        assert [snapshot.generation for snapshot in store.writes] == [2]
        assert store.attempt_times == [0.250]
    finally:
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_event_during_write_requires_next_generation(fake_clock, snapshot_supplier) -> None:
    store = BlockingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        await fake_clock.advance(0.250)
        await store.started.wait()
        snapshot_supplier.set_generation(2)
        await manager.mark_dirty(2)
        store.release_write.set()
        flush_task = asyncio.create_task(manager.flush())
        await fake_clock.advance(0)
        await flush_task
        assert [snapshot.generation for snapshot in store.writes] == [1, 2]
        assert store.maximum_active == 1
    finally:
        store.release_write.set()
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_deadline_is_measured_from_first_dirty_mark(fake_clock, snapshot_supplier) -> None:
    store = RecordingStore()
    manager = CheckpointManager(
        store,
        snapshot_supplier,
        fake_clock.now,
        fake_clock.sleep,
        start_delay=3.0,
        deadline=2.0,
    )
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        for generation in range(2, 9):
            await fake_clock.advance(0.249)
            snapshot_supplier.set_generation(generation)
            await manager.mark_dirty(generation)
        await fake_clock.advance(0.257)
        await store.wait_for_attempts(1)
        await store.wait_for_completions(1)
        assert store.attempt_times[0] == pytest.approx(2.0)
        assert store.writes[-1].generation == 8
    finally:
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_newer_generation_during_write_gets_a_fresh_start_delay(
    fake_clock, snapshot_supplier
) -> None:
    store = BlockingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        await fake_clock.advance(0.250)
        await store.started.wait()
        snapshot_supplier.set_generation(2)
        await manager.mark_dirty(2)
        store.release_write.set()
        while manager.status.durable_generation < 1:
            await asyncio.sleep(0)
        await fake_clock.advance(0.249)
        assert store.attempt_times == [0.250]
        await fake_clock.advance(0.001)
        await store.wait_for_attempts(2)
        assert store.attempt_times == pytest.approx([0.250, 0.500])
    finally:
        store.release_write.set()
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_flush_bypasses_delay_and_waits_for_active_write(fake_clock, snapshot_supplier) -> None:
    store = BlockingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(4)
        await manager.mark_dirty(4)
        flush_task = asyncio.create_task(manager.flush())
        await fake_clock.advance(0)
        await store.started.wait()
        assert not flush_task.done()
        store.release_write.set()
        status = await flush_task
        assert status.durable_generation == 4
        assert not status.write_active
        assert store.attempt_times == [0.0]
    finally:
        store.release_write.set()
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_cancel_during_write_waits_for_worker_and_prevents_restart_overlap(
    fake_clock, snapshot_supplier
) -> None:
    store = BlockingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    snapshot_supplier.set_generation(1)
    await manager.mark_dirty(1)
    await fake_clock.advance(0.250)
    await store.started.wait()

    try:
        for _ in range(3):
            run_task.cancel()
            await asyncio.sleep(0)
            assert not run_task.done()
            assert manager.status.write_active
            assert store.active == 1
            with pytest.raises(RuntimeError, match="already running"):
                await manager.run(asyncio.Event())
    finally:
        store.release_write.set()

    with pytest.raises(asyncio.CancelledError):
        await run_task
    assert not manager.status.write_active
    assert store.active == 0
    assert [snapshot.generation for snapshot in store.writes] == [1]

    restart_stop, restart_task = await start_manager(manager, store, fake_clock)
    try:
        status = await manager.flush()
        assert status.durable_generation == 1
        assert store.maximum_active == 1
    finally:
        await stop_manager(restart_stop, restart_task, fake_clock)


@pytest.mark.asyncio
async def test_failure_degrades_then_backs_off_and_recovers(fake_clock, snapshot_supplier) -> None:
    secret = "printf super-secret-command"
    store = RecordingStore(failures=4, message=f"write failed while persisting {secret}")
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(3)
        await manager.mark_dirty(3)
        await fake_clock.advance(0.250)
        await store.wait_for_attempts(1)
        await store.wait_for_completions(1)
        while manager.status.write_active:
            await asyncio.sleep(0)

        status_task = asyncio.create_task(manager.flush())
        await fake_clock.advance(0)
        assert manager.status.dirty_generation == 3
        assert manager.status.durable_generation == 0
        assert manager.status.last_error is not None
        assert "RuntimeError" in manager.status.last_error
        assert secret not in manager.status.last_error
        assert manager.status.next_retry_at == pytest.approx(0.5)

        for delay, attempt_count in zip((0.25, 0.5, 1.0, 2.0), (2, 3, 4, 5), strict=True):
            await fake_clock.advance(delay)
            await store.wait_for_attempts(attempt_count)
            await store.wait_for_completions(attempt_count)
            while manager.status.write_active:
                await asyncio.sleep(0)

        status = await status_task
        assert store.attempt_times == pytest.approx([0.25, 0.5, 1.0, 2.0, 4.0])
        assert status.durable_generation == 3
        assert status.last_error is None
        assert status.next_retry_at is None
        assert store.maximum_active == 1
    finally:
        await stop_manager(stop, run_task, fake_clock)


@pytest.mark.asyncio
async def test_flush_only_waits_for_generation_dirty_at_invocation(fake_clock, snapshot_supplier) -> None:
    store = BlockingStore()
    manager = CheckpointManager(store, snapshot_supplier, fake_clock.now, fake_clock.sleep)
    stop, run_task = await start_manager(manager, store, fake_clock)
    try:
        snapshot_supplier.set_generation(1)
        await manager.mark_dirty(1)
        flush_task = asyncio.create_task(manager.flush())
        await fake_clock.advance(0)
        await store.started.wait()
        snapshot_supplier.set_generation(2)
        await manager.mark_dirty(2)
        store.release_write.set()
        status = await flush_task
        assert status.durable_generation == 1
        assert status.dirty_generation == 2
    finally:
        store.release_write.set()
        await stop_manager(stop, run_task, fake_clock)
