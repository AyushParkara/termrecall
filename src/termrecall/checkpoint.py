# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from termrecall.model import Snapshot
from termrecall.store import SnapshotStore


async def await_uncancellable_completion(task: asyncio.Task[object]) -> bool:
    """Wait for task completion while recording and consuming cancellation requests."""
    cancellation_requested = False
    current_task = asyncio.current_task()
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancellation_requested = True
            if current_task is not None:
                current_task.uncancel()
        except Exception:
            break
    return cancellation_requested


@dataclass(frozen=True, slots=True)
class CheckpointStatus:
    dirty_generation: int
    durable_generation: int
    write_active: bool
    last_error: str | None
    next_retry_at: float | None


class CheckpointManager:
    """Coalesce snapshot writes while maintaining a bounded durability delay."""

    def __init__(
        self,
        store: SnapshotStore,
        snapshot_supplier: Callable[[], Snapshot],
        clock: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]],
        start_delay: float = 0.250,
        deadline: float = 2.0,
        backoff: Sequence[float] = (0.25, 0.5, 1.0, 2.0),
    ) -> None:
        if start_delay < 0 or deadline < 0:
            raise ValueError("checkpoint delays must be non-negative")
        if not backoff or any(delay < 0 for delay in backoff):
            raise ValueError("checkpoint backoff must contain non-negative delays")
        self._store = store
        self._snapshot_supplier = snapshot_supplier
        self._clock = clock
        self._sleep = sleep
        self._start_delay = start_delay
        self._deadline = deadline
        self._backoff = tuple(backoff)

        self._condition = asyncio.Condition()
        self._changed = asyncio.Event()
        self._dirty_generation = 0
        self._durable_generation = 0
        self._write_active = False
        self._last_error: str | None = None
        self._next_retry_at: float | None = None
        self._first_dirty_at: float | None = None
        self._write_at: float | None = None
        self._retry_index = 0
        self._flush_generation = 0
        self._running = False
        self._write_task: asyncio.Task[object] | None = None

    @property
    def status(self) -> CheckpointStatus:
        return CheckpointStatus(
            dirty_generation=self._dirty_generation,
            durable_generation=self._durable_generation,
            write_active=self._write_active,
            last_error=self._last_error,
            next_retry_at=self._next_retry_at,
        )

    async def mark_dirty(self, generation: int) -> None:
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise ValueError("generation must be a non-negative integer")
        async with self._condition:
            if generation <= self._dirty_generation:
                return
            now = self._clock()
            starts_pending_window = self._dirty_generation <= self._durable_generation
            if starts_pending_window:
                self._first_dirty_at = now
                if self._next_retry_at is None:
                    self._write_at = min(now + self._start_delay, now + self._deadline)
            self._dirty_generation = generation
            self._notify_state_changed()

    async def flush(self) -> CheckpointStatus:
        async with self._condition:
            target = self._dirty_generation
            if target <= self._durable_generation:
                return self.status
            if not self._running:
                raise RuntimeError("checkpoint manager is not running")
            self._flush_generation = max(self._flush_generation, target)
            self._notify_state_changed()
            await self._condition.wait_for(lambda: self._durable_generation >= target or not self._running)
            if self._durable_generation < target:
                raise RuntimeError("checkpoint manager stopped before flush completed")
            return self.status

    async def run(self, stop: asyncio.Event) -> None:
        async with self._condition:
            if self._running:
                raise RuntimeError("checkpoint manager is already running")
            self._running = True
            self._notify_state_changed()
        try:
            while not stop.is_set():
                self._changed.clear()
                due_at = await self._next_write_time()
                if due_at is None:
                    await self._wait_for_change_or_stop(stop, None)
                    continue
                delay = max(0.0, due_at - self._clock())
                if delay:
                    changed = await self._wait_for_change_or_stop(stop, delay)
                    if stop.is_set():
                        break
                    if changed:
                        continue
                if stop.is_set():
                    break
                await self._write_once()
        finally:
            async with self._condition:
                self._running = False
                self._write_active = False
                self._notify_state_changed()

    async def _next_write_time(self) -> float | None:
        async with self._condition:
            if self._write_active or self._dirty_generation <= self._durable_generation:
                return None
            if self._next_retry_at is not None:
                return self._next_retry_at
            if self._flush_generation > self._durable_generation:
                return self._clock()
            return self._write_at

    async def _write_once(self) -> None:
        async with self._condition:
            if self._write_active or self._dirty_generation <= self._durable_generation:
                return
            target = self._dirty_generation
            snapshot = self._snapshot_supplier()
            self._write_active = True
            self._notify_state_changed()
        write_task = asyncio.create_task(asyncio.to_thread(self._store.write, snapshot))
        self._write_task = write_task
        cancellation_requested = False
        try:
            cancellation_requested = await await_uncancellable_completion(write_task)
            write_task.result()
        except Exception as exc:
            async with self._condition:
                self._write_active = False
                self._last_error = f"{type(exc).__name__}: checkpoint write failed"
                delay = self._backoff[min(self._retry_index, len(self._backoff) - 1)]
                self._retry_index += 1
                self._next_retry_at = self._clock() + delay
                self._notify_state_changed()
        else:
            async with self._condition:
                self._write_active = False
                self._durable_generation = max(self._durable_generation, target)
                self._last_error = None
                self._next_retry_at = None
                self._retry_index = 0
                if self._durable_generation >= self._dirty_generation:
                    self._first_dirty_at = None
                    self._write_at = None
                else:
                    now = self._clock()
                    first_dirty_at = self._first_dirty_at if self._first_dirty_at is not None else now
                    self._write_at = min(now + self._start_delay, first_dirty_at + self._deadline)
                if self._durable_generation >= self._flush_generation:
                    self._flush_generation = 0
                self._notify_state_changed()
        finally:
            self._write_task = None
        if cancellation_requested:
            raise asyncio.CancelledError

    async def _wait_for_change_or_stop(self, stop: asyncio.Event, delay: float | None) -> bool:
        if self._changed.is_set() or stop.is_set():
            return self._changed.is_set()
        changed_task = asyncio.create_task(self._changed.wait())
        stop_task = asyncio.create_task(stop.wait())
        tasks = {changed_task, stop_task}
        if delay is not None:
            tasks.add(asyncio.create_task(self._sleep(delay)))
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return changed_task in done

    def _notify_state_changed(self) -> None:
        self._changed.set()
        self._condition.notify_all()
