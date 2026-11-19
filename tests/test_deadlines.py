"""Real deadline boundaries and stdlib cancellation ownership on an ordinary loop."""

import asyncio
from time import perf_counter

import pytest

from harness_lab.timing import deadline_timeout


def observe_timers(loop, monkeypatch):
    """Track only this test's callbacks, including callbacks explicitly fired early."""
    original, timers = loop.call_later, []

    def call_later(delay, callback, *args, context=None):
        timer = {"fired": False}

        def fire():
            timer["fired"] = True
            callback(*args)

        timer["fire"] = fire
        timer["handle"] = original(delay, fire, context=context)
        timers.append(timer)
        return timer["handle"]

    monkeypatch.setattr(loop, "call_later", call_later)
    return timers


def assert_no_pending_timers(timers):
    assert timers
    assert all(timer["fired"] or timer["handle"].cancelled() for timer in timers)


def test_early_scheduler_callback_waits_for_the_real_deadline(monkeypatch):
    async def check():
        timers = observe_timers(asyncio.get_running_loop(), monkeypatch)
        delay, started = .18, perf_counter()
        with pytest.raises(TimeoutError):
            async with deadline_timeout(delay):
                # Invoke the first queued callback immediately after scope entry,
                # when its handle is assigned; no scheduling race or inline reentry.
                first = timers[0]
                first["handle"].cancel()
                first["fire"]()
                assert len(timers) == 2
                assert asyncio.current_task().cancelling() == 0
                await asyncio.Event().wait()
        assert perf_counter() - started >= delay
        assert asyncio.current_task().cancelling() == 0
        assert_no_pending_timers(timers)
        await asyncio.sleep(0)
        assert asyncio.current_task().cancelling() == 0

    asyncio.run(check())


@pytest.mark.parametrize("raises", [False, True])
def test_scope_exit_cleans_up_the_deadline_handle(monkeypatch, raises):
    async def check():
        timers = observe_timers(asyncio.get_running_loop(), monkeypatch)

        async def work():
            async with deadline_timeout(10):
                if raises:
                    raise LookupError("body failure")

        if raises:
            with pytest.raises(LookupError, match="body failure"):
                await work()
        else:
            await work()
        assert len(timers) == 1 and timers[0]["handle"].cancelled()
        assert asyncio.current_task().cancelling() == 0

    asyncio.run(check())


@pytest.mark.parametrize("cancel_count", [1, 2])
def test_external_cancellation_keeps_its_ownership_and_cleans_up(monkeypatch, cancel_count):
    async def check():
        timers = observe_timers(asyncio.get_running_loop(), monkeypatch)
        entered = asyncio.Event()

        async def work():
            async with deadline_timeout(10):
                entered.set()
                await asyncio.Event().wait()

        worker = asyncio.create_task(work())
        await entered.wait()
        for _ in range(cancel_count):
            worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        assert worker.cancelled() and worker.cancelling() == cancel_count
        assert len(timers) == 1 and timers[0]["handle"].cancelled()
        assert asyncio.current_task().cancelling() == 0

    asyncio.run(check())


@pytest.mark.parametrize("expires", ["inner", "outer"])
def test_nested_scopes_convert_only_their_own_cancellation(monkeypatch, expires):
    async def check():
        timers = observe_timers(asyncio.get_running_loop(), monkeypatch)
        if expires == "inner":
            async with deadline_timeout(10):
                with pytest.raises(TimeoutError):
                    async with deadline_timeout(.03):
                        await asyncio.Event().wait()
                assert asyncio.current_task().cancelling() == 0
                await asyncio.sleep(0)
        else:
            with pytest.raises(TimeoutError):
                async with deadline_timeout(.03), deadline_timeout(10):
                    await asyncio.Event().wait()
        assert asyncio.current_task().cancelling() == 0
        assert_no_pending_timers(timers)

    asyncio.run(check())


def test_external_cancel_during_expiry_is_not_converted_to_timeout(monkeypatch):
    async def check():
        timers = observe_timers(asyncio.get_running_loop(), monkeypatch)

        async def work():
            async with deadline_timeout(.03):
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    # Add another cancellation at a known boundary, after the
                    # deadline's cancel and before its context manager exits.
                    task = asyncio.current_task()
                    assert task.cancelling() == 1
                    task.cancel()
                    raise

        worker = asyncio.create_task(work())
        with pytest.raises(asyncio.CancelledError):
            await worker
        assert worker.cancelled() and worker.cancelling() == 1
        assert_no_pending_timers(timers)
        assert asyncio.current_task().cancelling() == 0

    asyncio.run(check())
