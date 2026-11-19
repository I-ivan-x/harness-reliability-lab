"""Real deadlines without early cancellation on coarse asyncio clocks."""

import asyncio
import math
import time
from contextlib import asynccontextmanager


@asynccontextmanager
async def deadline_timeout(delay_s: float):
    """Use a high-resolution deadline; stdlib retains cancellation ownership.

    asyncio timer callbacks can run one scheduler tick early. Recheck the real
    deadline before arming cancellation, without changing the caller's loop.
    Scheduling and cleanup may finish late; this is not a hard real-time timer.
    """
    if not math.isfinite(delay_s) or delay_s <= 0:
        raise ValueError("timeout must be finite and positive")
    loop = asyncio.get_running_loop()
    deadline = time.perf_counter() + delay_s
    resolution = time.get_clock_info("monotonic").resolution
    async with asyncio.timeout(None) as scope:
        def check_deadline():
            nonlocal handle
            remaining = deadline - time.perf_counter()
            if remaining > 0:
                # Avoid a busy loop when a coarse scheduler wakes us early again.
                handle = loop.call_later(max(remaining, resolution), check_deadline)
            else:
                scope.reschedule(loop.time())

        handle = loop.call_later(delay_s, check_deadline)
        try:
            yield
        finally:
            handle.cancel()
