"""Thin official-SDK stdio port, with raw JSON-RPC trace and no tool retries."""

import asyncio
import sys
import time
from collections.abc import Callable
from contextlib import AsyncExitStack
from datetime import timedelta
from pathlib import Path
from traceback import walk_tb
from types import TracebackType
from typing import Any

from anyio import BrokenResourceError
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from harness_lab.timing import deadline_timeout

Trace = Callable[[str, dict[str, Any]], None]
STARTUP_REQUEST_TIMEOUT_S = 10.0


class _TracedStream:
    """Delegate SDK streams while observing actual wire message IDs and payloads."""

    def __init__(self, stream: Any, trace: Trace, direction: str):
        self.stream = stream
        self.trace = trace
        self.direction = direction

    def _record(self, message: Any) -> None:
        if isinstance(message, Exception):
            self.trace(self.direction, {"transport_error_type": type(message).__name__})
        else:
            self.trace(self.direction, message.message.model_dump(
                mode="json", by_alias=True, exclude_none=True
            ))

    async def send(self, message: Any) -> None:
        self._record(message)
        await self.stream.send(message)

    def __aiter__(self):
        return self

    async def __anext__(self):
        message = await self.stream.__anext__()
        self._record(message)
        return message

    async def __aenter__(self):
        await self.stream.__aenter__()
        return self

    async def __aexit__(self, *args: Any):
        return await self.stream.__aexit__(*args)


class MCPToolPort:
    """Own one SDK session/process; enter and exit must happen in the same task."""

    def __init__(self, config_path: Path, stderr_path: Path, trace: Trace | None = None):
        # The process owns its private startup config. This port never opens or parses it.
        self.config_path = Path(config_path).resolve()
        self.stderr_path = Path(stderr_path)
        self.trace: Trace = trace or (lambda _event, _data: None)
        self.tools: list[dict[str, Any]] = []
        self.initialize_result: dict[str, Any] | None = None
        self.cleanup_completed = False
        self.closing = False
        self.cleanup_elapsed_s: float | None = None
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None
        self._owner_task: asyncio.Task | None = None

    async def __aenter__(self):
        if self._stack is not None:
            raise RuntimeError("MCPToolPort is already entered")
        self.closing = False
        self._owner_task = asyncio.current_task()
        self._stack = AsyncExitStack()
        self.stderr_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            errlog = self._stack.enter_context(self.stderr_path.open("w", encoding="utf-8"))
            process = StdioServerParameters(
                command=sys.executable,
                args=["-m", "harness_lab.tool_server", str(self.config_path)],
            )
            read_stream, write_stream = await self._stack.enter_async_context(
                stdio_client(process, errlog=errlog)
            )
            self._session = await self._stack.enter_async_context(ClientSession(
                _TracedStream(read_stream, self.trace, "wire_receive"),
                _TracedStream(write_stream, self.trace, "wire_send"),
                read_timeout_seconds=timedelta(seconds=STARTUP_REQUEST_TIMEOUT_S),
            ))
            initialized = await self._session.initialize()
            self.initialize_result = initialized.model_dump(mode="json", by_alias=True)
            self.trace("mcp_initialized", self.initialize_result)
            listed = await self._session.list_tools()
            self.tools = [tool.model_dump(mode="json", by_alias=True) for tool in listed.tools]
            self.trace("mcp_tools", {"tools": self.tools})
            return self
        except BaseException:
            # Startup cancellation is consumed before leaving SDK-owned scopes.
            # The caller still receives the original cancellation after cleanup.
            if self._owner_task.cancelling():
                self._owner_task.uncancel()
            await self.__aexit__(*sys.exc_info())
            raise

    async def call(self, name: str, args: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError("MCPToolPort is not entered")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        # The precise Host/port deadline remains timeout_s. The SDK timer is a
        # fallback: its coarse loop clock must not cancel before that deadline.
        sdk_timeout = timeout_s + 2 * time.get_clock_info("monotonic").resolution
        async with deadline_timeout(timeout_s):
            response = await self._session.call_tool(
                name, args, read_timeout_seconds=timedelta(seconds=sdk_timeout)
            )
        return response.model_dump(mode="json", by_alias=True)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        if asyncio.current_task() is not self._owner_task:
            raise RuntimeError("Enter and exit MCPToolPort in the same task")
        self.closing = True
        started = time.perf_counter()
        completed = False
        try:
            if self._stack is not None:
                # Host control-flow errors do not belong to the SDK task groups.
                # Passing one into their __aexit__ would wrap it in ExceptionGroup.
                # Close normally in this same task, then let Python propagate it unchanged.
                try:
                    await self._stack.aclose()
                except* BrokenResourceError as errors:
                    # SDK 1.30 can race: ClientSession closes its receive stream
                    # while stdio's stdout reader sends the last reply. The exit
                    # stack has still joined both task groups and closed the process.
                    # Only this shutdown-only closed-pipe error is benign.
                    _, unexpected = errors.split(lambda exc: isinstance(exc, BrokenResourceError)
                        and any(frame.f_globals.get("__name__") == "mcp.client.stdio"
                                and frame.f_code.co_name == "stdout_reader"
                                for frame, _ in walk_tb(exc.__traceback__)))
                    if unexpected is not None:
                        raise unexpected
                    self.trace("mcp_shutdown_closed_pipe", {})
            completed = True
            return False
        finally:
            self._session = None
            self._stack = None
            self.cleanup_completed = completed
            self.cleanup_elapsed_s = time.perf_counter() - started
            self.trace("mcp_cleanup", {
                "completed": completed, "elapsed_s": self.cleanup_elapsed_s,
            })
