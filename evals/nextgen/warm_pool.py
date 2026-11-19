"""Module 1A: Persistent warm MCP sandbox worker pool eliminating 1.83s cold-start per run."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Any

from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, ErrorData

from evals.development import read
from evals.formal import atomic, journal
from evals.nextgen import PROJECT, assert_nextgen_artifact_safe, dist_stats, paired_comparison_stats
from evals.run_case import prepare_case
from harness_lab.contracts import Ports, RunConfig, TaskInput
from harness_lab.mcp_port import MCPToolPort
from harness_lab.models import ScriptedController
from harness_lab.runtime import run as runtime_run
from harness_lab.timing import deadline_timeout
from harness_lab.tool_server import (
    ReadRequest,
    ResponseFault,
    ServerConfig,
    ToolService,
    WriteRequest,
    build_server,
    error,
)
from harness_lab.trace import replay, source_revision

Trace = Callable[[str, dict[str, Any]], None]

INIT_RESULT_TEMPLATE: dict[str, Any] = {
    "protocolVersion": "2025-11-25",
    "capabilities": {
        "experimental": {},
        "prompts": {"listChanged": False},
        "resources": {"subscribe": False, "listChanged": False},
        "tools": {"listChanged": False},
    },
    "serverInfo": {"name": "harness-local-tools", "version": "1.30.0"},
}


async def _worker_main() -> None:
    """Long-lived isolated worker loop serving sequential sessions over line-delimited JSON-RPC."""
    import tempfile
    import threading

    from harness_lab.storage import initialize_environment

    loop = asyncio.get_running_loop()
    in_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def _stdin_pump() -> None:
        while True:
            raw_line = sys.stdin.buffer.readline()
            loop.call_soon_threadsafe(in_queue.put_nowait, raw_line)
            if not raw_line:
                break

    threading.Thread(target=_stdin_pump, name="warm-worker-stdin", daemon=True).start()
    write_lock = asyncio.Lock()

    async def send_frame(frame: dict[str, Any]) -> None:
        raw = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
        async with write_lock:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()

    cached_tools_payload: list[dict[str, Any]] | None = None
    active_service: ToolService | None = None
    active_config: ServerConfig | None = None
    inflight_tasks: set[asyncio.Task[None]] = set()
    hang_on_method: str | None = None

    async def _ensure_tools_cached() -> None:
        nonlocal cached_tools_payload
        if cached_tools_payload is not None:
            return
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_db = Path(tmp_dir) / "prime.sqlite"
            initialize_environment(
                tmp_db,
                {
                    "target_ref": "prime",
                    "revision": 1,
                    "queue_options": ["ops"],
                    "write_policy": "allow",
                    "facts": {},
                },
            )
            prime_cfg = ServerConfig(
                db_path=str(tmp_db),
                run_id="prime",
                principal="prime",
                operation_id="prime:write-0",
                idempotency_key="prime:write-0",
                target_ref="prime",
                can_read=True,
                can_write=True,
            )
            mcp_srv, tmp_svc = build_server(prime_cfg)
            try:
                listed = await mcp_srv.list_tools()
                cached_tools_payload = [
                    t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in listed
                ]
            finally:
                tmp_svc.store.close()

    async def handle_tool_call(
        req_id: int | str,
        name: str,
        arguments: dict[str, Any],
        service: ToolService,
        cfg: ServerConfig,
    ) -> None:
        models = {"read_state": ReadRequest, "create_ticket": WriteRequest}
        fault = cfg.fault
        if name in models and isinstance(fault, ResponseFault) and fault.kind == "protocol_error":
            try:
                parsed = models[name].model_validate(arguments)
                service.authorize(
                    parsed.target_ref, parsed.envelope, write=(name == "create_ticket")
                )
                if fault.matches(parsed.envelope):
                    await send_frame(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32603, "message": "Tool protocol failure"},
                        }
                    )
                    return
            except Exception:
                pass

        if name not in models:
            res = error("INVALID_REQUEST", f"Unknown tool: {name}")
        else:
            try:
                validated = models[name].model_validate(arguments)
            except Exception:
                res = error("INVALID_REQUEST", "Tool arguments do not match the strict schema")
            else:
                if name == "read_state":
                    res = await service.read_state(validated.target_ref, validated.envelope)
                else:
                    params = {
                        "target_ref": validated.target_ref,
                        "expected_revision": validated.expected_revision,
                        "queue": validated.queue,
                        "priority": validated.priority,
                    }
                    res = await service.create_ticket(params, validated.envelope)

        dumped = res.model_dump(mode="json", by_alias=True, exclude_none=True)
        await send_frame({"jsonrpc": "2.0", "id": req_id, "result": dumped})

    while True:
        line = await in_queue.get()
        if not line:
            break
        msg = json.loads(line.decode("utf-8"))
        method = msg.get("method")
        req_id = msg.get("id")

        if hang_on_method is not None and method == hang_on_method:
            # Simulate wedged stdio pipe (mirrors historical Windows stdio handshake/RPC hang)
            await asyncio.Event().wait()

        if method == "__warmup__":
            await _ensure_tools_cached()
            await send_frame({"__control__": "ready", "id": req_id})
        elif method == "__inject_hang__":
            target_method = str(msg.get("on_method", "initialize"))
            if target_method == "immediate":
                await asyncio.Event().wait()
            hang_on_method = target_method
            await send_frame(
                {"__control__": "hang_armed", "id": req_id, "on_method": hang_on_method}
            )
        elif method == "__bind_session__":
            await _ensure_tools_cached()
            cfg_data = json.loads(Path(msg["config_path"]).read_text(encoding="utf-8"))
            active_config = ServerConfig.model_validate(cfg_data)
            active_service = ToolService(active_config)
            active_service.initial_read_seen = bool(msg.get("initial_read_seen", False))
            await send_frame({"__control__": "bound", "id": req_id})
        elif method == "__close_session__":
            if inflight_tasks:
                await asyncio.gather(*inflight_tasks, return_exceptions=True)
                inflight_tasks.clear()
            if active_service is not None:
                active_service.store.close()
                active_service = None
                active_config = None
            await send_frame({"__control__": "closed", "id": req_id})
        elif method == "__shutdown__":
            if active_service is not None:
                active_service.store.close()
            await send_frame({"__control__": "bye", "id": req_id})
            break
        elif method == "initialize":
            await send_frame({"jsonrpc": "2.0", "id": req_id, "result": INIT_RESULT_TEMPLATE})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            await send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": cached_tools_payload or []},
                }
            )
        elif method == "tools/call":
            assert active_service is not None and active_config is not None
            params = msg.get("params") or {}
            task = asyncio.create_task(
                handle_tool_call(
                    req_id,
                    params.get("name", ""),
                    params.get("arguments") or {},
                    active_service,
                    active_config,
                )
            )
            inflight_tasks.add(task)
            task.add_done_callback(inflight_tasks.discard)


class _WarmWorkerHandle:
    """Owns one warm worker OS process and multiplexes responses by request ID."""

    def __init__(self, process: asyncio.subprocess.Process):
        self.process = process
        self.pid: int | None = process.pid
        self.pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self.trace: Trace = lambda _e, _d: None
        self.accept_wire = False
        self.healthy = True
        self.pipes_closed = False
        self._closed = False
        self._reader_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                raw = await self.process.stdout.readline()
                if not raw:
                    raise RuntimeError("Warm worker closed stdout unexpectedly")
                frame = json.loads(raw.decode("utf-8"))
                if "__control__" in frame:
                    fut = self.pending.pop(frame["id"], None)
                    if fut is not None and not fut.done():
                        fut.set_result(frame)
                    continue
                if self.accept_wire:
                    self.trace("wire_receive", frame)
                fut = self.pending.pop(frame.get("id"), None)
                if fut is not None and not fut.done():
                    fut.set_result(frame)
        except BaseException as exc:
            if not self._closed:
                self.healthy = False
            if not isinstance(exc, asyncio.CancelledError):
                for fut in list(self.pending.values()):
                    if not fut.done():
                        fut.set_exception(exc)
                self.pending.clear()

    async def control(self, payload: dict[str, Any], *, timeout_s: float = 5.0) -> dict[str, Any]:
        if not self.healthy or self.process.returncode is not None:
            self.healthy = False
            raise RuntimeError("Warm worker process is not healthy")
        assert self.process.stdin is not None
        cid = f"ctl-{id(payload)}-{time.perf_counter_ns()}"
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[cid] = fut
        try:
            async with deadline_timeout(timeout_s):
                self.process.stdin.write(
                    (json.dumps({**payload, "id": cid}, ensure_ascii=False) + "\n").encode("utf-8")
                )
                await self.process.stdin.drain()
                return await fut
        except BaseException:
            self.healthy = False
            raise
        finally:
            self.pending.pop(cid, None)

    async def rpc(
        self, frame: dict[str, Any], *, expect_reply: bool = True
    ) -> dict[str, Any] | None:
        if not self.healthy or self.process.returncode is not None:
            self.healthy = False
            raise RuntimeError("Warm worker process is not healthy")
        assert self.process.stdin is not None
        self.trace("wire_send", frame)
        raw = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
        if not expect_reply:
            try:
                self.process.stdin.write(raw)
                await self.process.stdin.drain()
            except BaseException:
                self.healthy = False
                raise
            return None
        req_id = frame["id"]
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[req_id] = fut
        try:
            self.process.stdin.write(raw)
            await self.process.stdin.drain()
            return await fut
        except (BrokenPipeError, ConnectionResetError, RuntimeError):
            self.healthy = False
            raise
        finally:
            self.pending.pop(req_id, None)

    async def _reap_and_close_pipes(self, *, graceful: bool) -> None:
        if self._closed and self.pipes_closed:
            return
        self._closed = True
        self.accept_wire = False
        self.trace = lambda _e, _d: None
        if graceful and self.healthy and self.process.returncode is None:
            try:
                await self.control({"method": "__shutdown__"}, timeout_s=1.0)
            except Exception:
                graceful = False
        self.healthy = False
        for fut in list(self.pending.values()):
            if not fut.done():
                fut.cancel()
        self.pending.clear()
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except Exception:
                pass
        if graceful and self.process.returncode is None:
            try:
                await asyncio.wait_for(self.process.wait(), timeout=1.0)
            except Exception:
                graceful = False
        if self.process.returncode is None:
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
            await asyncio.wait_for(self.process.wait(), timeout=5.0)
        if not self._reader_task.done():
            self._reader_task.cancel()
        await asyncio.gather(self._reader_task, return_exceptions=True)

        # Explicitly close underlying Windows Proactor / POSIX pipe transports to avoid handle leaks
        proc_transport = getattr(self.process, "_transport", None)
        if proc_transport is not None:
            for fd in (0, 1, 2):
                try:
                    pipe_tr = proc_transport.get_pipe_transport(fd)
                    if pipe_tr is not None:
                        pipe_tr.close()
                except Exception:
                    pass
            try:
                proc_transport.close()
            except Exception:
                pass
        await asyncio.sleep(0)
        self.pipes_closed = True

    async def force_kill(self) -> None:
        """Immediately kill a wedged worker subprocess and close all stdio pipe handles."""
        await self._reap_and_close_pipes(graceful=False)

    async def terminate(self) -> None:
        await self._reap_and_close_pipes(graceful=True)


class WarmWorkerPool:
    """Reusable pool of pre-imported MCP tool worker subprocesses with watchdog self-healing."""

    def __init__(
        self,
        size: int = 1,
        *,
        spawn_timeout_s: float = 10.0,
        handshake_timeout_s: float = 5.0,
        control_timeout_s: float = 5.0,
    ):
        if size < 1:
            raise ValueError("Pool size must be >= 1")
        if spawn_timeout_s <= 0 or handshake_timeout_s <= 0 or control_timeout_s <= 0:
            raise ValueError("Watchdog timeouts must be positive")
        self.size = size
        self.spawn_timeout_s = spawn_timeout_s
        self.handshake_timeout_s = handshake_timeout_s
        self.control_timeout_s = control_timeout_s
        self._idle: asyncio.Queue[_WarmWorkerHandle] = asyncio.Queue()
        self._all: list[_WarmWorkerHandle] = []
        self.boot_elapsed_s: float = 0.0
        self.watchdog_kills: int = 0
        self.replacements_spawned: int = 0

    async def _spawn_one(self) -> _WarmWorkerHandle:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "evals.nextgen.warm_pool",
            "--worker",
            cwd=str(PROJECT),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=4 * 1024 * 1024,
        )
        handle = _WarmWorkerHandle(proc)
        try:
            await handle.control({"method": "__warmup__"}, timeout_s=self.spawn_timeout_s)
        except BaseException:
            await handle.force_kill()
            raise
        return handle

    async def __aenter__(self) -> WarmWorkerPool:
        t0 = time.perf_counter()
        try:
            for _ in range(self.size):
                worker = await self._spawn_one()
                self._all.append(worker)
                self._idle.put_nowait(worker)
        except BaseException:
            await self.__aexit__(*sys.exc_info())
            raise
        self.boot_elapsed_s = time.perf_counter() - t0
        return self

    async def discard_and_replace(self, broken: _WarmWorkerHandle) -> _WarmWorkerHandle:
        """Kill a wedged worker, close its pipes cleanly, and spawn a fresh replacement."""
        if broken in self._all:
            self._all.remove(broken)
        await broken.force_kill()
        self.watchdog_kills += 1
        replacement = await self._spawn_one()
        self._all.append(replacement)
        self.replacements_spawned += 1
        self._idle.put_nowait(replacement)
        return replacement

    async def acquire(self) -> _WarmWorkerHandle:
        worker = await self._idle.get()
        if (
            not worker.healthy
            or worker.process.returncode is not None
            or worker._reader_task.done()
        ):
            await self.discard_and_replace(worker)
            worker = await self._idle.get()
        return worker

    def release(self, worker: _WarmWorkerHandle) -> None:
        self._idle.put_nowait(worker)

    async def __aexit__(self, *_: Any) -> None:
        await asyncio.gather(*(w.terminate() for w in list(self._all)), return_exceptions=True)
        self._all.clear()


class PooledToolPort:
    """Drop-in duck-typed replacement for MCPToolPort backed by WarmWorkerPool."""

    def __init__(
        self,
        pool: WarmWorkerPool,
        config_path: Path,
        stderr_path: Path,
        trace: Trace | None = None,
        *,
        initial_read_seen: bool = False,
        handshake_timeout_s: float | None = None,
    ):
        self.pool = pool
        self.config_path = Path(config_path).resolve()
        self.stderr_path = Path(stderr_path)
        self.trace: Trace = trace or (lambda _e, _d: None)
        self.initial_read_seen = initial_read_seen
        self.handshake_timeout_s = (
            handshake_timeout_s if handshake_timeout_s is not None else pool.handshake_timeout_s
        )
        self.tools: list[dict[str, Any]] = []
        self.initialize_result: dict[str, Any] | None = None
        self.cleanup_completed = False
        self.closing = False
        self.cleanup_elapsed_s: float | None = None
        self._worker: _WarmWorkerHandle | None = None
        self._worker_tainted = False
        self._had_call_timeout = False
        self._next_id = 0
        self._owner_task: asyncio.Task[Any] | None = None

    def _alloc_id(self) -> int:
        req_id = self._next_id
        self._next_id += 1
        return req_id

    async def __aenter__(self) -> PooledToolPort:
        self.closing = False
        self._worker_tainted = False
        self._had_call_timeout = False
        self._owner_task = asyncio.current_task()
        self.stderr_path.parent.mkdir(parents=True, exist_ok=True)
        self.stderr_path.write_text("", encoding="utf-8")
        worker = await self.pool.acquire()
        self._worker = worker
        worker.trace = self.trace
        try:
            async with deadline_timeout(self.handshake_timeout_s):
                await worker.control(
                    {
                        "method": "__bind_session__",
                        "config_path": str(self.config_path),
                        "initial_read_seen": self.initial_read_seen,
                    },
                    timeout_s=self.handshake_timeout_s,
                )
                worker.accept_wire = True
                init_resp = await worker.rpc(
                    {
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {"name": "mcp", "version": "0.1.0"},
                        },
                        "jsonrpc": "2.0",
                        "id": self._alloc_id(),
                    }
                )
                assert init_resp is not None and "result" in init_resp
                await worker.rpc(
                    {"method": "notifications/initialized", "jsonrpc": "2.0"}, expect_reply=False
                )
                from mcp.types import InitializeResult, ListToolsResult

                init_model = InitializeResult.model_validate(init_resp["result"])
                self.initialize_result = init_model.model_dump(mode="json", by_alias=True)
                self.trace("mcp_initialized", self.initialize_result)

                list_resp = await worker.rpc(
                    {
                        "method": "tools/list",
                        "jsonrpc": "2.0",
                        "id": self._alloc_id(),
                    }
                )
                assert list_resp is not None and "result" in list_resp
                listed_model = ListToolsResult.model_validate(list_resp["result"])
                self.tools = [t.model_dump(mode="json", by_alias=True) for t in listed_model.tools]
                self.trace("mcp_tools", {"tools": self.tools})
                return self
        except BaseException:
            self._worker_tainted = True
            if self._owner_task and self._owner_task.cancelling():
                self._owner_task.uncancel()
            await self.__aexit__(*sys.exc_info())
            raise

    async def call(self, name: str, args: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        if self._worker is None:
            raise RuntimeError("PooledToolPort is not entered")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        req_id = self._alloc_id()
        try:
            async with deadline_timeout(timeout_s):
                resp = await self._worker.rpc(
                    {
                        "method": "tools/call",
                        "params": {"name": name, "arguments": args},
                        "jsonrpc": "2.0",
                        "id": req_id,
                    }
                )
        except TimeoutError:
            self._had_call_timeout = True
            raise
        except (BrokenPipeError, ConnectionResetError, RuntimeError):
            self._worker_tainted = True
            raise
        assert resp is not None
        if "error" in resp:
            err = resp["error"]
            raise McpError(ErrorData(code=err["code"], message=err["message"]))
        validated = CallToolResult.model_validate(resp["result"])
        return validated.model_dump(mode="json", by_alias=True)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        if asyncio.current_task() is not self._owner_task:
            raise RuntimeError("Enter and exit PooledToolPort in the same task")
        self.closing = True
        started = time.perf_counter()
        completed = False
        worker = self._worker
        self._worker = None
        saved_cancels = 0
        while self._owner_task is not None and self._owner_task.cancelling() > 0:
            self._owner_task.uncancel()
            saved_cancels += 1
        try:
            if worker is not None:
                needs_heal = (
                    self._worker_tainted
                    or not worker.healthy
                    or worker.process.returncode is not None
                )
                if not needs_heal:
                    close_timeout = (
                        min(self.pool.control_timeout_s, 1.0)
                        if self._had_call_timeout
                        else self.pool.control_timeout_s
                    )
                    try:
                        await worker.control(
                            {"method": "__close_session__"}, timeout_s=close_timeout
                        )
                        worker.accept_wire = False
                        worker.trace = lambda _e, _d: None
                        worker.pending.clear()
                        self.pool.release(worker)
                    except BaseException:
                        needs_heal = True
                if needs_heal:
                    await self.pool.discard_and_replace(worker)
                    self.trace("mcp_watchdog_healed", {"replaced_pid": worker.pid})
            completed = True
            return False
        finally:
            for _ in range(saved_cancels):
                assert self._owner_task is not None
                self._owner_task.cancel()
            self.cleanup_completed = completed
            self.cleanup_elapsed_s = time.perf_counter() - started
            self.trace("mcp_cleanup", {"completed": completed, "elapsed_s": self.cleanup_elapsed_s})


async def run_warm_pool_benchmark(output_dir: Path, *, repeats: int = 2) -> dict[str, Any]:
    """Compare C0 cold MCPToolPort vs T1 PooledToolPort across all 18 frozen tasks."""
    from evals.diagnostics import decompose_run_latency
    from evals.grader import grade
    from evals.protocol_audit import verify_protocol

    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("Use a fresh benchmark output directory")
    manifest = read(PROJECT / "tasks/frozen/manifest.json")
    tasks = manifest["tasks"]

    cold_rows: list[dict[str, Any]] = []
    warm_rows: list[dict[str, Any]] = []

    work_root = output_dir / "_runs"
    work_root.mkdir(parents=True, exist_ok=False)

    # First run C0 (cold stdio subprocess per trial)
    for rep in range(1, repeats + 1):
        for entry in tasks:
            case_path = PROJECT / "tasks/frozen" / entry["file"]
            slot = f"{entry['id']}-r{rep}-cold"
            run_dir = work_root / "cold" / slot
            prep = prepare_case(case_path, run_dir)
            cfg = RunConfig(
                run_id=prep["run_id"],
                principal=prep["principal"],
                artifact_dir=run_dir,
                policy="P2",
                seed=7000 + rep,
            )
            port = MCPToolPort(prep["server_path"], run_dir / "mcp-stderr.log")
            await runtime_run(
                TaskInput(**prep["task_input"]), cfg, Ports(ScriptedController(), port)
            )
            rec = replay(run_dir)
            evs = journal(run_dir / "trace.jsonl")
            verify_protocol(evs)
            sc = grade(rec, prep["database"], prep["oracle"])
            lat = decompose_run_latency(evs)
            cold_rows.append(
                {
                    "slot": slot,
                    "task_id": entry["id"],
                    "repeat": rep,
                    "startup_s": lat["mcp_breakdown_s"]["mcp_startup_s"],
                    "tool_calls_s": lat["mcp_breakdown_s"]["mcp_tool_calls_s"],
                    "cleanup_s": lat["stages_s"]["cleanup_s"],
                    "total_s": rec["costs"]["total_s"],
                    "signature": {
                        k: sc[k]
                        for k in (
                            "correct_disposition",
                            "goal_completed",
                            "false_allow",
                            "duplicate_effect",
                        )
                    },
                }
            )

    # Next run T1 (warm worker pool across all trials, priming 1st task discovery in pool)
    async with WarmWorkerPool(size=1) as pool:
        for rep in range(1, repeats + 1):
            for entry in tasks:
                case_path = PROJECT / "tasks/frozen" / entry["file"]
                slot = f"{entry['id']}-r{rep}-warm"
                run_dir = work_root / "warm" / slot
                prep = prepare_case(case_path, run_dir)
                cfg = RunConfig(
                    run_id=prep["run_id"],
                    principal=prep["principal"],
                    artifact_dir=run_dir,
                    policy="P2",
                    seed=7000 + rep,
                )
                port = PooledToolPort(pool, prep["server_path"], run_dir / "mcp-stderr.log")
                await runtime_run(
                    TaskInput(**prep["task_input"]), cfg, Ports(ScriptedController(), port)
                )
                rec = replay(run_dir)
                evs = journal(run_dir / "trace.jsonl")
                verify_protocol(evs)
                sc = grade(rec, prep["database"], prep["oracle"])
                lat = decompose_run_latency(evs)
                warm_rows.append(
                    {
                        "slot": slot,
                        "task_id": entry["id"],
                        "repeat": rep,
                        "startup_s": lat["mcp_breakdown_s"]["mcp_startup_s"],
                        "tool_calls_s": lat["mcp_breakdown_s"]["mcp_tool_calls_s"],
                        "cleanup_s": lat["stages_s"]["cleanup_s"],
                        "total_s": rec["costs"]["total_s"],
                        "signature": {
                            k: sc[k]
                            for k in (
                                "correct_disposition",
                                "goal_completed",
                                "false_allow",
                                "duplicate_effect",
                            )
                        },
                    }
                )
        pool_boot_s = round(pool.boot_elapsed_s, 6)

    # Remove raw run scratch subdirs containing private-server.json db_path before sealing summary
    import shutil

    shutil.rmtree(work_root)

    # Verify exact decision parity on every (task, repeat) pair
    parity_mismatches = [
        c["slot"]
        for c, w in zip(cold_rows, warm_rows, strict=True)
        if c["signature"] != w["signature"]
    ]
    if parity_mismatches:
        raise AssertionError(f"Warm pool decision parity mismatch: {parity_mismatches}")

    cold_startups = [r["startup_s"] for r in cold_rows]
    warm_startups = [r["startup_s"] for r in warm_rows]
    startup_diffs = [w - c for c, w in zip(cold_startups, warm_startups, strict=True)]
    cold_med = dist_stats(cold_startups)["median_s"]
    warm_med = dist_stats(warm_startups)["median_s"]
    assert cold_med is not None and warm_med is not None
    reduction_ratio = round(1.0 - (warm_med / cold_med), 6)

    summary = {
        "schema": "nextgen-m1a-warm-pool-v1",
        "source": source_revision(),
        "model_api_calls": 0,
        "pool_one_time_boot_s": pool_boot_s,
        "trials_per_arm": len(cold_rows),
        "decision_parity_100_percent": True,
        "replay_and_protocol_audit_passed": True,
        "cold_subprocess_c0": {
            "startup_s": dist_stats(cold_startups),
            "cleanup_s": dist_stats([r["cleanup_s"] for r in cold_rows]),
            "total_s": dist_stats([r["total_s"] for r in cold_rows]),
        },
        "warm_pool_t1": {
            "startup_s": dist_stats(warm_startups),
            "cleanup_s": dist_stats([r["cleanup_s"] for r in warm_rows]),
            "total_s": dist_stats([r["total_s"] for r in warm_rows]),
        },
        "median_startup_reduction_ratio": reduction_ratio,
        "paired_startup_delta_s": paired_comparison_stats(startup_diffs),
    }
    assert_nextgen_artifact_safe(summary)
    assert_nextgen_artifact_safe(cold_rows)
    assert_nextgen_artifact_safe(warm_rows)
    atomic(output_dir / "summary.json", summary)
    atomic(output_dir / "cold_c0_runs.jsonl", cold_rows, lines=True)
    atomic(output_dir / "warm_t1_runs.jsonl", warm_rows, lines=True)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=2)
    args = parser.parse_args()
    if args.worker:
        asyncio.run(_worker_main())
        return
    if args.output is None:
        parser.error("--output is required when not running --worker")
    res = asyncio.run(run_warm_pool_benchmark(args.output, repeats=args.repeats))
    print(
        json.dumps(
            {
                "trials_per_arm": res["trials_per_arm"],
                "cold_median_startup_s": res["cold_subprocess_c0"]["startup_s"]["median_s"],
                "warm_median_startup_s": res["warm_pool_t1"]["startup_s"]["median_s"],
                "median_startup_reduction_ratio": res["median_startup_reduction_ratio"],
                "decision_parity": res["decision_parity_100_percent"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
