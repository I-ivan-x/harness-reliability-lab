"""Real stdio MCP server with one fixed business write effect per run."""

import argparse
import asyncio
import json
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolRequest, CallToolResult, ErrorData, TextContent, Tool
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from harness_lab.storage import EnvironmentStore, ToolRejection, canonical_json


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Envelope(StrictModel):
    run_id: str
    principal: str
    operation_id: str
    idempotency_key: str
    attempt: int = Field(ge=1)
    stage: Literal["initial_read", "write-0", "refresh_read"]


class ReadRequest(StrictModel):
    target_ref: str
    envelope: Envelope


class WriteRequest(ReadRequest):
    expected_revision: int = Field(ge=0)
    queue: str = Field(min_length=1)
    priority: Literal["normal", "urgent"]


class SelectedFault(StrictModel):
    stage: Literal["initial_read", "write-0", "refresh_read"] = "write-0"
    attempts: list[Annotated[int, Field(ge=1)]] | None = Field(default=None, min_length=1)

    def matches(self, envelope: Envelope) -> bool:
        return self.stage == envelope.stage and (
            self.attempts is None or envelope.attempt in self.attempts
        )


class DelayFault(SelectedFault):
    kind: Literal["pre_commit_delay", "commit_response_delay"]
    delay_s: float = Field(gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def committed_write_only(self):
        if self.kind == "commit_response_delay" and self.stage != "write-0":
            raise ValueError("Committed response delay requires a write stage")
        return self


class ResponseFault(SelectedFault):
    kind: Literal["temporary_unavailable", "malformed_result", "protocol_error"]


class StatePatch(StrictModel):
    revision: int = Field(ge=0)
    queue_options: list[str] | None = Field(default=None, min_length=1)
    facts: dict[str, Any] | None = None


class StateChangeFault(StrictModel):
    kind: Literal["state_change"]
    attempt: Literal[1] = 1
    state_patch: StatePatch


class ServerConfig(StrictModel):
    db_path: str
    run_id: str
    principal: str
    operation_id: str
    idempotency_key: str
    target_ref: str
    can_read: bool
    can_write: bool
    fault: DelayFault | ResponseFault | StateChangeFault | None = None


def result(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        isError=not payload["ok"],
        structuredContent=payload,
        content=[TextContent(type="text", text=canonical_json(payload))],
    )


def error(code: str, message: str, *, repairable: bool = False) -> CallToolResult:
    return result({"ok": False, "error": {
        "code": code,
        "message": message,
        "repairable": repairable,
        "not_executed": repairable,
        "unbound": repairable,
    }})


class StrictFastMCP(FastMCP):
    """Validate raw arguments before FastMCP's compatibility coercion/extra discard."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        models = {"read_state": ReadRequest, "create_ticket": WriteRequest}
        if name in models:
            try:
                models[name].model_validate(arguments)
            except ValidationError:
                return error("INVALID_REQUEST", "Tool arguments do not match the strict schema")
        return await super().call_tool(name, arguments)

    async def list_tools(self) -> list[Tool]:
        tools = await super().list_tools()
        for tool in tools:
            tool.inputSchema["additionalProperties"] = False
        return tools


class ToolService:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.store = EnvironmentStore(config.db_path)
        self.lock = asyncio.Lock()
        # Registered before any await: delayed old requests remain visible to the whole slot.
        self.inflight: set[str] = set()
        self.initial_read_seen = False
        self.state_change_applied = False

    def authorize(self, target_ref: str, envelope: Envelope, *, write: bool = False) -> None:
        expected = self.config
        if (
            envelope.run_id != expected.run_id
            or envelope.principal != expected.principal
            or envelope.operation_id != expected.operation_id
            or envelope.idempotency_key != expected.idempotency_key
            or target_ref != expected.target_ref
            or not expected.can_read
        ):
            raise ToolRejection("PERMISSION_DENIED", "Request is outside the trusted grant")
        if (envelope.stage == "write-0") != write:
            raise ToolRejection("INVALID_REQUEST", "Operation stage does not match the tool")

    def selected_fault(self, envelope: Envelope) -> SelectedFault | None:
        fault = self.config.fault
        return fault if isinstance(fault, SelectedFault) and fault.matches(envelope) else None

    @staticmethod
    def deliver(payload: dict[str, Any], fault: SelectedFault | None) -> CallToolResult:
        if isinstance(fault, ResponseFault) and fault.kind == "malformed_result":
            # MCP remains valid; only the application schema is damaged.
            return CallToolResult(content=[TextContent(type="text", text="Invalid result")],
                                  structuredContent={"ok": "invalid"}, isError=False)
        return result(payload)

    async def read_state(self, target_ref: str, envelope: Envelope) -> CallToolResult:
        try:
            self.authorize(target_ref, envelope)
            fault = self.selected_fault(envelope)
            if isinstance(fault, ResponseFault) and fault.kind == "temporary_unavailable":
                return error("TEMPORARY_UNAVAILABLE", "Tool temporarily unavailable")
            if isinstance(fault, DelayFault):
                await asyncio.sleep(fault.delay_s)
            async with self.lock:
                state = self.store.read_state(target_ref)
                self.initial_read_seen |= envelope.stage == "initial_read"
                return self.deliver({"ok": True, "kind": "state", "state": state}, fault)
        except ToolRejection as exc:
            return error(exc.code, str(exc))
        except sqlite3.Error:
            return error("SYSTEM_FAILURE", "Environment database operation failed")

    async def create_ticket(self, params: dict[str, Any], envelope: Envelope) -> CallToolResult:
        try:
            self.authorize(params["target_ref"], envelope, write=True)
        except ToolRejection as exc:
            return error(exc.code, str(exc))
        request_id = uuid.uuid4().hex
        self.inflight.add(request_id)
        try:
            fault = self.selected_fault(envelope)
            if isinstance(fault, ResponseFault) and fault.kind == "temporary_unavailable":
                return error("TEMPORARY_UNAVAILABLE", "Tool temporarily unavailable")
            if (
                isinstance(fault, DelayFault)
                and fault.kind == "pre_commit_delay"
            ):
                # The old request remains in-flight, but owns no lock or transaction.
                # Cancellation here must leave the operation unbound and effect-free.
                # Private diagnostics expose scheduling only, never tool observations.
                print(canonical_json({
                    "event": "pre_commit_delay_entered", "attempt": envelope.attempt,
                }), file=sys.stderr, flush=True)
                try:
                    await asyncio.sleep(fault.delay_s)
                finally:
                    print(canonical_json({
                        "event": "pre_commit_delay_exited", "attempt": envelope.attempt,
                    }), file=sys.stderr, flush=True)
            async with self.lock:
                try:
                    fault = self.config.fault
                    if (
                        isinstance(fault, StateChangeFault)
                        and self.initial_read_seen
                        and not self.state_change_applied
                        and envelope.attempt == fault.attempt
                    ):
                        # A separate short transaction persists the external world change
                        # even when the following write fails current-state validation.
                        self.store.change_state_if_unbound(
                            self.config.operation_id,
                            self.config.target_ref,
                            fault.state_patch.model_dump(exclude_none=True),
                        )
                        self.state_change_applied = True
                    receipt = self.store.create_ticket(
                        run_id=self.config.run_id,
                        operation_id=self.config.operation_id,
                        params=params,
                        can_write=self.config.can_write,
                    )
                except ToolRejection as exc:
                    return error(
                        exc.code, str(exc),
                        repairable=exc.repairable and self.inflight == {request_id},
                    )
                except sqlite3.Error:
                    return error("SYSTEM_FAILURE", "Environment database operation failed")
            # This is deliberately after COMMIT and outside the mutex/transaction.
            # Cancellation here never rolls back or erases the immutable receipt.
            fault = self.selected_fault(envelope)
            if (
                isinstance(fault, DelayFault)
                and fault.kind == "commit_response_delay"
            ):
                await asyncio.sleep(fault.delay_s)
            return self.deliver({"ok": True, "kind": "receipt", "receipt": receipt}, fault)
        finally:
            self.inflight.remove(request_id)


def build_server(config: ServerConfig) -> tuple[FastMCP, ToolService]:
    service = ToolService(config)
    server = StrictFastMCP("harness-local-tools", log_level="WARNING")

    @server.tool(structured_output=False)
    async def read_state(target_ref: str, envelope: Envelope) -> CallToolResult:
        """Read the current target state inside this isolated run."""
        return await service.read_state(target_ref, envelope)

    @server.tool(structured_output=False)
    async def create_ticket(
        target_ref: str,
        expected_revision: int,
        queue: str,
        priority: Literal["normal", "urgent"],
        envelope: Envelope,
    ) -> CallToolResult:
        """Create at most one ticket using the Host-bound operation and idempotency key."""
        params = {"target_ref": target_ref, "expected_revision": expected_revision,
                  "queue": queue, "priority": priority}
        return await service.create_ticket(params, envelope)

    original_handler = server._mcp_server.request_handlers[CallToolRequest]

    async def call_with_protocol_fault(request: CallToolRequest):
        # FastMCP converts ordinary exceptions into tool text. The low-level
        # handler must emit ErrorData to exercise a real JSON-RPC error instead.
        model = {"read_state": ReadRequest, "create_ticket": WriteRequest}.get(request.params.name)
        fault = config.fault
        if model and isinstance(fault, ResponseFault) and fault.kind == "protocol_error":
            try:
                parsed = model.model_validate(request.params.arguments or {})
                service.authorize(parsed.target_ref, parsed.envelope,
                                  write=request.params.name == "create_ticket")
                if fault.matches(parsed.envelope):
                    return ErrorData(code=-32603, message="Tool protocol failure")
            except (ValidationError, ToolRejection):
                pass
        return await original_handler(request)

    server._mcp_server.request_handlers[CallToolRequest] = call_with_protocol_fault
    return server, service


def main() -> None:
    parser = argparse.ArgumentParser(description="One-run local MCP tool server")
    parser.add_argument("config", type=Path, help="private trusted server startup JSON")
    args = parser.parse_args()
    config = ServerConfig.model_validate(json.loads(args.config.read_text(encoding="utf-8")))
    server, service = build_server(config)
    try:
        server.run(transport="stdio")
    finally:
        service.store.close()


if __name__ == "__main__":
    main()
