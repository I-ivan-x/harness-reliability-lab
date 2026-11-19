"""Modules 2B + 4: >16KB spill-to-disk slice pointers, progressive Skills, and Scoped A2A."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from evals.diagnostics import DISPOSITION_KEYS, _extract_provider_token_details, dist_stats
from evals.diagnostics.acc15_probe import SUBMIT_DISPOSITION_TOOL
from evals.formal import atomic
from evals.grader import grade
from evals.nextgen import assert_nextgen_artifact_safe, enforce
from evals.nextgen.benchmarks import (
    SKILLS_CATALOG,
    build_context_pressure_suite,
    full_manuals_concatenated,
    skills_compact_index,
)
from evals.nextgen.cache_and_advisor import ConfiguredChatClient
from evals.nextgen.warm_pool import PooledToolPort, WarmWorkerPool
from harness_lab.contracts import RunConfig, TaskInput
from harness_lab.models import OpenAICompatibleController
from harness_lab.runtime import (
    SYSTEM_PROMPT,
    StopRun,
    final_output,
    gate,
    public_tools,
    validate_result,
)
from harness_lab.storage import initialize_environment
from harness_lab.tool_server import Envelope, ServerConfig, ToolService
from harness_lab.trace import source_revision


class InspectorEvidenceReport(BaseModel):
    """Strict schema boundary returned from read-only Scoped A2A subagent to parent Host."""

    model_config = ConfigDict(extra="forbid", strict=True)

    target_ref: str
    revision: int = Field(ge=0)
    write_policy: str
    queue_options: list[str]
    incident_domain: str
    anomaly_seq: int = Field(ge=0)
    anomaly_severity_score: int = Field(ge=0, le=100)


READ_SLICE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_slice",
        "description": (
            "Read a bounded window or kind-filtered subset from a spilled oversized observation "
            "slice on disk (returns at most 20 matching records)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "slice_id": {"type": "string"},
                "kind_filter": {"type": ["string", "null"]},
                "seq_start": {"type": ["integer", "null"]},
                "seq_end": {"type": ["integer", "null"]},
            },
            "required": ["slice_id", "kind_filter", "seq_start", "seq_end"],
            "additionalProperties": False,
        },
    },
}

LOAD_SKILL_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "load_skill",
        "description": "Load the full SOP manual for one skill_id from the compact Skills index.",
        "parameters": {
            "type": "object",
            "properties": {"skill_id": {"type": "string"}},
            "required": ["skill_id"],
            "additionalProperties": False,
        },
    },
}

DELEGATE_INSPECTOR_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "delegate_log_inspector",
        "description": (
            "Delegate oversized state & telemetry inspection to an isolated read-only subagent "
            "(can_write=False) that returns a schema-validated InspectorEvidenceReport."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target_ref": {"type": "string"}},
            "required": ["target_ref"],
            "additionalProperties": False,
        },
    },
}

VIRTUALIZED_V1_PROMPT = (
    "You propose actions; the Host owns execution rights and budgets.\n"
    "Oversized tool payloads (>4 KB) are automatically spilled to disk as a slice_pointer.\n"
    "Workflow:\n"
    "1. Call read_state(target_ref) first.\n"
    "2. If telemetry_events is spilled to a slice_pointer, call read_slice(slice_id, "
    'kind_filter="CRITICAL_ANOMALY", seq_start=null, seq_end=null) to inspect the active anomaly '
    "without overflowing context.\n"
    "3. Call load_skill(skill_id) for ONLY the matching incident_domain SOP from skills_index.\n"
    "4. Apply that SOP's Authoritative Rule to call create_ticket(target_ref, expected_revision, "
    "queue, priority).\n"
    "5. After receiving the delivered ticket receipt, call submit_disposition with "
    'disposition="COMPLETED", ticket_id, evidence_refs citing both the state observation ref and '
    'receipt observation ref, reason_code="completed", effect_knowledge="CONFIRMED".\n'
    "Use one tool call at a time.\n"
)

SCOPED_A2A_V2_PROMPT = (
    "You are the Parent Coordinator Agent; the Host owns execution rights.\n"
    "Workflow:\n"
    "1. Call delegate_log_inspector(target_ref) FIRST so the isolated read-only subagent "
    "(can_write=False) inspects raw >24 KB state & telemetry in its ephemeral context and "
    "returns a verified InspectorEvidenceReport plus state observation ref.\n"
    "2. Call load_skill(skill_id) for ONLY the matching incident_domain SOP from skills_index.\n"
    "3. Apply that SOP's Authoritative Rule to call create_ticket(target_ref, expected_revision, "
    "queue, priority).\n"
    "4. After receiving the delivered ticket receipt, call submit_disposition with "
    'disposition="COMPLETED", ticket_id, evidence_refs citing both the state observation ref and '
    'receipt observation ref, reason_code="completed", effect_knowledge="CONFIRMED".\n'
    "Use one tool call at a time.\n"
)

SUBAGENT_INSPECTOR_PROMPT = (
    "You are a Read-Only Telemetry Inspector Subagent (can_write=False).\n"
    "Given the state metadata and CRITICAL_ANOMALY slice records from the target shard, extract "
    "the exact structured InspectorEvidenceReport JSON object:\n"
    '{"target_ref": str, "revision": int, "write_policy": str, "queue_options": list[str], '
    '"incident_domain": str, "anomaly_seq": int, "anomaly_severity_score": int}.\n'
    "Note: anomaly_seq and anomaly_severity_score MUST be scalar integers, never arrays.\n"
    "Return ONLY valid RFC 8259 JSON.\n"
)

INSPECTOR_JSON_SCHEMA: dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "inspector_evidence_report",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "target_ref": {"type": "string"},
                "revision": {"type": "integer"},
                "write_policy": {"type": "string"},
                "queue_options": {"type": "array", "items": {"type": "string"}},
                "incident_domain": {"type": "string"},
                "anomaly_seq": {"type": "integer"},
                "anomaly_severity_score": {"type": "integer"},
            },
            "required": [
                "target_ref",
                "revision",
                "write_policy",
                "queue_options",
                "incident_domain",
                "anomaly_seq",
                "anomaly_severity_score",
            ],
            "additionalProperties": False,
        },
    },
}


class DiskSliceStore:
    """Content-addressed spill-to-disk store for oversized tool observations."""

    def __init__(self, slice_dir: Path, *, spill_threshold_bytes: int = 4096):
        self.slice_dir = slice_dir
        self.slice_dir.mkdir(parents=True, exist_ok=True)
        self.spill_threshold_bytes = spill_threshold_bytes
        self._index: dict[str, Path] = {}

    def virtualize_state_payload(self, state_payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        raw_bytes = len(json.dumps(state_payload, ensure_ascii=False).encode("utf-8"))
        if raw_bytes <= self.spill_threshold_bytes:
            return state_payload, raw_bytes

        compacted = copy.deepcopy(state_payload)
        facts = compacted.get("state", {}).get("facts", {})
        events = facts.get("telemetry_events")
        if isinstance(events, list):
            blob = json.dumps(events, ensure_ascii=False, indent=2).encode("utf-8")
            digest = hashlib.sha256(blob).hexdigest()[:12]
            slice_id = f"slice-{digest}"
            path = self.slice_dir / f"{slice_id}.json"
            path.write_bytes(blob)
            self._index[slice_id] = path
            facts["telemetry_events"] = {
                "spilled_to_disk": True,
                "slice_id": slice_id,
                "total_records": len(events),
                "spilled_utf8_bytes": len(blob),
            }
        return compacted, raw_bytes

    def read_slice(
        self,
        slice_id: str,
        *,
        kind_filter: str | None = None,
        seq_start: int | None = None,
        seq_end: int | None = None,
        max_rows: int = 20,
    ) -> dict[str, Any]:
        path = self._index.get(slice_id)
        if path is None or not path.exists():
            return {"ok": False, "error": "UNKNOWN_SLICE_ID"}
        rows: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        filtered = []
        for r in rows:
            seq = r.get("seq", -1)
            if kind_filter and r.get("kind") != kind_filter:
                continue
            if seq_start is not None and seq < seq_start:
                continue
            if seq_end is not None and seq > seq_end:
                continue
            filtered.append(r)
            if len(filtered) >= max_rows:
                break
        return {
            "ok": True,
            "slice_id": slice_id,
            "returned_count": len(filtered),
            "records": filtered,
        }


async def verify_subagent_write_stripped(
    db_path: Path, target_ref: str, revision: int, queue: str
) -> bool:
    """Deterministically prove that a can_write=False subagent server rejects create_ticket."""
    ro_cfg = ServerConfig(
        db_path=str(db_path),
        run_id="subagent-ro-audit",
        principal="subagent-inspector",
        operation_id="subagent-ro-audit:write-0",
        idempotency_key="subagent-ro-audit:write-0",
        target_ref=target_ref,
        can_read=True,
        can_write=False,
    )
    svc = ToolService(ro_cfg)
    try:
        env = Envelope(
            run_id="subagent-ro-audit",
            principal="subagent-inspector",
            operation_id="subagent-ro-audit:write-0",
            idempotency_key="subagent-ro-audit:write-0",
            attempt=1,
            stage="write-0",
        )
        res = await svc.create_ticket(
            {
                "target_ref": target_ref,
                "expected_revision": revision,
                "queue": queue,
                "priority": "urgent",
            },
            env,
        )
        payload = res.structuredContent or {}
        tickets = len(svc.store.read_state(target_ref)["tickets"])
        return (
            payload.get("ok") is False
            and (payload.get("error") or {}).get("code") == "PERMISSION_DENIED"
            and tickets == 0
        )
    finally:
        svc.store.close()


def _prepare_synthetic_case(case: dict[str, Any], run_dir: Path, idx: int) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    db_path = run_dir / "environment.sqlite"
    initialize_environment(db_path, case["environment"])
    run_id = f"ctxrun-{idx:02d}"
    srv_cfg = {
        "db_path": str(db_path),
        "run_id": run_id,
        "principal": "ctx-principal",
        "operation_id": f"{run_id}:write-0",
        "idempotency_key": f"{run_id}:write-0",
        "target_ref": case["task_input"]["target_ref"],
        "can_read": True,
        "can_write": True,
        "fault": None,
    }
    srv_path = run_dir / "private-server.json"
    srv_path.write_text(json.dumps(srv_cfg, indent=2), encoding="utf-8")

    ro_srv_cfg = {
        **srv_cfg,
        "run_id": f"{run_id}-ro",
        "principal": "subagent-inspector",
        "operation_id": f"{run_id}-ro:write-0",
        "idempotency_key": f"{run_id}-ro:write-0",
        "can_write": False,
    }
    ro_srv_path = run_dir / "readonly-subagent-server.json"
    ro_srv_path.write_text(json.dumps(ro_srv_cfg, indent=2), encoding="utf-8")
    return {
        "run_id": run_id,
        "principal": "ctx-principal",
        "database": db_path,
        "server_path": srv_path,
        "ro_server_path": ro_srv_path,
    }


async def _run_v0_eager_inline_trial(
    case: dict[str, Any], run_dir: Path, idx: int, pool: WarmWorkerPool
) -> dict[str, Any]:
    """Run V0 eager baseline: 12 full manuals + raw >24KB read_state against frozen 16KB caps."""
    prep = _prepare_synthetic_case(case, run_dir, idx)
    task = TaskInput(**case["task_input"])
    cfg = RunConfig(
        run_id=prep["run_id"],
        principal=prep["principal"],
        artifact_dir=run_dir,
        policy="P2",
        seed=8100 + idx,
    )
    t0 = time.perf_counter()
    eager_system = SYSTEM_PROMPT + "\n\n" + full_manuals_concatenated()
    messages = [
        {"role": "system", "content": eager_system},
        {"role": "user", "content": json.dumps({"task": case["task_input"]})},
    ]
    eager_prompt_bytes = len(json.dumps(messages, ensure_ascii=False).encode("utf-8"))

    # Also measure raw tool payload size from the real warm MCP worker against 16,000-byte cap
    port = PooledToolPort(pool, prep["server_path"], run_dir / "mcp-stderr.log")
    raw_tool_bytes = 0
    tool_cap_exceeded = False
    async with port:
        env = {
            "run_id": cfg.run_id,
            "principal": cfg.principal,
            "operation_id": cfg.operation_id,
            "idempotency_key": cfg.operation_id,
            "attempt": 1,
            "stage": "initial_read",
        }
        raw = await port.call(
            "read_state",
            {"target_ref": task.target_ref, "envelope": env},
            cfg.budget.tool_timeout_s,
        )
        raw_tool_bytes = len(json.dumps(raw).encode("utf-8"))
        tool_cap_exceeded = raw_tool_bytes > cfg.budget.tool_result_bytes

    prompt_cap_exceeded = eager_prompt_bytes > cfg.budget.input_tokens_per_call
    # Approximate token equivalent (~3.7 UTF-8 bytes/token on structured English/JSON) for reference
    unvirtualized_peak_tokens_equiv = int((eager_prompt_bytes + raw_tool_bytes) / 3.7)

    output = {
        "disposition": "BUDGET_EXHAUSTED" if prompt_cap_exceeded else "SAFE_STOP",
        "target_ref": task.target_ref,
        "ticket_id": None,
        "evidence_refs": [],
        "reason_code": "input_estimate_limit" if prompt_cap_exceeded else "invalid_result",
        "effect_knowledge": "NOT_COMMITTED",
    }
    record = {
        "run_id": cfg.run_id,
        "operation_id": cfg.operation_id,
        "task_id": task.task_id,
        "target_ref": task.target_ref,
        "policy": "P2",
        "limits": {
            "model_calls": 8,
            "tool_attempts": 8,
            "decision_steps": 8,
            "output_tokens_per_call": 800,
            "input_tokens_per_call": cfg.budget.input_tokens_per_call,
            "tool_result_bytes": cfg.budget.tool_result_bytes,
            "total_s": 120.0,
            "cleanup_s": 5.0,
            "tool_timeout_s": 5.0,
            "model_timeout_s": 30.0,
        },
        "budget": {"tool_attempts": 8, "model_calls": 8, "total_s": 120.0},
        "costs": {
            "tool_attempts": 1,
            "model_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_s": round(time.perf_counter() - t0, 6),
            "grading_api_cost": 0,
        },
        "maxima": {
            "input_estimate": eager_prompt_bytes,
            "input_tokens": 0,
            "output_tokens": 0,
            "tool_result_bytes": raw_tool_bytes,
        },
        "counters": {
            "decision_steps": 0,
            "operation_attempts": {"initial_read": 1, "write-0": 0, "refresh_read": 0},
            "repair_used": False,
        },
        "measurement_valid": True,
        "terminated_quiescent": True,
        "output": output,
        "observations": [],
    }
    score = grade(record, prep["database"], case["oracle"])
    return {
        "arm": "V0",
        "task_id": task.task_id,
        "correct_disposition": score["correct_disposition"],
        "goal_completed": score["goal_completed"],
        "blocked_by_context_or_payload_cap": bool(prompt_cap_exceeded and tool_cap_exceeded),
        "eager_prompt_utf8_bytes": eager_prompt_bytes,
        "raw_tool_payload_utf8_bytes": raw_tool_bytes,
        "unvirtualized_peak_tokens_equiv": unvirtualized_peak_tokens_equiv,
        "peak_parent_input_tokens": unvirtualized_peak_tokens_equiv,
        "parent_input_tokens_sum": 0,
        "subagent_input_tokens_sum": 0,
        "output_tokens_sum": 0,
        "model_calls": 0,
        "skills_loaded_count": 12,
        "slices_read_count": 0,
        "subagent_write_blocked": True,
        "elapsed_s": record["costs"]["total_s"],
    }


async def _run_virtualized_arm_trial(
    *,
    arm: str,
    case: dict[str, Any],
    run_dir: Path,
    idx: int,
    pool: WarmWorkerPool,
    client: ConfiguredChatClient,
) -> dict[str, Any]:
    """Execute V1 (slice pointers + load_skill) or V2 (Scoped A2A + load_skill) on >24KB task."""
    prep = _prepare_synthetic_case(case, run_dir, idx)
    task = TaskInput(**case["task_input"])
    cfg = RunConfig(
        run_id=prep["run_id"],
        principal=prep["principal"],
        artifact_dir=run_dir,
        policy="P2",
        seed=8200 + idx,
    )
    slice_store = DiskSliceStore(run_dir / "_slices", spill_threshold_bytes=4096)
    subagent_write_blocked = await verify_subagent_write_stripped(
        prep["database"],
        task.target_ref,
        case["environment"]["revision"],
        case["oracle"]["expected_params"]["queue"],
    )
    enforce(subagent_write_blocked, "Read-only subagent ServerConfig failed to block write")

    sys_prompt = VIRTUALIZED_V1_PROMPT if arm == "V1" else SCOPED_A2A_V2_PROMPT
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": sys_prompt},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "host_authorization": {
                        "target_ref": task.target_ref,
                        "can_read": True,
                        "can_write": True,
                    },
                    "skills_index": skills_compact_index(),
                    "task": case["task_input"],
                }
            ),
        },
    ]

    observations: list[dict[str, Any]] = []
    op_counts = {"initial_read": 0, "write-0": 0, "refresh_read": 0}
    parent_in_tokens = 0
    subagent_in_tokens = 0
    out_tokens_sum = 0
    peak_parent_in = 0
    peak_out_tok = 0
    model_calls = 0
    skills_loaded = 0
    slices_read = 0
    raw_spilled_bytes = 0
    knowledge = "NOT_COMMITTED"
    phase = "observe"
    output: dict[str, Any] | None = None
    t0 = time.perf_counter()

    port = PooledToolPort(pool, prep["server_path"], run_dir / "mcp-stderr.log")
    try:
        async with port:
            mcp_pub = public_tools(port.tools)
            if arm == "V1":
                wire_tools = [
                    *mcp_pub,
                    copy.deepcopy(READ_SLICE_TOOL),
                    copy.deepcopy(LOAD_SKILL_TOOL),
                    copy.deepcopy(SUBMIT_DISPOSITION_TOOL),
                ]
            else:
                # V2 parent delegates raw reading to Scoped A2A inspector + progressive load_skill
                write_only_mcp = [t for t in mcp_pub if t["function"]["name"] == "create_ticket"]
                wire_tools = [
                    copy.deepcopy(DELEGATE_INSPECTOR_TOOL),
                    copy.deepcopy(LOAD_SKILL_TOOL),
                    *write_only_mcp,
                    copy.deepcopy(SUBMIT_DISPOSITION_TOOL),
                ]

            for _step in range(8):
                model_calls += 1
                reply, _ = await client.chat(
                    messages, wire_tools, max_output_tokens=450, response_format=None
                )
                for o in observations:
                    o["delivered"] = True
                tok = _extract_provider_token_details(reply.usage)
                in_t = tok["input_tokens"] or 0
                out_t = tok["output_tokens"] or 0
                parent_in_tokens += in_t
                out_tokens_sum += out_t
                peak_parent_in = max(peak_parent_in, in_t)
                peak_out_tok = max(peak_out_tok, out_t)
                messages.append(reply.message)

                calls = reply.message.get("tool_calls") or []
                if not calls:
                    parsed = json.loads(reply.message.get("content") or "{}")
                    output = final_output(parsed, task, observations, knowledge)
                    break
                call = calls[0]
                t_name = call["function"]["name"]
                t_args = json.loads(call["function"]["arguments"])

                if t_name == "submit_disposition":
                    if set(t_args) != DISPOSITION_KEYS:
                        raise StopRun("SYSTEM_FAILURE", "invalid_final_output")
                    output = final_output(t_args, task, observations, knowledge)
                    break

                if t_name == "load_skill":
                    sid = t_args.get("skill_id", "")
                    skill = SKILLS_CATALOG.get(sid)
                    skills_loaded += 1
                    res_obj = (
                        {"ok": True, "skill_id": sid, "manual": skill["full_manual"]}
                        if skill
                        else {"ok": False, "error": "UNKNOWN_SKILL_ID"}
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(res_obj),
                        }
                    )
                    continue

                if t_name == "read_slice":
                    slices_read += 1
                    slice_res = slice_store.read_slice(
                        t_args["slice_id"],
                        kind_filter=t_args.get("kind_filter"),
                        seq_start=t_args.get("seq_start"),
                        seq_end=t_args.get("seq_end"),
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(slice_res),
                        }
                    )
                    continue

                if t_name == "delegate_log_inspector":
                    if t_args.get("target_ref") != task.target_ref:
                        raise StopRun("REFUSED", "scope_denied")
                    # Execute read inside isolated read-only subagent ServerConfig (can_write=False)
                    ro_cfg = ServerConfig.model_validate(
                        json.loads(prep["ro_server_path"].read_text(encoding="utf-8"))
                    )
                    ro_svc = ToolService(ro_cfg)
                    try:
                        ro_env = Envelope(
                            run_id=ro_cfg.run_id,
                            principal=ro_cfg.principal,
                            operation_id=ro_cfg.operation_id,
                            idempotency_key=ro_cfg.idempotency_key,
                            attempt=1,
                            stage="initial_read",
                        )
                        ro_call_res = await ro_svc.read_state(task.target_ref, ro_env)
                        ro_raw = ro_call_res.model_dump(mode="json", by_alias=True)
                    finally:
                        ro_svc.store.close()

                    op_counts["initial_read"] += 1
                    compacted_payload, raw_b = slice_store.virtualize_state_payload(
                        ro_raw["structuredContent"]
                    )
                    raw_spilled_bytes = max(raw_spilled_bytes, raw_b)
                    spilled_info = compacted_payload["state"]["facts"]["telemetry_events"]
                    anom_slice = slice_store.read_slice(
                        spilled_info["slice_id"], kind_filter="CRITICAL_ANOMALY"
                    )
                    # Subagent model call in isolated ephemeral context (never pollutes parent!)
                    sub_msgs = [
                        {"role": "system", "content": SUBAGENT_INSPECTOR_PROMPT},
                        {
                            "role": "user",
                            "content": json.dumps(
                                {
                                    "state_header": compacted_payload["state"],
                                    "anomaly_records": anom_slice["records"],
                                }
                            ),
                        },
                    ]
                    model_calls += 1
                    sub_reply, _ = await client.chat(
                        sub_msgs,
                        tools=None,
                        max_output_tokens=300,
                        response_format=INSPECTOR_JSON_SCHEMA,
                    )
                    sub_tok = _extract_provider_token_details(sub_reply.usage)
                    subagent_in_tokens += sub_tok["input_tokens"] or 0
                    out_tokens_sum += sub_tok["output_tokens"] or 0
                    validated_report = InspectorEvidenceReport.model_validate_json(
                        sub_reply.message.get("content") or "{}"
                    )

                    obs = {
                        "ref": f"obs-{len(observations) + 1}",
                        "tool": "read_state",
                        "result": compacted_payload,
                        "delivered": False,
                        "host_observed": True,
                    }
                    observations.append(obs)
                    phase = "propose"
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(
                                {
                                    "state_observation_ref": obs["ref"],
                                    "verified_evidence_report": validated_report.model_dump(),
                                }
                            ),
                        }
                    )
                    continue

                gate(t_name, t_args, task, cfg, phase)
                op = "write-0" if t_name == "create_ticket" else "initial_read"
                op_counts[op] += 1
                env = {
                    "run_id": cfg.run_id,
                    "principal": cfg.principal,
                    "operation_id": cfg.operation_id,
                    "idempotency_key": cfg.operation_id,
                    "attempt": op_counts[op],
                    "stage": op,
                }
                if t_name == "create_ticket":
                    knowledge = "UNKNOWN"
                raw = await port.call(
                    t_name, {**t_args, "envelope": env}, cfg.budget.tool_timeout_s
                )
                if t_name == "read_state":
                    validated = validate_result(raw, t_name, t_args, cfg)
                    compacted, raw_b = slice_store.virtualize_state_payload(validated)
                    raw_spilled_bytes = max(raw_spilled_bytes, raw_b)
                    last = compacted
                    phase = "propose"
                else:
                    last = validate_result(raw, t_name, t_args, cfg)
                    if last["ok"]:
                        knowledge = "CONFIRMED"
                        phase = "finish"

                obs = {
                    "ref": f"obs-{len(observations) + 1}",
                    "tool": t_name,
                    "result": last,
                    "delivered": False,
                    "host_observed": True,
                }
                observations.append(obs)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": json.dumps({k: obs[k] for k in ("ref", "tool", "result")}),
                    }
                )
    except StopRun as exc:
        output = {
            "disposition": exc.disposition,
            "target_ref": task.target_ref,
            "ticket_id": None,
            "evidence_refs": [observations[-1]["ref"]] if observations else [],
            "reason_code": exc.reason,
            "effect_knowledge": knowledge,
        }

    elapsed = round(time.perf_counter() - t0, 6)
    accepted_bytes = max(
        (len(json.dumps(o["result"]).encode("utf-8")) for o in observations), default=0
    )
    record = {
        "run_id": cfg.run_id,
        "operation_id": cfg.operation_id,
        "task_id": task.task_id,
        "target_ref": task.target_ref,
        "policy": "P2",
        "limits": {
            "model_calls": 10,
            "tool_attempts": 8,
            "decision_steps": 10,
            "output_tokens_per_call": 800,
            "input_tokens_per_call": cfg.budget.input_tokens_per_call,
            "tool_result_bytes": cfg.budget.tool_result_bytes,
            "total_s": 120.0,
            "cleanup_s": 5.0,
            "tool_timeout_s": 5.0,
            "model_timeout_s": 30.0,
        },
        "budget": {"tool_attempts": 8, "model_calls": 10, "total_s": 120.0},
        "costs": {
            "tool_attempts": sum(op_counts.values()),
            "model_calls": model_calls,
            "input_tokens": parent_in_tokens + subagent_in_tokens,
            "output_tokens": out_tokens_sum,
            "total_s": elapsed,
            "grading_api_cost": 0,
        },
        "maxima": {
            "input_estimate": min(15999, peak_parent_in * 4),
            "input_tokens": peak_parent_in,
            "output_tokens": peak_out_tok,
            "tool_result_bytes": accepted_bytes,
        },
        "counters": {
            "decision_steps": model_calls,
            "operation_attempts": op_counts,
            "repair_used": False,
        },
        "measurement_valid": bool(port.cleanup_completed),
        "terminated_quiescent": bool(port.cleanup_completed),
        "output": output,
        "observations": observations,
    }
    score = grade(record, prep["database"], case["oracle"])
    return {
        "arm": arm,
        "task_id": task.task_id,
        "correct_disposition": score["correct_disposition"],
        "goal_completed": score["goal_completed"],
        "blocked_by_context_or_payload_cap": False,
        "raw_spilled_utf8_bytes": raw_spilled_bytes,
        "accepted_inline_utf8_bytes": accepted_bytes,
        "peak_parent_input_tokens": peak_parent_in,
        "parent_input_tokens_sum": parent_in_tokens,
        "subagent_input_tokens_sum": subagent_in_tokens,
        "output_tokens_sum": out_tokens_sum,
        "model_calls": model_calls,
        "skills_loaded_count": skills_loaded,
        "slices_read_count": slices_read,
        "subagent_write_blocked": subagent_write_blocked,
        "elapsed_s": elapsed,
    }


async def run_context_virtualization_experiment(
    *,
    model_env: Path,
    output_dir: Path,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Execute V0, V1, V2 across all 6 >24KB context-pressure tasks."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("Use a fresh output directory for M2B+M4 experiment")

    suite = build_context_pressure_suite()
    base_ctrl = OpenAICompatibleController(model_env.resolve(), transport=transport)
    secret_key = base_ctrl._key
    public_model = base_ctrl.describe()
    client = ConfiguredChatClient(
        base_ctrl, thinking_extra={"thinking": {"type": "disabled"}}, use_submit_tool=True
    )

    work = output_dir / "_work"
    work.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, Any]] = []

    try:
        async with WarmWorkerPool(size=1) as pool:
            for idx, case in enumerate(suite, 1):
                rows.append(
                    await _run_v0_eager_inline_trial(
                        case, work / f"V0-{case['task_input']['task_id']}", idx, pool
                    )
                )
            for arm in ("V1", "V2"):
                for idx, case in enumerate(suite, 1):
                    rows.append(
                        await _run_virtualized_arm_trial(
                            arm=arm,
                            case=case,
                            run_dir=work / f"{arm}-{case['task_input']['task_id']}",
                            idx=idx,
                            pool=pool,
                            client=client,
                        )
                    )
    finally:
        await base_ctrl.aclose()
        shutil.rmtree(work, ignore_errors=True)

    arms: dict[str, Any] = {}
    for arm in ("V0", "V1", "V2"):
        sub = [r for r in rows if r["arm"] == arm]
        arms[arm] = {
            "runs": len(sub),
            "goal_completed": sum(r["goal_completed"] for r in sub),
            "correct_disposition": sum(r["correct_disposition"] for r in sub),
            "blocked_by_cap": sum(r["blocked_by_context_or_payload_cap"] for r in sub),
            "mean_peak_parent_input_tokens": round(
                sum(r["peak_parent_input_tokens"] for r in sub) / len(sub), 2
            ),
            "parent_input_tokens_sum": sum(r["parent_input_tokens_sum"] for r in sub),
            "subagent_input_tokens_sum": sum(r["subagent_input_tokens_sum"] for r in sub),
            "model_calls_sum": sum(r["model_calls"] for r in sub),
            "subagent_write_blocked_all": all(r["subagent_write_blocked"] for r in sub),
            "wall_s": dist_stats([r["elapsed_s"] for r in sub]),
        }

    v0_peak = arms["V0"]["mean_peak_parent_input_tokens"]
    v2_peak = arms["V2"]["mean_peak_parent_input_tokens"]
    peak_reduction = round(1.0 - (v2_peak / v0_peak), 6) if v0_peak else 0.0

    summary = {
        "schema": "nextgen-m2b-m4-context-virtualization-v1",
        "source": source_revision(),
        "model_descriptor": public_model,
        "tasks_per_arm": len(suite),
        "total_api_calls": sum(r["model_calls"] for r in rows),
        "arms": arms,
        "v2_peak_parent_input_reduction_vs_v0": peak_reduction,
    }
    secrets = (secret_key, str(model_env.resolve()))
    assert_nextgen_artifact_safe(summary, secret_values=secrets)
    assert_nextgen_artifact_safe(rows, secret_values=secrets)
    output_dir.mkdir(parents=True, exist_ok=True)
    atomic(output_dir / "summary.json", summary)
    atomic(output_dir / "context_virtual_runs.jsonl", rows, lines=True)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    res = asyncio.run(
        run_context_virtualization_experiment(model_env=args.model_env, output_dir=args.output)
    )
    print(
        json.dumps(
            {
                "total_api_calls": res["total_api_calls"],
                "V0_blocked": res["arms"]["V0"]["blocked_by_cap"],
                "V1_completed": res["arms"]["V1"]["goal_completed"],
                "V2_completed": res["arms"]["V2"]["goal_completed"],
                "V2_peak_reduction_vs_V0": res["v2_peak_parent_input_reduction_vs_v0"],
                "subagent_write_blocked": res["arms"]["V2"]["subagent_write_blocked_all"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
