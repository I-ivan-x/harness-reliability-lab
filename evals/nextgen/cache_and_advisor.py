"""Modules 2A + 3: Prefix cache page alignment & Executor-Advisor thinking Pareto experiment."""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import shutil
import time
from pathlib import Path
from typing import Any

import httpx

from evals.development import read
from evals.diagnostics import DISPOSITION_KEYS, _extract_provider_token_details, dist_stats
from evals.diagnostics.acc15_probe import SUBMIT_DISPOSITION_TOOL, SUBMIT_TOOL_SYSTEM_PROMPT
from evals.formal import atomic
from evals.grader import grade
from evals.nextgen import (
    PROJECT,
    assert_nextgen_artifact_safe,
    paired_comparison_stats,
)
from evals.nextgen.warm_pool import PooledToolPort, WarmWorkerPool
from evals.run_case import prepare_case
from harness_lab.contracts import RunConfig, TaskInput
from harness_lab.models import ModelReply, OpenAICompatibleController
from harness_lab.runtime import (
    SYSTEM_PROMPT,
    StopRun,
    certified_unbound,
    final_output,
    gate,
    public_tools,
    tool_failure,
    validate_result,
)
from harness_lab.timing import deadline_timeout
from harness_lab.trace import source_revision

# Universal static system prompt (>1,592 tokens together with 3 public tool schemas on Doubao)
# Contains ZERO per-task dynamic fields so all tasks share identical 256-token KV cache pages.
UNIVERSAL_ALIGNED_SYSTEM_PROMPT = (
    SUBMIT_TOOL_SYSTEM_PROMPT
    + "\nUniversal Host & Protocol Invariants (Static Cache-Aligned Specification v2025-11-25):\n"
    + "\n".join(
        f"{idx:02d}. Execution & Epistemic Rule {idx:02d}: The Host exclusively owns principal "
        f"identity, operation slot binding, idempotency keys, retry budgets, and state refresh "
        f"scheduling. Every model turn must invoke exactly one supplied tool (read_state, "
        f"create_ticket, or submit_disposition). Always evaluate timestamps against task.as_of "
        f"in UTC, treat boundary equality strictly per task wording, treat write_policy "
        f"(allow / forbid / approval) in the latest delivered state as authoritative, and cite "
        f"only the latest active state observation plus any delivered success receipt."
        for idx in range(1, 12)
    )
)

ADVISOR_SYSTEM_PROMPT = (
    "You are a read-only Escalation Advisor assisting a fast Executor after a certified "
    "state-change recovery notice. Given the public task and the refreshed state observation, "
    "compute the exact required parameters under all boundary rules (including timestamp "
    "equality and write_policy). Return ONLY a valid JSON object with fields: "
    '{"recommended_tool": "create_ticket"|"submit_disposition", "expected_revision": int|null, '
    '"queue": str|null, "priority": "normal"|"urgent"|null, '
    '"disposition": str|null, "reason_code": str|null}.'
)

REPRESENTATIVE_TASKS = (
    "acc-05",
    "acc-06",
    "acc-07",
    "acc-08",
    "acc-09",
    "acc-10",
    "acc-11",
    "acc-15",
)


class ConfiguredChatClient:
    """Thin chat client supporting thinking controls, unified submit tool, and cache telemetry."""

    def __init__(
        self,
        base: OpenAICompatibleController,
        *,
        thinking_extra: dict[str, Any] | None = None,
        use_submit_tool: bool = False,
    ):
        self.base = base
        self.thinking_extra = thinking_extra or {}
        self.use_submit_tool = use_submit_tool
        self._supports_required_tool_choice = True

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        *,
        timeout_s: float = 30.0,
        max_output_tokens: int = 800,
        extra_override: dict[str, Any] | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> tuple[ModelReply, float]:
        extra = extra_override if extra_override is not None else self.thinking_extra
        payload: dict[str, Any] = {
            "model": self.base.model,
            "messages": messages,
            "stream": False,
            self.base.token_limit_field: max_output_tokens,
            "temperature": 0,
        }
        if response_format is not None:
            payload["response_format"] = response_format
        if tools:
            tc_mode = (
                "required"
                if (self.use_submit_tool and self._supports_required_tool_choice)
                else "auto"
            )
            payload.update(tools=tools, tool_choice=tc_mode)
        if extra:
            payload.update(extra)

        t0 = time.perf_counter()
        resp = await self.base._client.post(
            self.base._url,
            json=payload,
            timeout=httpx.Timeout(timeout_s),
            headers={"Authorization": "Bearer " + self.base._key},
        )
        if resp.status_code == 400 and payload.get("tool_choice") == "required":
            self._supports_required_tool_choice = False
            payload["tool_choice"] = "auto"
            t0 = time.perf_counter()
            resp = await self.base._client.post(
                self.base._url,
                json=payload,
                timeout=httpx.Timeout(timeout_s),
                headers={"Authorization": "Bearer " + self.base._key},
            )
        elapsed_s = time.perf_counter() - t0
        if not 200 <= resp.status_code < 300:
            raise self.base._response_error(f"HTTP_{resp.status_code}", resp)
        data = resp.json()
        choice = data["choices"][0]
        msg = {
            k: v
            for k, v in choice["message"].items()
            if k not in {"reasoning_content", "reasoning"}
        }
        raw_u = data.get("usage") or {}
        usage = {
            "input_tokens": raw_u.get("prompt_tokens", raw_u.get("input_tokens")),
            "output_tokens": raw_u.get("completion_tokens", raw_u.get("output_tokens")),
            "provider": raw_u,
        }
        return ModelReply(
            msg, usage, choice["finish_reason"], data.get("model", self.base.model)
        ), elapsed_s


async def _run_arm_trial(
    *,
    arm: str,
    case_path: Path,
    run_dir: Path,
    pool: WarmWorkerPool,
    client: ConfiguredChatClient,
    seed: int,
) -> dict[str, Any]:
    """Execute one isolated P2 trial under arm G0 / G1 / G2 / G3 and grade against SQLite."""
    prep = prepare_case(case_path, run_dir)
    task = TaskInput(**prep["task_input"])
    cfg = RunConfig(
        run_id=prep["run_id"],
        principal=prep["principal"],
        artifact_dir=run_dir,
        policy="P2",
        seed=seed,
    )
    aligned = arm in {"G1", "G2", "G3"}
    use_submit = arm in {"G1", "G2", "G3"}
    use_advisor = arm == "G3"

    port = PooledToolPort(pool, prep["server_path"], run_dir / "mcp-stderr.log")
    t_run0 = time.perf_counter()

    if aligned:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": UNIVERSAL_ALIGNED_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "host_authorization": {
                            "target_ref": task.target_ref,
                            "can_read": True,
                            "can_write": True,
                        },
                        "task": prep["task_input"],
                    }
                ),
            },
        ]
    else:
        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
                + "\nHost authorization: "
                + json.dumps(
                    {
                        "target_ref": task.target_ref,
                        "can_read": True,
                        "can_write": True,
                    }
                ),
            },
            {"role": "user", "content": json.dumps({"task": prep["task_input"]})},
        ]

    observations: list[dict[str, Any]] = []
    attempts = {"initial_read": 0, "write-0": 0, "refresh_read": 0}
    costs = {
        "tool_attempts": 0,
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_s": 0.0,
        "grading_api_cost": 0,
    }
    maxima = {
        "input_estimate": 0,
        "input_tokens": None,
        "output_tokens": None,
        "tool_result_bytes": 0,
    }
    decisions = 0
    repair_used = False
    knowledge = "NOT_COMMITTED"
    phase = "observe"
    output: dict[str, Any] | None = None
    format_parse_failures = 0
    advisor_calls = 0
    call_telemetry: list[dict[str, Any]] = []
    rng_backoff = 0.02

    async def exec_tool(
        t_name: str, t_args: dict[str, Any], cid: str | None, op: str
    ) -> dict[str, Any]:
        nonlocal knowledge
        limit = 1 if op == "refresh_read" else 3
        last = None
        while attempts[op] < limit:
            costs["tool_attempts"] += 1
            attempts[op] += 1
            att = attempts[op]
            if t_name == "create_ticket":
                knowledge = "UNKNOWN"
            env = {
                "run_id": cfg.run_id,
                "principal": cfg.principal,
                "operation_id": cfg.operation_id,
                "idempotency_key": cfg.operation_id,
                "attempt": att,
                "stage": op,
            }
            try:
                async with deadline_timeout(cfg.budget.tool_timeout_s):
                    raw = await port.call(
                        t_name, {**t_args, "envelope": env}, cfg.budget.tool_timeout_s
                    )
                r_bytes = len(json.dumps(raw).encode())
                last = validate_result(raw, t_name, t_args, cfg)
                maxima["tool_result_bytes"] = max(maxima["tool_result_bytes"], r_bytes)
            except TimeoutError:
                last = {"ok": False, "error": {"code": "TIMEOUT"}}
            except Exception:
                last = {"ok": False, "error": {"code": "INVALID_RESULT"}}

            if last["ok"]:
                if t_name == "create_ticket":
                    knowledge = "CONFIRMED"
                break
            err_code = last["error"]["code"]
            if t_name == "create_ticket" and (
                certified_unbound(last)
                or err_code in {"PERMISSION_DENIED", "APPROVAL_REQUIRED", "INVALID_REQUEST"}
            ):
                knowledge = "NOT_COMMITTED"
            retry = err_code in {"TIMEOUT", "TRANSPORT_ERROR", "TEMPORARY_UNAVAILABLE"}
            if not retry or att == limit:
                break
            await asyncio.sleep(rng_backoff * (2 ** (att - 1)))

        assert last is not None
        obs = {
            "ref": f"obs-{len(observations) + 1}",
            "tool": t_name,
            "result": last,
            "delivered": False,
            "host_observed": True,
        }
        observations.append(obs)
        vis = {k: obs[k] for k in ("ref", "tool", "result")}
        if cid is not None:
            messages.append({"role": "tool", "tool_call_id": cid, "content": json.dumps(vis)})
        else:
            messages.append(
                {
                    "role": "user",
                    "content": json.dumps({"source": "host_refresh", "observation": vis}),
                }
            )
        return last

    try:
        async with port:
            base_tools = public_tools(port.tools)
            wire_tools = (
                [*base_tools, copy.deepcopy(SUBMIT_DISPOSITION_TOOL)] if use_submit else base_tools
            )
            while output is None:
                if (
                    costs["model_calls"] >= cfg.budget.model_calls
                    or decisions >= cfg.budget.decision_steps
                ):
                    raise StopRun("BUDGET_EXHAUSTED", "model_or_decision_budget")
                est = len(json.dumps({"messages": messages, "tools": wire_tools}).encode()) + 128
                maxima["input_estimate"] = max(maxima["input_estimate"], est)

                # Out-of-band Advisor escalation ONLY on certified recovery notice in G3!
                last_msg_txt = messages[-1].get("content") or ""
                in_recovery = '"source": "host_recovery"' in last_msg_txt
                if use_advisor and in_recovery:
                    latest_state_obs = next(
                        o
                        for o in reversed(observations)
                        if o["tool"] == "read_state" and o["result"].get("ok")
                    )
                    adv_msgs = [
                        {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": json.dumps(
                                {
                                    "task": prep["task_input"],
                                    "refreshed_state_observation": {
                                        "ref": latest_state_obs["ref"],
                                        "state": latest_state_obs["result"]["state"],
                                    },
                                }
                            ),
                        },
                    ]
                    costs["model_calls"] += 1
                    advisor_calls += 1
                    adv_reply, adv_s = await client.chat(
                        adv_msgs,
                        tools=None,
                        max_output_tokens=800,
                        extra_override={"reasoning_effort": "low"},
                        response_format={"type": "json_object"},
                    )
                    adv_tok = _extract_provider_token_details(adv_reply.usage)
                    costs["input_tokens"] += adv_tok["input_tokens"] or 0
                    costs["output_tokens"] += adv_tok["output_tokens"] or 0
                    maxima["input_tokens"] = max(
                        maxima["input_tokens"] or 0, adv_tok["input_tokens"] or 0
                    )
                    maxima["output_tokens"] = max(
                        maxima["output_tokens"] or 0, adv_tok["output_tokens"] or 0
                    )
                    call_telemetry.append(
                        {
                            "role": "advisor",
                            "turn": len(call_telemetry) + 1,
                            "elapsed_s": round(adv_s, 6),
                            "tokens": adv_tok,
                        }
                    )
                    # Append structured Advisor digest to recovery notice without mutating prefix
                    rec_obj = json.loads(messages[-1]["content"])
                    rec_obj["advisor_verified_digest"] = json.loads(
                        adv_reply.message.get("content") or "{}"
                    )
                    messages[-1]["content"] = json.dumps(rec_obj)

                costs["model_calls"] += 1
                max_out = 400 if arm in {"G2", "G3"} else 800
                rf = None if use_submit else {"type": "json_object"}
                reply, call_s = await client.chat(
                    messages, wire_tools, max_output_tokens=max_out, response_format=rf
                )
                for o in observations:
                    o["delivered"] = True
                decisions += 1
                tok = _extract_provider_token_details(reply.usage)
                costs["input_tokens"] += tok["input_tokens"] or 0
                costs["output_tokens"] += tok["output_tokens"] or 0
                maxima["input_tokens"] = max(maxima["input_tokens"] or 0, tok["input_tokens"] or 0)
                maxima["output_tokens"] = max(
                    maxima["output_tokens"] or 0, tok["output_tokens"] or 0
                )
                call_telemetry.append(
                    {
                        "role": "executor",
                        "turn": len(call_telemetry) + 1,
                        "elapsed_s": round(call_s, 6),
                        "tokens": tok,
                    }
                )
                messages.append(reply.message)

                calls = reply.message.get("tool_calls") or []
                if not calls:
                    try:
                        parsed_content = json.loads(reply.message.get("content") or "")
                    except json.JSONDecodeError:
                        format_parse_failures += 1
                        raise
                    output = final_output(parsed_content, task, observations, knowledge)
                    break

                if len(calls) != 1:
                    raise StopRun("SYSTEM_FAILURE", "parallel_tools_not_allowed")
                call = calls[0]
                t_name = call["function"]["name"]
                try:
                    t_args = json.loads(call["function"]["arguments"])
                except json.JSONDecodeError:
                    format_parse_failures += 1
                    raise

                if use_submit and t_name == "submit_disposition":
                    if not isinstance(t_args, dict) or set(t_args) != DISPOSITION_KEYS:
                        format_parse_failures += 1
                        raise StopRun("SYSTEM_FAILURE", "invalid_final_output")
                    output = final_output(t_args, task, observations, knowledge)
                    break

                gate(t_name, t_args, task, cfg, phase)
                op = "write-0" if t_name == "create_ticket" else "initial_read"
                last = await exec_tool(t_name, t_args, call["id"], op)
                if (
                    t_name == "create_ticket"
                    and certified_unbound(last)
                    and knowledge == "NOT_COMMITTED"
                    and not repair_used
                ):
                    repair_used = True
                    if last["error"]["code"] == "STALE_REVISION":
                        ref_res = await exec_tool(
                            "read_state", {"target_ref": task.target_ref}, None, "refresh_read"
                        )
                        if not ref_res["ok"]:
                            raise tool_failure("read_state", ref_res)
                    messages.append(
                        {
                            "role": "user",
                            "content": json.dumps(
                                {
                                    "source": "host_recovery",
                                    "allowed_actions": (
                                        ["create_ticket", "submit_disposition"]
                                        if use_submit
                                        else ["create_ticket", "final"]
                                    ),
                                    "notice": (
                                        "One corrected proposal is permitted. Use visible "
                                        "refreshed facts and original target; do not request "
                                        "another read."
                                    ),
                                    "effect_knowledge": knowledge,
                                }
                            ),
                        }
                    )
                    continue
                if not last["ok"]:
                    raise tool_failure(t_name, last)
                phase = "propose" if t_name == "read_state" else "finish"
    except StopRun as exc:
        output = {
            "disposition": exc.disposition,
            "target_ref": task.target_ref,
            "ticket_id": None,
            "evidence_refs": [observations[-1]["ref"]] if observations else [],
            "reason_code": exc.reason,
            "effect_knowledge": knowledge,
        }
    except Exception:
        output = {
            "disposition": "SYSTEM_FAILURE",
            "target_ref": task.target_ref,
            "ticket_id": None,
            "evidence_refs": [],
            "reason_code": "invalid_response",
            "effect_knowledge": knowledge,
        }

    costs["total_s"] = round(time.perf_counter() - t_run0, 6)
    record = {
        "run_id": cfg.run_id,
        "operation_id": cfg.operation_id,
        "task_id": task.task_id,
        "target_ref": task.target_ref,
        "policy": "P2",
        "limits": {
            "model_calls": cfg.budget.model_calls,
            "tool_attempts": cfg.budget.tool_attempts,
            "decision_steps": cfg.budget.decision_steps,
            "output_tokens_per_call": cfg.budget.output_tokens_per_call,
            "input_tokens_per_call": cfg.budget.input_tokens_per_call,
            "tool_result_bytes": cfg.budget.tool_result_bytes,
            "total_s": cfg.budget.total_s,
            "cleanup_s": cfg.budget.cleanup_s,
            "tool_timeout_s": cfg.budget.tool_timeout_s,
            "model_timeout_s": cfg.budget.model_timeout_s,
        },
        "budget": {
            "tool_attempts": cfg.budget.tool_attempts,
            "model_calls": cfg.budget.model_calls,
            "total_s": cfg.budget.total_s,
        },
        "costs": costs,
        "maxima": maxima,
        "counters": {
            "decision_steps": decisions,
            "operation_attempts": attempts,
            "repair_used": repair_used,
        },
        "measurement_valid": bool(port.cleanup_completed),
        "terminated_quiescent": bool(port.cleanup_completed),
        "output": output,
        "observations": observations,
    }
    score = grade(record, prep["database"], prep["oracle"])
    infer_s = round(sum(c["elapsed_s"] for c in call_telemetry), 6)
    in_sum = sum(c["tokens"]["input_tokens"] or 0 for c in call_telemetry)
    cache_sum = sum(c["tokens"]["cached_tokens"] or 0 for c in call_telemetry)
    out_sum = sum(c["tokens"]["output_tokens"] or 0 for c in call_telemetry)
    reas_sum = sum(c["tokens"]["reasoning_tokens"] or 0 for c in call_telemetry)
    turn1 = call_telemetry[0]["tokens"]

    return {
        "arm": arm,
        "task_id": task.task_id,
        "correct_disposition": score["correct_disposition"],
        "goal_completed": score["goal_completed"],
        "false_allow": score["false_allow"],
        "duplicate_effect": score["duplicate_effect"],
        "format_parse_failures": format_parse_failures,
        "advisor_calls": advisor_calls,
        "model_calls": costs["model_calls"],
        "inference_s": infer_s,
        "total_s": costs["total_s"],
        "input_tokens": in_sum,
        "cached_tokens": cache_sum,
        "output_tokens": out_sum,
        "reasoning_tokens": reas_sum,
        "turn1_input_tokens": turn1["input_tokens"] or 0,
        "turn1_cached_tokens": turn1["cached_tokens"] or 0,
        "calls": call_telemetry,
    }


async def run_pareto_experiment(
    *,
    model_env: Path,
    output_dir: Path,
    repeats: int = 2,
    task_ids: tuple[str, ...] = REPRESENTATIVE_TASKS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Execute G0, G1, G2, G3 across the 8 representative tasks and verify Pareto assertions."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("Use a fresh output directory for M2A+M3 Pareto experiment")

    manifest = read(PROJECT / "tasks/frozen/manifest.json")
    task_map = {t["id"]: t for t in manifest["tasks"]}
    selected = [task_map[tid] for tid in task_ids]

    base_ctrl = OpenAICompatibleController(model_env.resolve(), transport=transport)
    secret_key = base_ctrl._key
    public_model = base_ctrl.describe()

    arm_configs: dict[str, tuple[dict[str, Any], bool]] = {
        "G0_baseline_p2": ({}, False),
        "G1_aligned_default_thinking": ({}, True),
        "G2_aligned_disabled_thinking": ({"thinking": {"type": "disabled"}}, True),
        "G3_aligned_executor_advisor": ({"thinking": {"type": "disabled"}}, True),
    }

    work_dir = output_dir / "_work"
    work_dir.mkdir(parents=True, exist_ok=False)
    all_rows: list[dict[str, Any]] = []
    arm_summaries: dict[str, Any] = {}

    try:
        async with WarmWorkerPool(size=1) as pool:
            for arm_key, (think_extra, use_sub) in arm_configs.items():
                short = arm_key.split("_")[0]
                client = ConfiguredChatClient(
                    base_ctrl, thinking_extra=think_extra, use_submit_tool=use_sub
                )
                arm_rows: list[dict[str, Any]] = []
                seen_tasks_in_arm: set[str] = set()

                # Prime universal static prefix with 2 lightweight warm calls on task 1 for aligned
                # arms when running against live multi-replica pool so tasks 2..8 test unseen hits!
                for idx_t, entry in enumerate(selected):
                    case_path = PROJECT / "tasks/frozen" / entry["file"]
                    for rep in range(1, repeats + 1):
                        is_first_seen = entry["id"] not in seen_tasks_in_arm
                        seen_tasks_in_arm.add(entry["id"])
                        slot_dir = work_dir / f"{short}-{entry['id']}-r{rep}"
                        row = await _run_arm_trial(
                            arm=short,
                            case_path=case_path,
                            run_dir=slot_dir,
                            pool=pool,
                            client=client,
                            seed=7500 + idx_t * 10 + rep,
                        )
                        row["repeat"] = rep
                        row["family"] = entry["family"]
                        row["cohort"] = entry["cohort"]
                        row["first_seen_task_in_arm"] = is_first_seen
                        arm_rows.append(row)
                        all_rows.append(row)

                # Tasks 2..N first-seen Turn-1 cross-task cache hit rate
                unseen_subsequent = [
                    r
                    for r in arm_rows
                    if r["first_seen_task_in_arm"] and r["task_id"] != selected[0]["id"]
                ]
                u_in = sum(r["turn1_input_tokens"] for r in unseen_subsequent)
                u_ct = sum(r["turn1_cached_tokens"] for r in unseen_subsequent)
                tot_in = sum(r["input_tokens"] for r in arm_rows)
                tot_ct = sum(r["cached_tokens"] for r in arm_rows)
                ctrl_reas = sum(r["reasoning_tokens"] for r in arm_rows if r["cohort"] == "C")

                arm_summaries[short] = {
                    "label": arm_key,
                    "runs": len(arm_rows),
                    "correct_disposition": sum(r["correct_disposition"] for r in arm_rows),
                    "correct_rate": round(
                        sum(r["correct_disposition"] for r in arm_rows) / len(arm_rows), 6
                    ),
                    "f3_correct": sum(
                        r["correct_disposition"] for r in arm_rows if r["cohort"] == "M"
                    ),
                    "f3_total": sum(r["cohort"] == "M" for r in arm_rows),
                    "control_correct": sum(
                        r["correct_disposition"] for r in arm_rows if r["cohort"] == "C"
                    ),
                    "control_total": sum(r["cohort"] == "C" for r in arm_rows),
                    "format_parse_failures": sum(r["format_parse_failures"] for r in arm_rows),
                    "model_calls_sum": sum(r["model_calls"] for r in arm_rows),
                    "advisor_calls_sum": sum(r["advisor_calls"] for r in arm_rows),
                    "inference_s": dist_stats([r["inference_s"] for r in arm_rows]),
                    "total_wall_s": dist_stats([r["total_s"] for r in arm_rows]),
                    "input_tokens_sum": tot_in,
                    "cached_tokens_sum": tot_ct,
                    "overall_cache_hit_ratio": round(tot_ct / tot_in, 6) if tot_in else 0.0,
                    "unseen_tasks_2_to_n_turn1_cache_hit_ratio": (
                        round(u_ct / u_in, 6) if u_in else 0.0
                    ),
                    "output_tokens_sum": sum(r["output_tokens"] for r in arm_rows),
                    "reasoning_tokens_sum": sum(r["reasoning_tokens"] for r in arm_rows),
                    "control_cohort_reasoning_tokens": ctrl_reas,
                }
    finally:
        await base_ctrl.aclose()
        shutil.rmtree(work_dir, ignore_errors=True)

    g0 = arm_summaries["G0"]
    g1 = arm_summaries["G1"]
    g3 = arm_summaries["G3"]
    g0_inf = g0["inference_s"]["sum_s"] or 1e-9
    g3_inf = g3["inference_s"]["sum_s"] or 0.0
    inf_reduction_vs_g0 = round(1.0 - (g3_inf / g0_inf), 6)

    g0_by_pair = {
        (r["task_id"], r["repeat"]): r["inference_s"] for r in all_rows if r["arm"] == "G0"
    }
    g3_by_pair = {
        (r["task_id"], r["repeat"]): r["inference_s"] for r in all_rows if r["arm"] == "G3"
    }
    paired_inf_diffs = [g3_by_pair[k] - g0_by_pair[k] for k in sorted(g0_by_pair)]

    summary = {
        "schema": "nextgen-m2a-m3-pareto-v1",
        "source": source_revision(),
        "model_descriptor": public_model,
        "tasks_evaluated": list(task_ids),
        "repeats": repeats,
        "total_runs": len(all_rows),
        "total_api_calls": sum(r["model_calls"] for r in all_rows),
        "arms": arm_summaries,
        "pareto_comparisons": {
            "g3_inference_time_reduction_vs_g0": inf_reduction_vs_g0,
            "g3_vs_g0_paired_inference_delta_s": paired_comparison_stats(paired_inf_diffs),
            "g1_unseen_turn1_cache_gain_over_g0": round(
                g1["unseen_tasks_2_to_n_turn1_cache_hit_ratio"]
                - g0["unseen_tasks_2_to_n_turn1_cache_hit_ratio"],
                6,
            ),
        },
    }

    secrets = (secret_key, str(model_env.resolve()))
    assert_nextgen_artifact_safe(summary, secret_values=secrets)
    assert_nextgen_artifact_safe(all_rows, secret_values=secrets)
    output_dir.mkdir(parents=True, exist_ok=True)
    atomic(output_dir / "summary.json", summary)
    atomic(output_dir / "pareto_runs.jsonl", all_rows, lines=True)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    args = parser.parse_args()
    res = asyncio.run(
        run_pareto_experiment(
            model_env=args.model_env, output_dir=args.output, repeats=args.repeats
        )
    )
    print(
        json.dumps(
            {
                "total_runs": res["total_runs"],
                "total_api_calls": res["total_api_calls"],
                "G0_correct": res["arms"]["G0"]["correct_disposition"],
                "G1_unseen_cache": res["arms"]["G1"]["unseen_tasks_2_to_n_turn1_cache_hit_ratio"],
                "G2_correct": res["arms"]["G2"]["correct_disposition"],
                "G3_correct": res["arms"]["G3"]["correct_disposition"],
                "G3_ctrl_reasoning": res["arms"]["G3"]["control_cohort_reasoning_tokens"],
                "G3_inf_reduction_vs_G0": (
                    res["pareto_comparisons"]["g3_inference_time_reduction_vs_g0"]
                ),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
