"""Append-only run events and offline reconstruction without executing any ports."""

import json
import subprocess
import time
from pathlib import Path


def source_revision() -> dict:
    """Best-effort source identity; metadata never participates in task decisions."""
    try:
        root = Path(__file__).resolve().parents[2]
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal", "--", "."],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
        return {"commit": revision.stdout.strip(), "dirty": bool(dirty.stdout.strip())}
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "dirty": None}


class TraceWriter:
    def __init__(self, path: Path):
        self.file = path.open("x", encoding="utf-8")
        self.started = time.perf_counter()
        self.sequence = 0

    def __call__(self, event: str, data: dict) -> None:
        self.sequence += 1
        self.file.write(
            json.dumps(
                {
                    "seq": self.sequence,
                    "elapsed_s": time.perf_counter() - self.started,
                    "event": event,
                    "data": data,
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def replay(directory: Path) -> dict:
    """Rebuild delivered observations and final output strictly from recorded events."""
    record, observations, previous = None, [], -1.0
    events = [
        json.loads(line)
        for line in (directory / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    for index, item in enumerate(events, 1):
        if item["seq"] != index or item["elapsed_s"] < previous:
            raise ValueError("Trace sequence or monotonic time is inconsistent")
        previous = item["elapsed_s"]
        event, data = item["event"], item["data"]
        if event == "run_start":
            if record is not None or index != 1:
                raise ValueError("Duplicate or misplaced run start")
            record = dict(data["record"])
        elif event == "feedback":
            observations.append(data["observation"])
        elif event == "controller_delivery":
            by_ref = {item["ref"]: item for item in observations}
            for ref in data["refs"]:
                if ref not in by_ref or by_ref[ref]["delivered"]:
                    raise ValueError("Invalid controller-delivery event")
                by_ref[ref]["delivered"] = True
        elif event == "terminal":
            if record is None or "output" in record:
                raise ValueError("Duplicate or misplaced terminal event")
            record["output"] = data["output"]
        elif event == "run_end":
            if record is None or "output" not in record or index != len(events):
                raise ValueError("Run was not sealed")
            record.update(data)
    if record is None or not events or events[-1]["event"] != "run_end":
        raise ValueError("Incomplete trace")
    record["observations"] = observations
    costs = record["costs"]
    if costs["model_calls"] != sum(e["event"] == "model_request" for e in events) or (
        costs["tool_attempts"] != sum(e["event"] == "tool_attempt" for e in events)
    ):
        raise ValueError("Recorded costs disagree with actual attempt events")
    wire_calls = sum(
        e["event"] == "wire_send" and e["data"].get("method") == "tools/call" for e in events
    )
    if wire_calls > costs["tool_attempts"]:
        raise ValueError("Unaccounted MCP requests in trace")
    if "limits" in record:
        maxima = {"input_estimate": 0, "input_tokens": None, "output_tokens": None,
                  "tool_result_bytes": 0}
        totals = dict.fromkeys(("input_tokens", "output_tokens"), 0)
        operations = dict.fromkeys(("initial_read", "write-0", "refresh_read"), 0)
        decisions = repairs = 0
        for item in events:
            event, data = item["event"], item["data"]
            if event == "model_request":
                estimate = len(json.dumps({"messages": data["messages"],
                                           "tools": data["tools"]}).encode()) + 128
                if estimate != data["estimated_input_tokens_byte_bound"]:
                    raise ValueError("Input estimate disagrees with recorded request")
                maxima["input_estimate"] = max(maxima["input_estimate"], estimate)
            if event in {"model_response", "model_failed"}:
                decisions += event == "model_response"
                for field in totals:
                    used = None if data["usage"] is None else data["usage"][field]
                    totals[field] = None if used is None or totals[field] is None else (
                        totals[field] + used
                    )
                    if used is not None:
                        maxima[field] = max(maxima[field] or 0, used)
            if event == "tool_attempt":
                operations[data["operation"]] += 1
                if data["envelope"]["attempt"] != operations[data["operation"]]:
                    raise ValueError("Operation attempt sequence disagrees with trace")
            if event == "tool_result":
                maxima["tool_result_bytes"] = max(
                    maxima["tool_result_bytes"], data["accepted_result_bytes"]
                )
            repairs += event == "recovery"
        counters = {"decision_steps": decisions, "operation_attempts": operations,
                    "repair_used": bool(repairs)}
        if (record["maxima"] != maxima or record["counters"] != counters
                or any(costs[field] != totals[field] for field in totals) or repairs > 1):
            raise ValueError("Budget evidence disagrees with actual trace events")
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest["record"] != record:
        raise ValueError("Manifest and replayed trace disagree")
    return record
