"""Single-case driver: private setup stays outside the public runtime input."""

import argparse
import asyncio
import json
import uuid
from pathlib import Path

from evals.grader import grade
from harness_lab.storage import initialize_environment


def prepare_case(case_path: Path, outdir: Path, *, principal: str = "dev-user") -> dict:
    """Create one fresh world; never reuse another trial's key or database."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=False)
    run_id = "run-" + uuid.uuid4().hex
    operation = run_id + ":write-0"
    database = outdir / "environment.sqlite"
    initialize_environment(database, case["environment"])
    server = {
        "db_path": str(database), "run_id": run_id, "principal": principal,
        "operation_id": operation, "idempotency_key": operation,
        "target_ref": case["task_input"]["target_ref"], "can_read": True, "can_write": True,
        "fault": case["fault_plan"] or None,
    }
    server_path = outdir / "private-server.json"
    server_path.write_text(json.dumps(server, indent=2), encoding="utf-8")
    return {
        "task_input": case["task_input"], "oracle": case["oracle"], "run_id": run_id,
        "principal": principal, "server_path": server_path, "database": database,
        "artifact_dir": outdir,
    }


async def run_case(
    case_path: Path, outdir: Path, *, model: str = "scripted", model_env: Path | None = None,
    policy: str = "P1", seed: int = 0,
) -> dict:
    from harness_lab.contracts import Ports, RunConfig, TaskInput
    from harness_lab.mcp_port import MCPToolPort
    from harness_lab.models import OpenAICompatibleController, ScriptedController
    from harness_lab.runtime import run
    from harness_lab.trace import replay

    if model not in {"scripted", "api"} or (model == "api" and model_env is None):
        raise ValueError("API mode requires an explicit local --model-env file")
    prepared = prepare_case(case_path, outdir)
    config = RunConfig(
        run_id=prepared["run_id"], principal=prepared["principal"],
        artifact_dir=prepared["artifact_dir"], policy=policy, seed=seed,
    )
    controller = (
        ScriptedController() if model == "scripted" else OpenAICompatibleController(model_env)
    )
    tools = MCPToolPort(prepared["server_path"], outdir / "mcp-stderr.log")
    await run(TaskInput(**prepared["task_input"]), config, Ports(controller, tools))
    # Grading uses the same reconstruction path as offline regrade.
    result = grade(replay(outdir), prepared["database"], prepared["oracle"])
    (outdir / "grade.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def regrade_case(case_path: Path, outdir: Path) -> dict:
    """Reconstruct only recorded events; no model, MCP, or setup calls."""
    from harness_lab.trace import replay

    case = json.loads(case_path.read_text(encoding="utf-8"))
    return grade(replay(outdir), outdir / "environment.sqlite", case["oracle"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path, help="fresh artifact directory")
    destination.add_argument("--regrade", type=Path, help="existing run; never executes it")
    parser.add_argument("--model", choices=["scripted", "api"], default="scripted")
    parser.add_argument("--model-env", type=Path)
    parser.add_argument("--policy", choices=["P0", "P1", "P2"], default="P1")
    args = parser.parse_args()
    if args.regrade:
        result = regrade_case(args.case, args.regrade)
    else:
        result = asyncio.run(run_case(
            args.case, args.output, model=args.model, model_env=args.model_env, policy=args.policy,
        ))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
