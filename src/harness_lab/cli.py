"""Installed CLI: offline diagnostics, public runtime entry, and read-only replay."""

import argparse
import asyncio
import json
import sys
from importlib.metadata import version
from pathlib import Path

FORBIDDEN_ROOTS = ("app", "scripts", "evals")


def doctor_report() -> dict[str, object]:
    """Report the loaded-module boundary without loading configuration or tools."""
    forbidden = sorted(
        name
        for name in sys.modules
        if any(name == root or name.startswith(f"{root}.") for root in FORBIDDEN_ROOTS)
    )
    return {
        "package": "harness-reliability-lab",
        "version": version("harness-reliability-lab"),
        "package_location": str(Path(__file__).resolve().parent),
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "loaded_forbidden_modules": forbidden,
        "loaded_module_boundary_ok": not forbidden,
        "g1_implemented": True,
        "g1_acceptance": "See specs/README.md; implementation is not an experiment result",
    }


def main(argv: list[str] | None = None) -> int:
    """Parse the offline CLI and return its process exit code."""
    parser = argparse.ArgumentParser(prog="harness-lab")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="report package installation and loaded-module boundaries")
    replay = commands.add_parser("replay", help="reconstruct a sealed run without tools or API")
    replay.add_argument("directory", type=Path)
    execute = commands.add_parser(
        "run", help="run a public task against a prepared MCP environment"
    )
    execute.add_argument("task", type=Path, help="public TaskInput JSON; no oracle or fault plan")
    execute.add_argument(
        "--server-config", type=Path, required=True, help="opaque server config path"
    )
    execute.add_argument("--run-id", required=True, help="must match the trusted server grant")
    execute.add_argument("--principal", default="dev-user")
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--model", choices=["scripted", "api"], required=True)
    execute.add_argument("--model-env", type=Path, help="explicit independent API config file")
    execute.add_argument("--policy", choices=["P0", "P1", "P2"], default="P1")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        report = doctor_report()
    elif args.command == "replay":
        from harness_lab.trace import replay as replay_run

        report = replay_run(args.directory)
    else:
        from harness_lab.contracts import Ports, RunConfig, TaskInput
        from harness_lab.mcp_port import MCPToolPort
        from harness_lab.models import ModelError, OpenAICompatibleController, ScriptedController
        from harness_lab.runtime import run

        if args.model == "api" and args.model_env is None:
            parser.error("API mode requires an explicit --model-env file")
        try:
            controller = (
                ScriptedController()
                if args.model == "scripted"
                else OpenAICompatibleController(args.model_env)
            )
        except ModelError as exc:
            parser.error(str(exc))
        task = TaskInput(**json.loads(args.task.read_text(encoding="utf-8")))
        config = RunConfig(args.run_id, args.principal, args.output.resolve(), policy=args.policy)
        tools = MCPToolPort(args.server_config, args.output / "mcp-stderr.log")
        report = asyncio.run(run(task, config, Ports(controller, tools)))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.command == "doctor":
        return 0 if report["loaded_module_boundary_ok"] else 1
    return (
        0
        if report["measurement_valid"] and report["output"]["disposition"] != "SYSTEM_FAILURE"
        else 1
    )
