"""CLI entry for offline latency decomposition and acc-15 protocol-field inspection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.diagnostics import run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = run(args.input, args.output)
    print(
        json.dumps(
            {
                "runs": summary["runs"],
                "input_unchanged": summary["input_unchanged"],
                "model_api_calls": summary["model_api_calls"],
                "anomalies": len(summary["acc15_protocol_summary"]["anomalies"]),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
