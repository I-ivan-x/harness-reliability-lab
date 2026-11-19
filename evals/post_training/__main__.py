"""CLI entry for security-filtered post-training SFT and preference trajectory export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.post_training import run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--include-host-retry",
        action="store_true",
        help="also export Host-retried completed runs alongside certified reproposal runs",
    )
    args = parser.parse_args()
    summary = run(args.input, args.output, include_host_retry=args.include_host_retry)
    print(
        json.dumps(
            {
                "sft_samples": summary["sft"]["samples"],
                "preference_pairs": summary["preference"]["pairs"],
                "security_assertions_passed": summary["security_assertions"]["all_passed"],
                "input_unchanged": summary["input_unchanged"],
                "model_api_calls": summary["model_api_calls"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
