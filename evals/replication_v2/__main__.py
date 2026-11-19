"""Execute the independently frozen second replication once."""
import argparse
import asyncio
from pathlib import Path

from evals.replication_v2 import run

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--model-a", type=Path, required=True)
parser.add_argument("--model-b", type=Path, required=True)
args = parser.parse_args()
raise SystemExit(0 if asyncio.run(run(args.output, {
    "A": args.model_a.resolve(), "B": args.model_b.resolve()})) else 1)
