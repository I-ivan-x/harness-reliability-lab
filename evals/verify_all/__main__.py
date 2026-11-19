"""CLI entry for `python -m evals.verify_all`."""

from __future__ import annotations

import sys

from evals.verify_all import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
