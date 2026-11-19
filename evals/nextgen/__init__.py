"""Downstream Next-Gen Harness extensions; frozen core runtime and v2 evidence stay read-only."""

from __future__ import annotations

import json
import random
from pathlib import Path
from statistics import fmean
from typing import Any

from evals.diagnostics import dist_stats, rel_posix
from evals.diagnostics.acc15_probe import assert_probe_artifact_safe
from evals.post_training import SecurityViolationError, enforce

PROJECT = Path(__file__).resolve().parents[2]

__all__ = [
    "PROJECT",
    "SecurityViolationError",
    "assert_nextgen_artifact_safe",
    "dist_stats",
    "enforce",
    "paired_comparison_stats",
    "rel_posix",
]


def assert_nextgen_artifact_safe(payload: Any, *, secret_values: tuple[str, ...] = ()) -> None:
    """Block any Host wire envelope, private fault/oracle, credential, or local path on disk."""
    assert_probe_artifact_safe(payload, secret_values=secret_values)


def paired_comparison_stats(
    paired_diffs: list[float], *, seed: int = 20261118, resamples: int = 4000
) -> dict[str, Any]:
    """Compute exact sign-flip permutation p-value and bootstrap 95% CI on paired differences."""
    n = len(paired_diffs)
    if n == 0:
        return {
            "pairs": 0,
            "mean_diff": None,
            "bootstrap_95": None,
            "two_sided_sign_flip_p": None,
        }
    observed = fmean(paired_diffs)
    rng = random.Random(seed)
    boot = sorted(fmean(rng.choices(paired_diffs, k=n)) for _ in range(resamples))
    lo = boot[int(0.025 * (resamples - 1))]
    hi = boot[int(0.975 * (resamples - 1))]

    # Exact enumeration when n <= 16, Monte Carlo sign-flip otherwise
    abs_obs = abs(observed)
    if n <= 16:
        total = 1 << n
        extreme = 0
        for mask in range(total):
            flipped = (
                sum(paired_diffs[i] if (mask >> i) & 1 else -paired_diffs[i] for i in range(n)) / n
            )
            if abs(flipped) >= abs_obs - 1e-12:
                extreme += 1
        p_val = extreme / total
    else:
        extreme = sum(
            abs(sum(d if rng.getrandbits(1) else -d for d in paired_diffs) / n) >= abs_obs - 1e-12
            for _ in range(resamples)
        )
        p_val = extreme / resamples

    return {
        "pairs": n,
        "mean_diff": round(observed, 6),
        "bootstrap_95": [round(lo, 6), round(hi, 6)],
        "two_sided_sign_flip_p": round(p_val, 6),
    }


def dump_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
