# Acceptance corpus v1

This corpus is frozen at Git tag **`harness-experiment-v1`**, after reference
execution and label review. `manifest.json` records 18 authored synthetic tasks,
their fixed M/C membership, fault plans, references, contrasts and differences
from development. `experiment.json` snapshots the common prompt, public tools,
models, dependencies, budgets, scheduling, spending and invalid-trial rules.

| Family | Tasks | Role |
| --- | --- | --- |
| F1 | acc-01–02 | No-fault controls |
| F2 | acc-03–04 | Two transient read/write failures |
| F3 | acc-05–10 | Six new compound decisions after a real state change (M) |
| F4 | acc-11–12 | Two lost/damaged deliveries after one committed write |
| F5 | acc-13–15 | Two prohibitions and one explicit approval policy |
| F6 | acc-16–18 | Persistent read/write unavailability |

The other twelve tasks form C. Each task has three isolated trials per model and
policy: 54 paired blocks, six slots per block, 324 planned trials. Fixed scheduling
balances all six policy permutations nine times per model; each block shares its
fault plan and backoff seed while each slot gets a fresh world/identity. A model
random seed is not requested. Provider-default thinking and a temperature request
of zero do not promise deterministic execution or fixed provider backend weights.

Reference sequences and twelve F3 contrasts are oracle-aware environment probes,
outside the Host/model. They are not scored model trials or extra independent
tasks. Public requirements, initial/final decisions and contrasts were independently
reviewed. The six F3 cases have new combinations of deadlines, dynamic capacity,
set intersections/coverage, ownership and precedence; they share the same stale-state
mechanism and some logical primitives, and do not represent production sampling.
Every final state offers legal but semantically wrong alternatives. Full business
rule branch coverage is not claimed. F5 checks obeying the existing explicit policy,
not implementation of a dynamic authorization or two-person approval system.

From the child project, with reviewed source committed and a fresh output directory:

```powershell
python -m uv run --locked --no-env-file python -m evals.acceptance plan --output artifacts/new-acceptance-plan
python -m uv run --locked --no-env-file python -m evals.acceptance reference --output artifacts/new-acceptance-reference
```

Both commands call zero model APIs. `plan` creates the 324-slot schedule; `reference`
also probes real MCP, effects, receipts and final state. The common single-case
driver supports an explicit backoff seed and still calls the same public runtime.
Formal execution and its batch reservation/stop tests remain a separate next step;
these commands cannot start the paid experiment or enforce a provider billing cap.

Never tune these tasks, prompts, budgets or strategy from their API results and
then continue calling them held-out acceptance. Any such tuning requires a new
acceptance set. Keep started API/format failures as scored trials; pause on invalid
measurement, retain evidence, and rerun the whole paired block only after diagnosis.

The [freeze report](../../docs/acceptance-freeze.md) records the 30 verified worlds,
85 actual MCP requests, schedule review, costs and known provider limitations.
No model API was called on this corpus during preparation.
