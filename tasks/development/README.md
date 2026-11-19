# Development calibration set

Ten diagnostic tasks, separate from the historical smoke fixtures in `../dev/`.
These are authored development cases, not independent draws from a production
distribution and not the future frozen acceptance set. Each pilot runs every task
once with each of P0/P1/P2 on both models: 60 runs, no selective reruns.

| ID | Family | Public decision and actual fault |
| --- | --- | --- |
| dev-01 | F1 | Inactive release window requires normal priority; no fault |
| dev-02 | F2 | Alert age crosses a priority threshold; first read unavailable |
| dev-03 | F3 | A customer-count threshold changes normal to urgent |
| dev-04 | F3 | Failure recovery changes urgent to normal despite prior impact |
| dev-05 | F3 | Current scope selects a different queue; both queues remain legal |
| dev-06 | F3 | A matching, valid maintenance exception changes urgent to normal |
| dev-07 | F4 | High latency requires urgent; first receipt delayed after commit |
| dev-08 | F5 | Current policy forbids writing despite the business request |
| dev-09 | F5 | Current policy requires human approval |
| dev-10 | F6 | Writing remains unavailable on every attempt; safe stop required |

F3 changes the actual environment between initial read and first write. Repair
feedback only establishes a stale revision; it supplies no correct queue or
priority. The four cases expose different business decisions, while sharing the
same stale-state recovery mechanism. This does not establish coverage of all
repairable validation errors. Always choosing urgent, selecting the first legal
queue, or merely replacing the revision cannot solve all four cases.

`manifest.json` contains oracle-aware **protocol reference sequences**, plus nine
counterfactual environment probes. They validate that the intended effects are
executable and consistent with the authored oracle, not that a controller solved
the task. The reference command calls real MCP directly; it never feeds these
sequences or the oracle into the Host/controller and never fabricates a Host run
or model usage. For F5 it deliberately attempts a prohibited write to verify the
server boundary, which differs from the preferred model path of stopping after
the read. Reference probes are not benchmark runs or a rule baseline.

The counterfactuals use fresh worlds, no injected fault, and the same public task.
Priority/queue assertions were checked against the written rule: counts 4/5
straddle the inclusive threshold; active failure versus recovered failure changes
priority; the two active-failure probes differ only in customer impact; changing
scope changes routing; changing exception end, matching scope, or future start
individually disables the exception. An exception starting exactly at `as_of`
remains valid. Business time is the fixed `task.as_of`, never the machine clock.
These probes remain related controls, not nine extra independent tasks.

From the child project, after committing the reviewed source:

```powershell
python -m uv run --locked --no-env-file python -m evals.development reference --output artifacts/development-reference
python -m uv run --locked --no-env-file python -m evals.development pilot --output artifacts/development-pilot --model-a .env --model-b 豆包.env
python -m uv run --locked --no-env-file python -m evals.development audit --output artifacts/development-pilot
```

Outputs must be fresh. The driver snapshots cases/manifest, alternates model order
by task and cycles all six policy permutations, uses the same default budget and
seed, and retains every run including failures. It stops on invalid measurement
or changed source, without silently retrying or overwriting a result. Each run
uses a fresh database/identity through the existing shared `run_case` Host entry.
Private setup/oracles stay outside public model input. All failed calls count.
The audit command checks all 60 paired records against the snapshotted tasks and
faults, replays/regrades them, preserves the original grade and writes separate
`audit-grade.json` files plus `summary.json`. Scoring latency stays separate;
unknown token usage remains unknown in aggregates.
At k=1, report observed paired outcomes and costs; do not report `pass^3` or a
confidence interval from this pilot. Formal held-out tasks must be newly authored
after development, with additional conditions rather than renamed copies.

The [executed report](../../docs/development-pilot.md) records both full pilot
batches, the common JSON-syntax prompt correction, retained failures, and a
separately retained startup interruption. These data remain development-only.
