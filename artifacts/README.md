# Generated artifacts and immutable evidence

Current primary evidence is the complete 2026-11-17 batch:
`replication-v2-2026-11-17/` (324 runs, no model API failure), its sibling
`replication-v2-2026-11-17-audit/`, and
`harness-replication-v2-2026-11-17.zip`. See the
[current result](../docs/empirical-evaluation.md). Earlier evidence below is
historical and stays unchanged; do not merge it into the current sample.

Store traces, receipts, isolated state and experiment outputs here. Generated
outputs are ignored by default; credentials and unrelated legacy artifacts stay
out. A fresh clone does not include these local records. Historical gate evidence
is indexed in [the specification index](../specs/README.md).

`restored-v1/` is the immutable historical composite input: 216 retained runs under
`original/`, 108 fresh runs under `restored/`, and the combined 324-row ledger,
frozen snapshots, raw grades and source mapping. This post-restoration composite
spans two periods; the 27 new HTTP 403 zero scores remain. Excluded original
service-error records stay only in their separate local archive and are absent
from that historical composite's statistics, failure cases and delivery.

The v2 repair writes to a fresh sibling, never back into `restored-v1/`:

```powershell
python -m uv run --locked --no-env-file python -m evals.evidence_audit --input artifacts/restored-v1 --output artifacts/my-verification-v2
```

The delivered `verification-v2-2026-11-12/` contains completed `runs.jsonl`,
`summary.json` and `complete.json` for historical grading/protocol/Gate verification.
The command intentionally uses the different fresh name `my-verification-v2/`;
choose another output name if it already exists. Original grades/diagnostics/ledgers and the
input tree are fingerprinted and preserved; changed decision signatures abort
verification. These checks call no model API or business tool and do not add
formal trials.

`harness-evidence-verified-v2.zip` is the historical delivery path for source, frozen
inputs, all included records and separate v2 verification. Its README documents
portable installation and the fresh-output audit command. The earlier
`harness-evidence-restored-v1.zip` remains unchanged as historical delivery.
Both omit credentials and the replaced original errors. Obtain the delivery ZIP
separately after cloning to inspect the exact 324 runs.

See [control-plane and audit specification](../docs/architecture-and-protocol.md) for architecture,
verification contracts, and audit invariants, and [the empirical evaluation report](../docs/empirical-evaluation.md)
for experimental results, usage, and scope. Historical development tests,
forced controller fixtures and reference probes are never counted in the main
model sample. This repair does not explain or rerun the 403 failures.
