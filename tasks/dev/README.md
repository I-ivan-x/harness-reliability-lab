# Development tasks

Development fixtures are separate from the frozen acceptance set:

| File | Purpose |
| --- | --- |
| `normal.json` | One permitted, ordinary-priority ticket |
| `refused.json` | Current policy forbids the write; grounded refusal and no effect |
| `lost-response.json` | First committed response is delayed; original-key replay |
| `customer-impact.json` | Same public rule as normal; customer impact flips priority |
| `state-change.json` | Initial read is v1/normal; a persistent pre-write change requires v2/urgent |
| `read-transient.json` | Initial read attempt 1 is unavailable; bounded retries recover |
| `unavailable.json` | Every write attempt is unavailable; stop honestly with unknown write outcome |
| `approval.json` | Current policy requires human approval and no write |
| `malformed-read.json` | Invalid application read result; expected runtime failure, no retry |
| `malformed-write.json` | Real commit followed by invalid receipt; original-key replay can confirm |

`normal.json` and `customer-impact.json` have identical public task input, including
the task ID. Only the environment fact changes; they are two smoke variants, not
two independent task samples.

Only `task_input` enters the Host. `environment` initializes the isolated current
world; `fault_plan` goes only to the tool server; `oracle` goes only to the independent
grader. No fixture is a member of the planned frozen 18-task acceptance set. These
fixtures demonstrate a development path, not measured policy superiority.
The ten files include related smoke variants and negative contract fixtures;
they are not ten independent development/held-out tasks. For example,
`malformed-read.json` retains the original completion oracle so that stopping
safely still scores zero for an unfinished goal. The G2 test separately asserts
that this is the required runtime failure behavior. The distinct calibrated
task set and full pilot now live under [development](../development/README.md);
these historical fixtures retain their original meaning and evidence links.

`state-change.json` is a P2 development fixture. Its private `state_change` fault
updates SQLite once after an initial read and before write attempt 1. Retrying the
old request remains invalid; a fresh read exposes the new revision and business
fact. The fault response never supplies a complete corrected request.

Selected response/delay faults use Host-bound `stage` plus attempt number;
`attempts: null` persists for all attempts of that stage. Initial reads and
recovery refreshes cannot consume each other's fault selector. Temporary tool
errors, invalid application results, and actual JSON-RPC errors have separate
integration checks; a private pre-commit location never tells the Host a write
is known not to have happened.
