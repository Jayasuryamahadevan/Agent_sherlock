# The three execution pipelines

All three pipelines share one investigation engine (`agent/pipelines.py`, `BasePipeline`):

```
complaint -> triage -> collect evidence -> reason -> [collect follow-up evidence -> reason]* -> _act()
```

* **Triage** picks the category and the first evidence to collect (AI, or rules if explicitly selected).
* **Reasoning** returns hypotheses that quote real evidence (checked by code), then one of
  `collect_more`, `propose_action`, `conclude`, `ask_user`.
* **Follow-up rounds** are limited to `max_diagnostic_rounds` (3).
* `_act()` is the only part that differs. Each pipeline class implements it separately.

Authorization is enforced by code, not prompts: `PolicyEngine` decides and signs the decision (HMAC), and
`Executor` refuses anything unsigned, modified, replayed, denied, or missing a required approval.

## Pipeline 1 - Automatic execution (`AutomaticExecutionPipeline`)

Policy: `change_mode = NEVER`. Automatically executes **read-only diagnostic operations only**.

1. Triage, collect, reason (shared).
2. Re-collect the evidence types cited by the top hypothesis and reason again (confirmation re-measurement).
   The result is recorded as `diagnosis_confirmed` (true = reproduced, false = may be intermittent).
3. If the reasoner proposes a fix, the policy engine is still consulted. The report contains a
   **recommendation** (`executed: false`, whether the evidence supports it, policy notes). Nothing is changed.
4. Status: `diagnosed`, `cause_undetermined` or `needs_clarification`.

## Pipeline 2 - Automatic execution and resolution (`AutoResolutionPipeline`)

Policy: `change_mode = AUTOMATIC`, risk up to **medium**, at most **2** corrective attempts.

1. Triage, collect, reason (shared).
2. A proposed action goes to the `PolicyEngine`. It is eligible only if all of these hold: the action is
   catalogued; its parameters validate; it is linked to a hypothesis that survived evidence grounding; its
   precondition is satisfied by current evidence; it was not already attempted with the same parameters; the
   attempt limit is not reached; elevation is present if required; and it is not high risk.
3. If allowed, the `Executor` runs it. **Fresh evidence** is then collected and the action's verification function
   compares before and after: `resolved`, `improved`, `unchanged`, `worsened` or `inconclusive`.
4. `resolved` ends the session. Otherwise the reasoner is shown the failed attempt and the fresh evidence and may
   revise, up to the attempt limit. Policy refusals are shown to the reasoner too (at most 2 refusals, then stop).
5. Final status: `resolved`, `partially_resolved`, `not_resolved`, `action_refused`, and so on.
   "Command succeeded" and "problem resolved" are separate fields; only verification can set `resolved`.

Stops when: resolved; evidence is insufficient; the action is refused or high risk (a human is needed); or
2 attempts have been used.

## Pipeline 3 - Whitelist and approval before action (`WhitelistApprovalPipeline`)

Policy: `change_mode = WITH_APPROVAL` with a **parameter-constrained whitelist** (narrower than the catalogue).

1. Triage, collect, reason (shared).
2. A proposed action goes to the `PolicyEngine`: the same checks as Pipeline 2, plus the whitelist:
   * `restart_service`: only `Spooler`, `WSearch`, `BITS` (not `wuauserv` or `Audiosrv`).
   * `clear_temp_files`: `max_age_days >= 3`.
   * Any action not on the list is denied.
3. Verdict `require_approval` builds an `ApprovalRequest` (action, parameters, risk, reversibility, consequences,
   justification, supporting evidence) and hands it to an `ApprovalProvider`:
   * CLI: `ConsoleApprovalProvider` (only an explicit `yes` approves).
   * API/UI: the session pauses as `awaiting_approval`; `POST /api/agent/sessions/{id}/approval` resumes it.
4. The approval must match the pending `decision_id` and arrive within 15 minutes. A denied, expired,
   mismatched or missing approval means **nothing is executed**.
5. After approval: execute, collect fresh evidence, verify, record the result. May loop (max 2 attempts).

## Shared enforcement (`remediation/`)

| Rule | Where |
|---|---|
| Only catalogued operations exist; anything else is denied in every pipeline | `catalogue.py`, `policy.py` |
| Parameters validated by strict schemas (unknown fields, wrong types, injection strings rejected) | `catalogue.py` |
| Each action has an evidence precondition ("is this justified?") | `catalogue.py` |
| Protected processes (`lsass.exe`, `explorer.exe`, `python.exe`, ...) can never be terminated | `catalogue.py` |
| Decisions are HMAC-signed, single use, and bound to their approval | `policy.py`, `executor.py` |
| Parameters reach PowerShell through environment variables, never script text | `backends.py` |
| Real system changes are off unless `DIAG_ALLOW_SYSTEM_CHANGES=1` or `--allow-changes` | `backends.py` |
| Every stage is written to a JSONL audit log (decisions and outcomes, not raw evidence) | `agent/audit.py` |

## Tests

```
python -m pytest tests/test_pipelines.py                    # each pipeline, independent scenarios
python -m pytest tests/test_agent_safety.py                 # grounding, forged/replayed decisions, injection, refusal
python -m pytest tests/test_agent_api.py                    # HTTP flow including the approval endpoint
python -m pytest tests/test_cim_collectors_and_backend.py   # collectors and the real backend (mocked subprocess)
```
