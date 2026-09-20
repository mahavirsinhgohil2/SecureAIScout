# SecureAI Scout Slides

## Slide 1: The problem
- Security findings are difficult to explain to a non-security audience.
- A proposed fix is not the same as a tested fix.
- Teams need context, evidence, and a human approval point.

Speaker note: This project focuses on one controlled ShopEasy demo, not production systems.

## Slide 2: The solution
- SecureAI Scout turns a local scan into a reviewable workflow.
- It investigates, triages context, proposes targeted changes, verifies them in a sandbox, and asks for approval.
- The final cache contains 36 events: 7 raw findings, 6 real findings, and 1 removed false alarm.

Speaker note: Describe it as deterministic scanner + rule-based triage + deterministic sandbox verifier.

## Slide 3: Workflow
```text
INVESTIGATE -> TRIAGE -> FIX -> VERIFY -> REVIEW
       scan       context     snippets   sandbox     human approval
```
- Every stage emits a plain-English event.
- Command injection used 3 attempts: weak patch rejected, model correction unavailable, deterministic fallback verified.
- Only verifier proof creates the Verified state.

Speaker note: The cache contains 33 events from the real run.

## Slide 4: Architecture
- Scanner: six controlled Python patterns plus the allowlisted query example.
- Agent: deterministic triage, snippet replacement, retry, risk scoring, and cache writer.
- Verifier/UI: temporary sandbox checks and Streamlit review/export controls.

Speaker note: The original `demo_app/` remains unchanged; fixes are tested in a temporary copy.

## Slide 5: Demo evidence
- Screenshot placeholder: investigate and triage event trace.
- Screenshot placeholder: command-injection failed verification followed by retry success.
- Screenshot placeholder: review cards with diff, proof, and approval control.

Speaker note: Use replay mode if live timing is risky; the tracked cache contains the same run.

## Slide 6: Trust model
- A language model explains findings and proposes a corrected patch when the verifier rejects one; deterministic rules decide what is real, a sandbox verifier decides what is verified, and a human approves.
- The verifier checks syntax, rescans the sandbox, applies a command-safety rule, and runs demo tests.
- A human approval is required before the patch download appears.

Speaker note: The default path is offline and built-in rules provide explanations; enabling the optional provider never changes triage or verification.

## Slide 7: Results from the real run

| Metric | Value |
|---|---:|
| Raw findings | 7 |
| Real findings | 6 |
| False alarms removed | 1 |
| Verified | 6 |
| Command-injection attempts | 3 |
| Event count | 36 |
| Risk before -> after | 78 -> 1 |

Speaker note: The risk score uses deterministic severity weights and a small residual after verification; it is a secondary signal, not a security guarantee.

## Slide 8: Limits and roadmap
- Current scope: Python and one bundled intentionally vulnerable demo.
- Scout does not scan production, find every vulnerability, or perform autonomous production remediation.
- Future scope: PR creation, more languages, and optional real-LLM triage.

Speaker note: `HF_TOKEN` and `ENABLE_LLM_EXPLANATIONS=true` opt into explanation text only; without them the built-in rules run offline.
