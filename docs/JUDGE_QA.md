# Judge Q&A

## 1. Where is the AI?
A language model explains findings when the optional Hugging Face integration is enabled; deterministic rules decide triage, deterministic sandbox checks verify fixes, and a human approves. With no token or flag, built-in rules provide the explanation and the full demo remains offline.

## 2. What stops it approving a bad fix?
The system never approves automatically. The verifier must pass syntax, sandbox rescan, command-specific safety, and demo tests before a finding can show Verified, and a human must approve before export.

## 3. What if the verifier is wrong?
A deterministic verifier can still encode incomplete checks. The proof is evidence for the controlled demo, not a universal guarantee, which is why the project keeps human approval and states its scope clearly.

The risk score also keeps a residual floor of 1 after verification because a scan of one demo app never proves zero risk.

## 4. Why deterministic checks?
They make the result repeatable offline and let a judge inspect exactly why a patch passed or failed. In the real run, the first command fix failed because unsafe execution remained.

## 5. How is this different from Snyk, Semgrep, or Dependabot?
Those are broader established tools; SecureAI Scout is a small agentic review experience that connects findings, plain-English triage, targeted sandbox verification, retry, and human approval in one demo. It is not claiming their breadth.

## 6. Does it work on real repositories?
The current implementation is intentionally limited to the bundled `demo_app/` and guards scanner/agent paths accordingly. It is not presented as a production repository scanner.

## 7. Is it safe?
The verifier copies the demo into a temporary sandbox and never edits the original demo in place. The UI and runner operate locally, and the replay path needs no API or network.

## 8. What happens if the retry also fails?
The agent emits a failed verification event and does not produce verifier proof. The finding cannot truthfully show Verified, and the export remains approval-gated.

## 9. How do you handle false positives?
Triage reads nearby source context. In this run it recognized the `/get-table` membership check and removed that one result with the explanation that the table name is checked against a short list.

## 10. What is the business value?
The value is review efficiency and trust: a developer sees what was found, why it matters, what changed, which checks passed, and where they must approve. This demo measures that flow with 33 readable events.

## 11. How does it scale?
This build does not claim production scale. It uses simple line-based scanning and one bundled app; scaling would require stronger parsing, job isolation, persistence, and broader test coverage.

## 12. Why Python only?
The demo app, scanner, verifier, and UI are all Python, which kept the four-hour hackathon scope coherent. More languages are a future direction, not a current capability.

## 13. What did each team member build?
Mahavir built the scanner, agent, verifier, and deterministic retry flow. Maitri built the Streamlit UI and visual system. Vrushti built the demo app, tests, documentation, and pitch assets.

## 14. What would you build next?
The stated roadmap is PR creation, more languages, and an optional real-LLM triage layer. Any such layer would remain separate from deterministic verification.

## 15. What are the limitations?
The tool covers one intentionally vulnerable Python demo and six controlled patterns. It does not find every vulnerability, perform autonomous production remediation, or prove real-world security from one run; the real output is risk 78 -> 1 for this scoped demo.
