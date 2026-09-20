# Replay Video Shot List

Record this backup video from replay mode. Target length: under 3:00.

| Time | Screen | Click sequence | Narration |
|---|---|---|---|
| 0:00-0:15 | Start screen | Open Streamlit and show `Start demo scan`. | "This is an offline replay of a real SecureAI Scout run against the bundled ShopEasy demo." |
| 0:15-0:35 | Work view | Click `Start demo scan`; let the event trace appear. | "The cache preserves 36 events, including investigation and context-aware triage." |
| 0:35-0:55 | Triage trace | Scroll to the false-alarm message. | "Seven raw findings become six real findings because the allowlisted table lookup is dismissed." |
| 0:55-1:15 | Verify trace | Scroll to command injection. | "The weak patch fails with the real verifier reason: `syntax check passed; command safety check failed because unsafe command execution remains`." |
| 1:15-1:35 | Model correction event | Show the fix trace. | "The model suggests, the verifier decides. The cache records `Asking the language model to correct the patch using the verifier's feedback.` The model then does not return a usable patch." |
| 1:35-1:55 | Deterministic fallback | Show the fallback and success events. | "The system records `The language model did not return a usable patch; using the built-in correction.` The deterministic fix is verified with `syntax check passed; command safety check passed; sandbox rescan passed; demo tests passed`." |
| 1:55-2:15 | Review summary | Show risk and metric cards. | "The run reports 6 verified real findings after 3 command-injection attempts, with risk moving from 78 to 1." |
| 2:05-2:25 | Finding card | Open a diff and proof; point to `Verified`. | "The badge is tied to proof text, not to approval or an AI claim. A language model explains findings and proposes a corrected patch when the verifier rejects one; deterministic rules decide what is real, a sandbox verifier decides what is verified, and a human approves." |
| 2:25-2:45 | Approval | Click `Approve verified fix` or `Approve all verified fixes`. | "The download is hidden until a human approves." |
| 2:45-2:58 | Download | Click download and show the diff filename. | "The exported file contains the approved patch changes only." |

## Recording tips

- Record at 1920x1080 or the browser's native 16:9 viewport.
- Use 100% browser zoom and enlarge the Streamlit window enough to show metric cards.
- Hide notifications, terminal windows, personal tabs, and API tokens.
- Keep `cache/last_run.json` present and do not rely on network access.
- Retake plan: use the same replay cache, restart Streamlit, and begin from the start screen.
