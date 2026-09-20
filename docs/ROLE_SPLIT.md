# Demo Role Split

## Who speaks and drives

| Person | Demo role | Judge questions |
|---|---|---|
| Mahavir | Drives the terminal, runs `python run_demo.py`, explains scanner, sandbox verifier, retry, and proof text. | Verification trust, retry behavior, scanner scope, safety, limitations. |
| Maitri | Drives Streamlit, shows the stepper, metrics, cards, diffs, approval controls, and download gate. | UI workflow, replay mode, human approval, accessibility, product experience. |
| Vrushti | Opens the pitch, explains ShopEasy and the problem, narrates the results, and closes with scope/roadmap. | Business value, team roles, differentiation, roadmap, Python-only scope. |

## Rehearsal plan

1. Run one live demo together and confirm the retry message and computed `78 -> 1` result.
2. Run one replay demo with network disabled and practice the approval-gated download.
3. Run one timed demo with interruptions from the judge questions; switch to the tracked cache if live timing slips.
