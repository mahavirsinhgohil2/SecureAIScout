# SecureAI Scout

SecureAI Scout is a small, offline-first security review agent for the bundled, intentionally vulnerable ShopEasy Flask demo.

## Workflow

`INVESTIGATE -> TRIAGE -> FIX -> VERIFY -> REVIEW`

The scanner finds controlled patterns, triage dismisses the allowlisted table lookup, fixes are tested in a temporary sandbox, failed patches can retry, and a person approves any export.

## Quick start

```powershell
python -m pip install -r requirements.txt
python run_demo.py
python -m streamlit run app/ui/main.py
python -m unittest discover -s tests
```

The demo writes `cache/last_run.json`. The Streamlit app can replay that file without network access.

The real run reports risk `78 -> 1`, not zero. The residual score is an intentional floor because a scan of a single demo app never proves zero risk.

## Safety scope

Only the bundled `demo_app/` is scanned. The verifier copies it to a temporary directory and never edits the original demo in place. A language model explains findings and proposes a corrected patch when the verifier rejects one; deterministic rules decide what is real, a sandbox verifier decides what is verified, and a human approves.

## Team roles

- Mahavir: scanner, agent, verifier
- Maitri: Streamlit UI and visual system
- Vrushti: demo app, tests, documentation, and pitch

## What Scout does not do

Scout does not scan production systems, upload applications, claim to find every vulnerability, perform autonomous production remediation, or treat an AI response as proof that a fix works.