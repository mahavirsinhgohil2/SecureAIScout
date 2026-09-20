# Three-minute demo

1. Run `python run_demo.py` and point out the investigate and triage messages. The allowlisted table lookup is removed as a false alarm.
2. Point out the fix and verify messages. The command-injection fix fails once, retries, and passes deterministic checks on the second attempt.
3. Run `python -m streamlit run app/ui/main.py`, start the scan, review the computed risk drop, inspect proofs and diffs, approve a verified fix, and download the approved patch.
4. Refresh or rerun the UI in replay mode. It reads `cache/last_run.json` without an API or network call.