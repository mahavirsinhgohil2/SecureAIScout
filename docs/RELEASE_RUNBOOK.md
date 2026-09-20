# SecureAI Scout Release Runbook

Reference cache metrics: 7 raw findings, 6 real findings, 1 false alarm removed, 6 verified, 3 command-injection attempts, 36 events, risk 78 -> 1.

## Morning checklist

- Pull the latest committed branch.
- Run `python run_demo.py` and confirm the retry message and `Risk: 78 -> 1`.
- Open a replay browser tab with the tracked `cache/last_run.json`.
- Open a live browser tab for `python -m streamlit run app/ui/main.py`.
- Keep the backup video tab ready.
- Charge the laptop.
- Turn off desktop and browser notifications.
- Set browser zoom and window size for readable metric cards.
- Copy the repository and backup video to USB and phone storage.

## Demo commands

### Install

```powershell
python -m pip install -r requirements.txt
```

### Live run

```powershell
python run_demo.py
python -m streamlit run app/ui/main.py
```

### Replay run

```powershell
python -m streamlit run app/ui/main.py
```

Use the generated or tracked `cache/last_run.json`; replay reads it locally and does not require an API or network.

### Tests

```powershell
python -m unittest demo_app/test_app.py
python -m unittest discover -s tests
```

## Failure plan

- If the live scan fails, switch to replay in under 10 seconds.
- If replay fails, play the backup video.
- If the projector fails, present from the phone or play the backup video.
- Never show `.env`, tokens, or a terminal containing secrets.

## Fifteen-minute rehearsal

- **Minutes 0-3:** Vrushti opens the pitch and explains the ShopEasy scope.
- **Minutes 3-7:** Mahavir runs the scan and narrates triage, verifier rejection, retry, and proof.
- **Minutes 7-11:** Maitri drives the UI review, approval, and export gate.
- **Minutes 11-13:** Run the replay fallback with networking disabled if practical.
- **Minutes 13-15:** Ask interruptions from the judge Q&A and confirm the video/USB backup.
