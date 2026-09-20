# Streamlit Community Cloud Deployment

## Deploy

1. Push the committed repository to GitHub.
2. Open Streamlit Community Cloud and choose **New app**.
3. Select the GitHub repository and branch `main`.
4. Set the main file path to `app/ui/main.py`.
5. In **Advanced settings -> Secrets**, add the optional explanation-only secret:

```toml
HF_TOKEN = "your-token-in-the-host-secrets-manager"
ENABLE_LLM_EXPLANATIONS = "true"
```

Never commit `.streamlit/secrets.toml` or a real token. The committed example is `.streamlit/secrets.toml.example`.

## Runtime

The tested local runtime is Python 3.14.7. Streamlit Community Cloud should use a compatible current Python 3.14 runtime; no `runtime.txt` is required by this project.

First boot should normally take about 1-3 minutes while dependencies install. Use the app menu's **Reboot app** action after changing secrets or requirements.

## Local commands

```powershell
python -m pip install -r requirements.txt
python run_demo.py
python -m streamlit run app/ui/main.py
```

The app opens on the committed replay. A live scan is optional and never overwrites `cache/last_run.json`.

## Fallback

If Community Cloud is unavailable, create a Hugging Face Space with the **Streamlit** SDK, upload the repository, use `app/ui/main.py` as the app entry point, and add `HF_TOKEN` through the Space secrets manager. The built-in rules remain available without a token.