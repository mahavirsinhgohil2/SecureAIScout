import os
import json
import re
from typing import Optional

from dotenv import load_dotenv

try:
    from huggingface_hub import InferenceClient
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    InferenceClient = None


class HFExplanationClient:
    """Optional explanation-only client; it never decides triage or verification."""

    model = "Qwen/Qwen2.5-Coder-7B-Instruct"

    def __init__(self, token: Optional[str] = None, timeout: int = 8):
        load_dotenv()
        self.token = token or os.getenv("HF_TOKEN")
        self.timeout = timeout

    def _call(self, messages, max_tokens):
        if not self.token or InferenceClient is None:
            return None
        for attempt in range(2):
            try:
                client = InferenceClient(model=self.model, token=self.token, timeout=self.timeout)
                return client.chat_completion(messages=messages, max_tokens=max_tokens).choices[0].message.content.strip()
            except Exception:
                if attempt == 1:
                    return None
        return None

    def explain_finding(self, finding):
        prompt = (
            "Explain this security finding in 2 or 3 plain-English sentences for a non-security user. "
            "Do not decide whether it is real, propose code, or claim verification.\n\n"
            f"Title: {finding.plain_english_title}\nImpact: {finding.attacker_impact}\nCode: {finding.raw_code}"
        )
        return self._call(
            [{"role": "system", "content": "You explain code findings for a developer."}, {"role": "user", "content": prompt}],
            160,
        )

    def propose_fix(self, finding, file_context, rejection_reason):
        prompt = (
            "Return only a JSON object with exactly old_snippet and new_snippet. "
            "The snippets must be standard-library Python, at most 30 lines each. "
            "The old snippet must be copied exactly from the source context. "
            "Do not use shell=True or os.system. Do not explain the answer.\n\n"
            f"Flagged code:\n{finding.raw_code}\n\nSurrounding source lines:\n{file_context}\n\n"
            f"Verifier rejection:\n{rejection_reason}"
        )
        response = self._call(
            [{"role": "system", "content": "You suggest a narrowly targeted Python patch."}, {"role": "user", "content": prompt}],
            300,
        )
        if not response:
            return None
        try:
            match = re.search(r"\{.*\}", response, re.DOTALL)
            data = json.loads(match.group(0) if match else response)
            old = data.get("old_snippet")
            new = data.get("new_snippet")
            if not isinstance(old, str) or not isinstance(new, str):
                return None
            if len(old.splitlines()) > 30 or len(new.splitlines()) > 30 or old not in file_context:
                return None
            if "shell=True" in new or "os.system" in new:
                return None
            return {"old_snippet": old, "new_snippet": new}
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None

    def explain(self, title: str, impact: str, deterministic_reason: str):
        class FindingView:
            plain_english_title = title
            attacker_impact = impact
            raw_code = ""

        result = self.explain_finding(FindingView())
        return (result or deterministic_reason), "llm" if result else "fallback"
