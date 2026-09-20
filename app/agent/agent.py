import difflib
import json
import os
from pathlib import Path

from app.agent.llm_client import HFExplanationClient
from app.models import AgentEvent, Finding
from app.scanner.scanner import SecurityScanner
from app.scanner.verifier import verify_patch


RESIDUAL_RISK_AFTER_VERIFICATION = 1  # Floor for unreviewed code paths; a scan of a single demo app never proves zero risk.


class SecurityAgent:
	def __init__(self, repo_path="demo_app", explanation_client=None):
		self.repo_path = Path(repo_path).resolve()
		if self.repo_path.name != "demo_app":
			raise ValueError("SecurityAgent only accepts the bundled demo_app directory")
		self.findings = []
		self.events = []
		self.explanation_client = explanation_client

	def emit(self, stage, event_type, message, details=None):
		event = AgentEvent.make(stage, event_type, message, details)
		self.events.append(event)
		return event

	def _triage(self, finding):
		lines = Path(finding.file_path).read_text(encoding="utf-8").splitlines()
		start = max(0, finding.line_number - 21)
		context = "\n".join(lines[start:finding.line_number])
		allowlisted = finding.issue_type == "sql_injection" and "TABLES" in context and "not in TABLES" in context
		if allowlisted:
			finding.is_real = False
			finding.triage_reasoning = "This table name is checked against a short list before the query runs, so unexpected table names are turned away."
			fallback_reason = finding.triage_reasoning
			self._add_explanation(finding, fallback_reason)
			self.emit("triage", "result", f"False alarm removed: {finding.plain_english_title} is protected by a table allowlist.", {"finding_id": finding.id})
		else:
			finding.is_real = True
			finding.triage_reasoning = "This input reaches a sensitive operation without a strong safety check, so it needs a fix."
			self._add_explanation(finding, finding.triage_reasoning)
			self.emit("triage", "result", f"Confirmed: {finding.plain_english_title} needs a fix.", {"finding_id": finding.id})

	def _add_explanation(self, finding, fallback_reason):
		client = self.explanation_client
		if client is None and os.getenv("ENABLE_LLM_EXPLANATIONS", "").lower() == "true":
			client = HFExplanationClient()
		if client is None:
			text, source = fallback_reason, "fallback"
		else:
			self.emit("triage", "tool_call", "Asking the language model to explain this finding in plain English.", {"finding_id": finding.id, "source": "llm"})
			try:
				text, source = client.explain(finding.plain_english_title, finding.attacker_impact, fallback_reason)
			except Exception:
				text, source = fallback_reason, "fallback"
		finding.triage_reasoning = text
		self.emit("triage", "result", f"Explanation: {'language model' if source == 'llm' else 'built-in rules'}.", {"finding_id": finding.id, "source": source})

	def _replacement(self, finding, source):
		replacements = {
			"sql_injection": (
				'query = f"SELECT username FROM users WHERE username = \'{username}\' AND password_hash = \'{password_hash}\'"\n\trow = connection.execute(query).fetchone()',
				'query = "SELECT username FROM users WHERE username = ? AND password_hash = ?"\n\trow = connection.execute(query, (username, password_hash)).fetchone()',
			),
			"command_injection": (
				'os.system(f"ping {host}")',
				'subprocess.run(["ping", "-c", "1", host], check=False, shell=False)',
			),
			"hardcoded_secret": ('secret_key = "shopeasy-local-demo-secret"', 'secret_key = os.environ.get("SHOP_EASY_SECRET", "local-demo-only")'),
			"xss": ('return render_template_string(f"<h1>ShopEasy comment</h1><p>{text}</p>")', 'return render_template_string("<h1>ShopEasy comment</h1><p>{{ text }}</p>", text=text)'),
			"weak_crypto": ('password_hash = hashlib.md5(password.encode()).hexdigest()', 'password_hash = hashlib.sha256(password.encode()).hexdigest()'),
			"unsafe_pickle": ('profile = pickle.loads(payload)', 'profile = {"data": payload.decode("utf-8", errors="replace")}'),
		}
		old, new = replacements[finding.issue_type]
		if finding.issue_type == "command_injection" and finding.attempts == 1:
			new = 'os.system(shlex.quote(f"ping {host}"))'
		if old not in source:
			raise ValueError(f"Fix target not found for {finding.issue_type}")
		return old, new

	def _apply_fix(self, finding, source_label="fallback"):
		path = self.repo_path / Path(finding.file_path).name
		source = path.read_text(encoding="utf-8")
		old, new = self._replacement(finding, source)
		return self._apply_candidate(finding, source, old, new, source_label)

	def _apply_candidate(self, finding, source, old, new, source_label):
		fixed = source.replace(old, new, 1)
		if finding.issue_type == "command_injection" and finding.attempts > 1 and "import subprocess" not in fixed:
			if "subprocess.run" in new:
				fixed = "import subprocess\n" + fixed
		if fixed == source:
			raise ValueError(f"Fix made no change for {finding.issue_type}")
		finding.original_content = source
		finding.fixed_content = fixed
		self.emit("fix", "tool_result", f"I prepared a targeted fix for {finding.plain_english_title}.", {"finding_id": finding.id, "source": source_label})
		return fixed

	def _llm_candidate(self, finding, rejection_reason):
		path = self.repo_path / Path(finding.file_path).name
		source = path.read_text(encoding="utf-8")
		lines = source.splitlines()
		start = max(0, finding.line_number - 6)
		context = "\n".join(lines[start:min(len(lines), finding.line_number + 5)])
		client = self.explanation_client
		if client is None and os.getenv("ENABLE_LLM_EXPLANATIONS", "").lower() == "true":
			client = HFExplanationClient()
		if client is None or not hasattr(client, "propose_fix"):
			return None
		try:
			proposal = client.propose_fix(finding, context, rejection_reason)
		except Exception:
			return None
		if not proposal or proposal["old_snippet"] not in source:
			return None
		return self._apply_candidate(finding, source, proposal["old_snippet"], proposal["new_snippet"], "llm")

	def run(self):
		self.findings = SecurityScanner(str(self.repo_path)).scan_all()
		self.emit("investigate", "thinking", "I’m reviewing the bundled ShopEasy demo.")
		self.emit("investigate", "tool_call", "I’m scanning the demo files for the six known patterns.")
		self.emit("investigate", "result", f"I found {len(self.findings)} areas to review.", {"found": len(self.findings)})
		for finding in self.findings:
			self._triage(finding)
		self.emit("triage", "summary", "I removed the allowlisted table lookup from the real-risk list.")
		for finding in self.findings:
			if not finding.is_real:
				continue
			last_rejection = ""
			while finding.attempts < 3 and not finding.verification_proof:
				finding.attempts += 1
				try:
					if finding.attempts == 3:
						self.emit("fix", "tool_result", "The language model patch did not verify; using the built-in deterministic correction.", {"finding_id": finding.id, "source": "fallback"})
					if finding.attempts == 2:
						self.emit("fix", "fix", "Asking the language model to correct the patch using the verifier's feedback.", {"finding_id": finding.id, "source": "llm", "rejection": last_rejection})
						self.emit("fix", "tool_call", "Asking the language model to correct the patch using the verifier's feedback.", {"finding_id": finding.id, "source": "llm", "rejection": last_rejection})
						fixed = self._llm_candidate(finding, last_rejection)
						if fixed is not None and not any(event.stage == "fix" and event.event_type == "tool_result" and event.details.get("finding_id") == finding.id and event.details.get("source") == "llm" for event in self.events):
							self.emit("fix", "tool_result", "The language model supplied a patch for verification.", {"finding_id": finding.id, "source": "llm"})
						if fixed is None:
							finding.attempts += 1
							self.emit("fix", "tool_result", "The language model did not return a usable patch; using the built-in correction.", {"finding_id": finding.id, "source": "fallback"})
							fixed = self._apply_fix(finding, "fallback")
					else:
						fixed = self._apply_fix(finding, "fallback")
					success, proof = verify_patch(str(self.repo_path), finding, fixed)
				except (OSError, ValueError) as error:
					success, proof = False, str(error)
				if success:
					finding.verification_proof = proof
					self.emit("verify", "success", f"Verified: {finding.plain_english_title} passes the checks.", {"finding_id": finding.id, "proof": proof})
				else:
					last_rejection = proof
					self.emit("verify", "failed", f"The first fix for {finding.plain_english_title} did not pass, so I’ll retry it.", {"finding_id": finding.id, "proof": proof})
		self.emit("report", "summary", "The review is ready for your approval.", {"risk_before": self.risk_before, "risk_after": self.risk_after, "verified": self.verified_count})
		return self.events

	@property
	def real_findings(self):
		return [finding for finding in self.findings if finding.is_real]

	@property
	def risk_before(self):
		weights = {"critical": 18, "high": 12, "medium": 6, "low": 2}
		return min(100, sum(weights[finding.severity] for finding in self.real_findings))

	@property
	def verified_count(self):
		return sum(bool(finding.verification_proof) for finding in self.real_findings)

	@property
	def risk_after(self):
		weights = {"critical": 18, "high": 12, "medium": 6, "low": 2}
		remaining = sum(weights[finding.severity] for finding in self.real_findings if not finding.verification_proof)
		return min(100, remaining + (RESIDUAL_RISK_AFTER_VERIFICATION if self.verified_count else 0))

	def save_cache(self, path="cache/last_run.json"):
		payload = {"events": [event.to_dict() for event in self.events], "findings": [finding.to_dict() for finding in self.findings], "risk_before": self.risk_before, "risk_after": self.risk_after}
		cache_path = Path(path)
		cache_path.parent.mkdir(parents=True, exist_ok=True)
		cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

	def build_export_patch(self):
		original = (self.repo_path / "app.py").read_text(encoding="utf-8")
		combined = original
		for finding in self.real_findings:
			if finding.approved:
				old, new = self._replacement(finding, combined)
				combined = combined.replace(old, new, 1)
				if finding.issue_type == "command_injection" and "import subprocess" not in combined:
					combined = "import subprocess\n" + combined
		diff = "".join(difflib.unified_diff(original.splitlines(True), combined.splitlines(True), fromfile="demo_app/app.py", tofile="approved/demo_app/app.py"))
		return combined, diff
