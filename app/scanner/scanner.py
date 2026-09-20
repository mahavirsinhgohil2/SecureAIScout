import os
import re
import sys
from pathlib import Path

from app.models import Finding


class SecurityScanner:
	def __init__(self, repo_path: str):
		self.repo_path = str(Path(repo_path).resolve())
		project_root = Path(__file__).resolve().parents[2]
		allowed_root = (project_root / "demo_app").resolve()
		path = Path(self.repo_path)
		is_bundled_demo = path == allowed_root
		is_verifier_sandbox = path.name == "demo_app" and path.parent.name.startswith("secureai-sandbox-")
		if not (is_bundled_demo or is_verifier_sandbox):
			raise ValueError("SecurityScanner only accepts the bundled demo_app directory")
		self.findings: list[Finding] = []

	def add(self, file_path, line_number, severity, issue_type, raw_code, title, impact):
		finding_id = f"{issue_type}_{len(self.findings) + 1}"
		self.findings.append(
			Finding(
				id=finding_id,
				file_path=file_path,
				line_number=line_number,
				severity=severity,
				issue_type=issue_type,
				raw_code=raw_code.strip(),
				plain_english_title=title,
				attacker_impact=impact,
			)
		)

	def scan_all(self):
		self.findings = []
		for root, dirs, files in os.walk(self.repo_path):
			dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "venv"}]
			for filename in files:
				if filename.endswith(".py"):
					self.scan_file(os.path.join(root, filename))
		return self.findings

	def scan_file(self, file_path):
		with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
			lines = file.readlines()

		query_lines = {}
		for number, line in enumerate(lines, start=1):
			stripped = line.strip()

			if re.search(r"\bquery\s*=\s*f[\"']", stripped):
				query_lines["query"] = number

			if "execute(" in stripped and ("f\"" in stripped or "f'" in stripped):
				self.add(
					file_path, number, "critical", "sql_injection", stripped,
					"Login can be bypassed",
					"An attacker may manipulate a database query and access another account.",
				)
			elif re.search(r"\bexecute\(\s*query\s*\)", stripped) and "query" in query_lines:
				query_line = query_lines.pop("query")
				self.add(
					file_path, query_line, "critical", "sql_injection", lines[query_line - 1],
					"Login can be bypassed",
					"An attacker may manipulate a database query and access another account.",
				)

			if "os.system(" in stripped or ("subprocess" in stripped and "shell=True" in stripped):
				self.add(
					file_path, number, "critical", "command_injection", stripped,
					"Attacker can run commands on your server",
					"An attacker may execute operating-system commands through this input.",
				)

			if re.search(r"(secret_key|api_key|token)\s*=\s*['\"][^'\"]+['\"]", stripped, re.I):
				self.add(
					file_path, number, "high", "hardcoded_secret", stripped,
					"A secret is visible in source code",
					"Anyone who can view the repository may reuse this secret.",
				)

			if "render_template_string(f" in stripped:
				self.add(
					file_path, number, "high", "xss", stripped,
					"Attackers can inject scripts into a page",
					"A malicious comment could run in another user's browser.",
				)

			if "hashlib.md5(" in stripped:
				self.add(
					file_path, number, "medium", "weak_crypto", stripped,
					"Passwords are protected with weak hashing",
					"Leaked password hashes could be cracked quickly.",
				)

			if "pickle.loads(" in stripped:
				self.add(
					file_path, number, "high", "unsafe_pickle", stripped,
					"Uploaded data can take over the server",
					"A malicious serialized object may execute code on the server.",
				)

		return self.findings


if __name__ == "__main__":
	repo_path = sys.argv[1] if len(sys.argv) > 1 else "demo_app"
	findings = SecurityScanner(repo_path).scan_all()
	print(f"Findings: {len(findings)}")
	for finding in findings:
		print(f"- {finding.plain_english_title}")
