import copy
import tempfile
import unittest
from pathlib import Path

from app.models import Finding
from app.scanner.verifier import verify_patch


class VerifierTests(unittest.TestCase):
	def setUp(self):
		self.repo = Path("demo_app").resolve()
		self.original = (self.repo / "app.py").read_text(encoding="utf-8")
		self.finding = Finding("x", str(self.repo / "app.py"), 1, "critical", "command_injection", "os.system", "title", "impact")

	def tearDown(self):
		self.assertEqual((self.repo / "app.py").read_text(encoding="utf-8"), self.original)

	def test_sql_fix_passes(self):
		finding = copy.copy(self.finding)
		finding.issue_type = "sql_injection"
		finding.line_number = 36
		finding.file_path = str(self.repo / "app.py")
		finding.raw_code = 'query = f"SELECT username FROM users WHERE username = \'{username}\' AND password_hash = \'{password_hash}\'"'
		content = self.original.replace('query = f"SELECT username FROM users WHERE username = \'{username}\' AND password_hash = \'{password_hash}\'"', 'query = "SELECT username FROM users WHERE username = ? AND password_hash = ?"')
		content = content.replace('row = connection.execute(query).fetchone()', 'row = connection.execute(query, (username, password_hash)).fetchone()')
		success, proof = verify_patch("demo_app", finding, content)
		self.assertTrue(success, proof)

	def test_shlex_only_command_fix_fails(self):
		content = self.original.replace('os.system(f"ping {host}")', 'os.system(shlex.quote(f"ping {host}"))')
		success, _ = verify_patch("demo_app", self.finding, content)
		self.assertFalse(success)

	def test_subprocess_command_fix_passes(self):
		content = self.original.replace('os.system(f"ping {host}")', 'subprocess.run(["ping", "-c", "1", host], check=False, shell=False)')
		content = content.replace('import sqlite3', 'import sqlite3\nimport subprocess')
		success, proof = verify_patch("demo_app", self.finding, content)
		self.assertTrue(success, proof)

	def test_syntax_error_fails(self):
		success, _ = verify_patch("demo_app", self.finding, self.original + "\n(")
		self.assertFalse(success)

	def test_temp_sandbox_is_cleaned(self):
		before = set(Path(tempfile.gettempdir()).glob("secureai-sandbox-*"))
		verify_patch("demo_app", self.finding, self.original)
		after = set(Path(tempfile.gettempdir()).glob("secureai-sandbox-*"))
		self.assertEqual(after, before)


if __name__ == "__main__":
	unittest.main()