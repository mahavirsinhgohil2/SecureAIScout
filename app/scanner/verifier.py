import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from app.models import Finding
from app.scanner.scanner import SecurityScanner


def _remove_readonly(func, path, _exc_info):
	os.chmod(path, stat.S_IWRITE)
	func(path)


def _target_path(repo_path, finding):
	root = Path(repo_path).resolve()
	target = (root / Path(finding.file_path).name).resolve()
	if target.parent != root:
		raise ValueError("Verifier only supports files directly inside demo_app")
	return target


def verify_patch(repo_path: str, finding: Finding, fixed_content: str):
	source_root = Path(repo_path).resolve()
	if source_root.name != "demo_app":
		raise ValueError("Verifier only accepts the bundled demo_app directory")
	sandbox_parent = Path(tempfile.mkdtemp(prefix="secureai-sandbox-"))
	sandbox_root = sandbox_parent / "demo_app"
	try:
		shutil.copytree(source_root, sandbox_root)
		target = _target_path(sandbox_root, finding)
		target.write_text(fixed_content, encoding="utf-8")
		checks = []
		try:
			compile_result = subprocess.run(
				["python", "-m", "py_compile", str(target)],
				capture_output=True,
				text=True,
				timeout=10,
				check=False,
			)
		except (OSError, subprocess.SubprocessError) as error:
			return False, f"Syntax check failed to run: {error}"
		if compile_result.returncode != 0:
			return False, f"Syntax check failed: {compile_result.stderr.strip()}"
		checks.append("syntax check passed")

		if finding.issue_type == "command_injection":
			text = target.read_text(encoding="utf-8")
			if "os.system(" in text or "shell=True" in text:
				return False, "syntax check passed; command safety check failed because unsafe command execution remains"
			if "subprocess.run([" not in text or "shell=False" not in text:
				return False, "syntax check passed; command safety check failed because a safe subprocess list call was not found"
			checks.append("command safety check passed")

		remaining = SecurityScanner(str(sandbox_root)).scan_all()
		if any(
			item.issue_type == finding.issue_type
			and Path(item.file_path).name == Path(finding.file_path).name
			and item.line_number == finding.line_number
			for item in remaining
		):
			return False, f"{', '.join(checks)}; rescan failed because {finding.issue_type} remains"
		checks.append("sandbox rescan passed")

		try:
			test_result = subprocess.run(
				["python", "-m", "unittest", "demo_app/test_app.py"],
				cwd=sandbox_parent,
				capture_output=True,
				text=True,
				timeout=15,
				check=False,
			)
			if test_result.returncode == 0:
				checks.append("demo tests passed")
		except (OSError, subprocess.SubprocessError) as error:
			checks.append(f"demo tests unavailable: {error}")
		return True, "; ".join(checks)
	finally:
		if sandbox_parent.exists():
			shutil.rmtree(sandbox_parent, onerror=_remove_readonly)
