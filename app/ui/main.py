import json
import sys
import time
from pathlib import Path

import streamlit as st

from app.models import AgentEvent, Finding
from app.agent.agent import SecurityAgent


ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = ROOT / "cache" / "last_run.json"
DEMO_PATH = ROOT / "demo_app"
STAGES = ["Investigate", "Triage", "Fix", "Verify", "Review"]


def load_css():
	css_path = Path(__file__).with_name("styles.css")
	st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def finding_from_dict(data):
	allowed = {field for field in Finding.__dataclass_fields__}
	return Finding(**{key: value for key, value in data.items() if key in allowed})


def load_run():
	if CACHE_PATH.exists():
		try:
			payload = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
			findings = [finding_from_dict(item) for item in payload.get("findings", [])]
			events = [AgentEvent(**item) for item in payload.get("events", [])]
			return findings, events, True
		except (OSError, TypeError, ValueError):
			pass

	agent = SecurityAgent(str(DEMO_PATH))
	events = list(agent.run())
	return agent.findings, events, False


def initialise_state():
	if "screen" not in st.session_state:
		st.session_state.screen = "start"
	if "findings" not in st.session_state:
		st.session_state.findings = []
	if "events" not in st.session_state:
		st.session_state.events = []
	if "approved" not in st.session_state:
		st.session_state.approved = set()
	if "rejected" not in st.session_state:
		st.session_state.rejected = set()
	if "streamed" not in st.session_state:
		st.session_state.streamed = False


def render_header():
	st.markdown('<div class="eyebrow">SecureAI Scout</div>', unsafe_allow_html=True)
	st.title("A calmer way to review security findings")
	st.markdown(
		'<p class="subtitle">I’ll inspect the local ShopEasy demo, explain what I found in plain English, and leave every change in your hands.</p>',
		unsafe_allow_html=True,
	)


def render_stepper(active_stage):
	active_index = STAGES.index(active_stage) if active_stage in STAGES else 0
	steps = []
	for index, stage in enumerate(STAGES):
		state = "done" if index < active_index else "active" if index == active_index else ""
		steps.append(f'<div class="step {state}" data-number="{index + 1}">{stage}</div>')
	st.markdown(f'<div class="stepper">{"".join(steps)}</div>', unsafe_allow_html=True)


def render_metrics():
	findings = st.session_state.findings
	false_alarms = len(st.session_state.rejected)
	fixes = len(findings)
	verified = sum(bool(finding.verification_proof) for finding in findings)
	fixes = sum(1 for event in st.session_state.events if event.stage == "fix" and event.event_type == "tool_result")
	metrics = [("Found", len(findings), "areas to review"), ("False alarms", false_alarms, "set aside"), ("Fixes proposed", fixes, "ready for review"), ("Verified", verified, "checks passed")]
	columns = st.columns(4)
	for column, (label, value, note) in zip(columns, metrics):
		with column:
			st.markdown(f'<div class="card"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>', unsafe_allow_html=True)


def render_events():
	st.subheader("What I’m doing")
	for event in st.session_state.events:
		st.markdown(f'<div class="event"><div class="event-stage">{event.stage}</div><div>{event.message}</div></div>', unsafe_allow_html=True)


def render_finding(finding):
	status = "verified" if finding.verification_proof else "rejected" if finding.id in st.session_state.rejected else ""
	chip_class = f"chip-{finding.severity}" if finding.severity in {"critical", "high", "medium"} else "chip-medium"
	status_html = '<span class="verified">✓ Verified</span>' if status == "verified" else "<span>Set aside</span>" if status == "rejected" else ""
	explanation_source = next((event.details.get("source") for event in st.session_state.events if event.details and event.details.get("finding_id") == finding.id and event.event_type == "result" and event.details.get("source")), "fallback")
	explanation_label = "language model" if explanation_source == "llm" else "built-in rules"
	st.markdown('<div class="card">', unsafe_allow_html=True)
	attempt_note = f"Fixed on {finding.attempts}nd attempt" if finding.attempts == 2 else f"Attempts: {finding.attempts}"
	st.markdown(f'<span class="chip {chip_class}">{finding.severity}</span> {status_html}<div class="finding-title">{finding.plain_english_title}</div><div class="finding-impact">{finding.attacker_impact}</div><div class="finding-impact">{finding.triage_reasoning or "Review is ready."} · {attempt_note}</div><div class="metric-note">Explanation: {explanation_label}</div><div class="code-block">{finding.raw_code}</div>', unsafe_allow_html=True)
	st.caption(f"{finding.file_path} · line {finding.line_number}")
	if finding.fixed_content and finding.original_content:
		with st.expander("View proposed change"):
			st.code("".join(__import__("difflib").unified_diff(finding.original_content.splitlines(True), finding.fixed_content.splitlines(True), fromfile="before", tofile="after")), language="diff")
	if finding.verification_proof:
		st.caption(f"Proof: {finding.verification_proof}")
	left, right = st.columns(2)
	with left:
		if st.button("Approve verified fix", key=f"approve_{finding.id}", disabled=not finding.verification_proof or finding.id in st.session_state.approved):
			st.session_state.approved.add(finding.id)
			st.session_state.rejected.discard(finding.id)
			st.rerun()
	with right:
		if st.button("Set aside", key=f"reject_{finding.id}", disabled=status == "rejected"):
			st.session_state.rejected.add(finding.id)
			st.session_state.approved.discard(finding.id)
			st.rerun()
	st.markdown('</div>', unsafe_allow_html=True)


def render_review_actions():
	verified = [finding for finding in st.session_state.findings if finding.verification_proof]
	if st.button("Approve all verified fixes", disabled=not verified):
		for finding in verified:
			finding.approved = True
			st.session_state.approved.add(finding.id)
		st.rerun()
	approved = [finding for finding in verified if finding.id in st.session_state.approved]
	if approved:
		agent = SecurityAgent(str(DEMO_PATH))
		agent.findings = st.session_state.findings
		for finding in approved:
			finding.approved = True
		combined, diff = agent.build_export_patch()
		st.download_button("Download approved patch", data=diff or combined, file_name="approved_shopeasy_patch.diff", mime="text/plain")


def main():
	st.set_page_config(page_title="SecureAI Scout", page_icon="🛡️", layout="wide")
	load_css()
	initialise_state()
	render_header()

	if st.session_state.screen == "start":
		render_stepper("Investigate")
		st.markdown('<div class="card"><h3>Ready for a friendly first pass?</h3><p class="subtitle">This scans only the bundled local demo. It will not upload, execute, or change your files.</p></div>', unsafe_allow_html=True)
		if st.button("Start demo scan", type="primary"):
			st.session_state.findings, st.session_state.events, replayed = load_run()
			st.session_state.screen = "review"
			st.session_state.replayed = replayed
			st.session_state.streamed = False
			st.rerun()
		return

	active_stage = "Review" if st.session_state.screen == "review" else "Investigate"
	render_stepper(active_stage)
	if getattr(st.session_state, "replayed", False):
		st.info("Showing the last saved run.")
	elif not st.session_state.streamed:
		with st.status("Reviewing the local demo", expanded=True) as status:
			for event in st.session_state.events:
				st.write(event.message)
				time.sleep(0.35)
			status.update(label="Review is ready", state="complete")
		st.session_state.streamed = True
	render_metrics()
	render_events()
	report_events = [event for event in st.session_state.events if event.stage == "report" and event.event_type == "summary"]
	if report_events:
		risk_before = report_events[-1].details.get("risk_before", 0)
		risk_after = report_events[-1].details.get("risk_after", 0)
		st.metric("Risk after review", f"{risk_before} → {risk_after}")
	st.subheader("Review each finding")
	if not st.session_state.findings:
		st.success("No findings were returned by the local scan.")
	for finding in st.session_state.findings:
		render_finding(finding)
	render_review_actions()


if __name__ == "__main__":
	sys.path.insert(0, str(ROOT))
	main()
