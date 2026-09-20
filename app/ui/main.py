import difflib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from app.agent.agent import SecurityAgent
from app.models import AgentEvent, Finding

CACHE_PATH = ROOT / "cache" / "last_run.json"
DEMO_PATH = ROOT / "demo_app"
STAGES = ["Investigate", "Triage", "Fix", "Verify", "Review"]


def load_css():
    css_path = ROOT / "app" / "ui" / "styles.css"
    st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def finding_from_dict(data):
    allowed = set(Finding.__dataclass_fields__)
    return Finding(**{key: value for key, value in data.items() if key in allowed})


def load_replay():
    if not CACHE_PATH.exists():
        return None
    try:
        payload = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        findings = [finding_from_dict(item) for item in payload["findings"]]
        events = [AgentEvent(**item) for item in payload["events"]]
        return findings, events, payload["risk_before"], payload["risk_after"]
    except (OSError, KeyError, TypeError, ValueError):
        return None


def load_run():
    """Compatibility helper for tests and local callers; prefer the committed replay."""
    replay = load_replay()
    if replay is not None:
        findings, events, _, _ = replay
        return findings, events, True
    findings, events, _, _ = run_live_scan()
    return findings, events, False


def run_live_scan():
    agent = SecurityAgent(str(DEMO_PATH))
    events = list(agent.run())
    return agent.findings, events, agent.risk_before, agent.risk_after


def initialise_state():
    defaults = {
        "screen": "start",
        "findings": [],
        "events": [],
        "risk_before": 0,
        "risk_after": 0,
        "approved": set(),
        "rejected": set(),
        "streamed": False,
        "source": "",
        "error": "",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def start_run(source):
    try:
        result = load_replay() if source == "replay" else run_live_scan()
        if result is None:
            st.session_state.error = "The saved example run is unavailable. Run `python run_demo.py` once, then refresh this page."
            return
        st.session_state.findings, st.session_state.events, st.session_state.risk_before, st.session_state.risk_after = result
        st.session_state.screen = "review"
        st.session_state.source = source
        st.session_state.streamed = source == "replay"
        st.session_state.error = ""
    except Exception:
        st.session_state.error = "I couldn't complete that scan safely. You can use the verified example run instead."


def render_stepper(active_stage):
    active_index = STAGES.index(active_stage) if active_stage in STAGES else 0
    steps = []
    for index, stage in enumerate(STAGES):
        state = "done" if index < active_index else "active" if index == active_index else ""
        steps.append(f'<div class="step {state}" data-number="{index + 1}">{stage}</div>')
    st.markdown(f'<div class="stepper">{"".join(steps)}</div>', unsafe_allow_html=True)


def render_header():
    st.markdown('<div class="eyebrow">SecureAI Scout</div>', unsafe_allow_html=True)
    st.title("A calmer way to review security findings")
    st.markdown('<p class="subtitle">Find risky patterns, understand what they mean, verify proposed changes, and keep the final decision in your hands.</p>', unsafe_allow_html=True)


def render_landing():
    render_stepper("Investigate")
    st.markdown('<div class="card"><h3>See a verified example first</h3><p class="subtitle">Explore a saved local run instantly, then try a fresh scan when you are ready.</p></div>', unsafe_allow_html=True)
    columns = st.columns(4)
    for column, title, text in zip(columns, ["Find", "Fix", "Verify", "You approve"], ["Spot clear risk patterns.", "Prepare a focused change.", "Check it in a sandbox.", "Choose what to export."]):
        with column:
            st.markdown(f'<div class="mini-step"><strong>{title}</strong><span>{text}</span></div>', unsafe_allow_html=True)
    with st.expander("About this demo"):
        st.write("This scans only one bundled, intentionally vulnerable Flask app named ShopEasy. It does not scan or modify your files in place.")
    replay = load_replay()
    if replay and st.button("See a verified example run", type="primary", use_container_width=True):
        start_run("replay")
        st.rerun()
    elif not replay:
        st.warning("The saved example run is missing. Run `python run_demo.py` to create it.")
    if st.button("Run a live scan", use_container_width=True):
        with st.spinner("Reviewing the bundled ShopEasy demo..."):
            start_run("live")
        st.rerun()


def render_metrics():
    real = [finding for finding in st.session_state.findings if finding.is_real]
    verified = sum(bool(finding.verification_proof) for finding in real)
    false_alarms = sum(finding.is_real is False for finding in st.session_state.findings)
    fixes = sum(event.stage == "fix" and event.event_type == "tool_result" for event in st.session_state.events)
    metrics = [("Found", len(st.session_state.findings), "raw results"), ("False alarms", false_alarms, "removed by context"), ("Fixes proposed", fixes, "targeted suggestions"), ("Verified", verified, "sandbox checks passed")]
    columns = st.columns(4)
    for column, (label, value, note) in zip(columns, metrics):
        with column:
            st.markdown(f'<div class="card"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>', unsafe_allow_html=True)


def render_summary():
    real = [finding for finding in st.session_state.findings if finding.is_real]
    verified = sum(bool(finding.verification_proof) for finding in real)
    false_alarms = sum(finding.is_real is False for finding in st.session_state.findings)
    st.markdown(f'<div class="summary-card"><div class="summary-kicker">Review summary</div><h2>{verified} of {len(real)} real issues verified</h2><p>{false_alarms} false alarm removed · Risk {st.session_state.risk_before} → {st.session_state.risk_after}</p><span>Only verifier checks create Verified. The model suggests; you approve.</span></div>', unsafe_allow_html=True)
    st.metric("Risk before → after", f"{st.session_state.risk_before} → {st.session_state.risk_after}")


def render_events():
    with st.expander("See the agent trace", expanded=False):
        for event in st.session_state.events:
            st.markdown(f'<div class="event"><div class="event-stage">{event.stage}</div><div>{event.message}</div></div>', unsafe_allow_html=True)


def render_command_timeline(finding):
    if finding.issue_type != "command_injection":
        return
    st.markdown("**Self-correction timeline**")
    for event in st.session_state.events:
        if event.details and event.details.get("finding_id") == finding.id and event.stage in {"fix", "verify"}:
            st.markdown(f'<div class="timeline-item">{event.message}</div>', unsafe_allow_html=True)


def render_finding(finding):
    status = "verified" if finding.verification_proof else "rejected" if finding.id in st.session_state.rejected else ""
    chip_class = f"chip-{finding.severity}" if finding.severity in {"critical", "high", "medium"} else "chip-medium"
    source = next((event.details.get("source") for event in st.session_state.events if event.details and event.details.get("finding_id") == finding.id and event.event_type == "result" and event.details.get("source")), "fallback")
    explanation = "language model" if source == "llm" else "built-in rules"
    st.markdown('<div class="card finding-card">', unsafe_allow_html=True)
    badge = '<span class="verified">✓ Verified</span>' if finding.verification_proof else '<span class="pending">Needs review</span>'
    attempt = f"Fixed on attempt {finding.attempts} using the built-in correction" if finding.attempts == 3 else f"Attempts: {finding.attempts}"
    st.markdown(f'<span class="chip {chip_class}">{finding.severity}</span> {badge}<div class="finding-title">{finding.plain_english_title}</div><h4>What could go wrong</h4><div class="finding-impact">{finding.attacker_impact}</div><h4>Why Scout kept it</h4><div class="finding-impact">{finding.triage_reasoning or "Review is ready."}</div><div class="metric-note">Explanation: {explanation} · {attempt}</div>', unsafe_allow_html=True)
    st.caption(f"{Path(finding.file_path).name} · line {finding.line_number}")
    render_command_timeline(finding)
    with st.expander("View before and after"):
        before, after = st.columns(2)
        with before:
            st.markdown("**Before**")
            st.code(finding.original_content or finding.raw_code, language="python")
        with after:
            st.markdown("**After**")
            st.code(finding.fixed_content or "No patch stored", language="python")
    if finding.verification_proof:
        with st.expander("View verifier proof"):
            st.write(finding.verification_proof)
    left, right = st.columns(2)
    with left:
        if st.button("Approve verified fix", key=f"approve_{finding.id}", disabled=not finding.verification_proof or finding.id in st.session_state.approved, use_container_width=True):
            st.session_state.approved.add(finding.id)
            st.session_state.rejected.discard(finding.id)
            st.rerun()
    with right:
        if st.button("Reject fix", key=f"reject_{finding.id}", disabled=finding.id in st.session_state.rejected, use_container_width=True):
            st.session_state.rejected.add(finding.id)
            st.session_state.approved.discard(finding.id)
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)


def render_review_actions():
    verified = [finding for finding in st.session_state.findings if finding.verification_proof]
    if st.button("Approve all verified", disabled=not verified, use_container_width=True):
        st.session_state.approved.update(finding.id for finding in verified)
        st.rerun()
    approved = [finding for finding in verified if finding.id in st.session_state.approved and finding.id not in st.session_state.rejected]
    st.caption("Nothing changes in your files until you apply the patch yourself.")
    if approved:
        agent = SecurityAgent(str(DEMO_PATH))
        agent.findings = st.session_state.findings
        for finding in approved:
            finding.approved = True
        _, diff = agent.build_export_patch()
        st.download_button("Download approved patch", data=diff, file_name="approved_shopeasy_patch.diff", mime="text/plain", use_container_width=True)


def render_review():
    render_stepper("Review")
    if st.session_state.source == "live":
        st.info("Live scan complete. The committed example cache was not changed.")
    else:
        st.info("Showing the saved verified example run.")
    render_summary()
    render_metrics()
    render_events()
    st.subheader("Review each finding")
    real_findings = [finding for finding in st.session_state.findings if finding.is_real]
    if not real_findings:
        st.success("No real findings need your attention.")
    for finding in real_findings:
        render_finding(finding)
    render_review_actions()
    if st.button("Start over", use_container_width=True):
        for key in ["findings", "events", "approved", "rejected"]:
            st.session_state.pop(key, None)
        st.session_state.screen = "start"
        st.rerun()


def main():
    st.set_page_config(page_title="SecureAI Scout", page_icon="🛡️", layout="wide")
    load_css()
    initialise_state()
    render_header()
    if st.session_state.error:
        st.error(st.session_state.error)
        if st.button("Use example run instead", use_container_width=True):
            start_run("replay")
            st.rerun()
    if st.session_state.screen == "start":
        render_landing()
    else:
        render_review()
    st.markdown('<div class="footer">Built by Mahavir, Maitri, Vrushti · Python demo only · The model suggests, the verifier decides, you approve.</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
