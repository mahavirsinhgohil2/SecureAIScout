import unittest
from pathlib import Path

from app.agent.agent import SecurityAgent
from app.models import Finding
from app.ui.main import STAGES, finding_from_dict


def sample_finding():
    return Finding(
        id="sql_injection_1",
        file_path="demo_app/app.py",
        line_number=1,
        severity="critical",
        issue_type="sql_injection",
        raw_code="cursor.execute(f\"SELECT ...\")",
        plain_english_title="Login can be bypassed",
        attacker_impact="An attacker may manipulate a database query.",
    )


class UiContractTests(unittest.TestCase):
    def test_has_five_requested_stages(self):
        self.assertEqual(STAGES, ["Investigate", "Triage", "Fix", "Verify", "Review"])

    def test_agent_events_include_each_workflow_stage(self):
        events = list(SecurityAgent("demo_app").run())
        self.assertEqual({event.stage for event in events}, {"investigate", "triage", "fix", "verify", "report"})

    def test_finding_round_trip_preserves_shared_model(self):
        self.assertEqual(finding_from_dict(sample_finding().to_dict()), sample_finding())

    def test_css_contains_required_design_tokens(self):
        css = Path("app/ui/styles.css").read_text(encoding="utf-8")
        for token in ("#F7F8FC", "#4F46E5", "#16A34A", "#1F2937", ".chip-critical", ".verified"):
            self.assertIn(token.lower(), css.lower())

    def test_agent_computes_verified_risk_drop(self):
        agent = SecurityAgent("demo_app")
        list(agent.run())
        self.assertEqual(agent.verified_count, 6)
        self.assertLess(agent.risk_after, agent.risk_before)


if __name__ == "__main__":
    unittest.main()