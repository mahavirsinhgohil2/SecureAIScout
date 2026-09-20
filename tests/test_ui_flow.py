import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from app.agent.agent import SecurityAgent
from app.ui import main as ui


class UiFlowTests(unittest.TestCase):
    UI_PATH = str(Path(__file__).resolve().parents[1] / "app" / "ui" / "main.py")

    def test_replay_review_shows_six_verified_findings_and_risk(self):
        app_test = AppTest.from_file(self.UI_PATH).run()
        self.assertEqual([button.label for button in app_test.button], ["Start demo scan"])
        app_test.button[0].click().run()
        self.assertEqual(sum(bool(finding.verification_proof) for finding in app_test.session_state.findings), 6)
        self.assertIn("78 → 1", " ".join(metric.value for metric in app_test.metric))
        self.assertFalse([error for error in app_test.exception])

    def test_unverified_finding_has_no_verified_badge(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "last_run.json"
            payload = {
                "events": [],
                "findings": [{
                    "id": "finding_1",
                    "file_path": "demo_app/app.py",
                    "line_number": 1,
                    "severity": "high",
                    "issue_type": "test",
                    "raw_code": "example",
                    "plain_english_title": "Example finding",
                    "attacker_impact": "Example impact",
                    "is_real": True,
                    "verification_proof": None,
                }],
                "risk_before": 12,
                "risk_after": 12,
            }
            cache_path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(ui, "CACHE_PATH", cache_path):
                findings, _, replayed = ui.load_run()
            self.assertTrue(replayed)
            self.assertEqual(findings[0].verification_proof, None)
            self.assertFalse(bool(findings[0].verification_proof))

    def test_download_requires_approval_and_rejected_fix_is_excluded(self):
        agent = SecurityAgent("demo_app")
        list(agent.run())
        real_findings = agent.real_findings
        real_findings[0].approved = True
        real_findings[1].rejected = True
        combined, diff = agent.build_export_patch()
        self.assertIn("SHOP_EASY_SECRET", diff)
        self.assertNotIn("hashlib.sha256", diff)
        self.assertNotEqual(combined, (Path("demo_app") / "app.py").read_text(encoding="utf-8"))

    def test_start_screen_has_no_download_before_approval(self):
        app_test = AppTest.from_file(self.UI_PATH).run()
        self.assertEqual(len(app_test.download_button), 0)

    def test_current_ui_has_no_start_new_demo_control(self):
        app_test = AppTest.from_file(self.UI_PATH).run()
        self.assertNotIn("Start new demo", [button.label for button in app_test.button])


if __name__ == "__main__":
    unittest.main()
