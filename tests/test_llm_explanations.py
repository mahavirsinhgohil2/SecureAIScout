import unittest

from app.agent.agent import SecurityAgent


class MockClient:
    def __init__(self, result=None, error=None, proposal=None):
        self.result = result
        self.error = error
        self.proposal = proposal

    def explain(self, title, impact, fallback):
        if self.error:
            raise self.error
        return self.result, "llm"

    def propose_fix(self, finding, file_context, rejection_reason):
        if self.error:
            raise self.error
        return self.proposal


class LlmExplanationTests(unittest.TestCase):
    def run_agent(self, client):
        agent = SecurityAgent("demo_app", explanation_client=client)
        list(agent.run())
        return agent

    def test_success_labels_language_model_and_preserves_decisions(self):
        agent = self.run_agent(MockClient("A clearer explanation."))
        self.assertTrue(any(event.details.get("source") == "llm" for event in agent.events if event.details))
        self.assertEqual(sum(finding.is_real is True for finding in agent.findings), 6)
        self.assertEqual(agent.verified_count, 6)

    def test_timeout_falls_back_without_changing_results(self):
        agent = self.run_agent(MockClient(error=TimeoutError("timed out")))
        self.assertTrue(any(event.details.get("source") == "fallback" for event in agent.events if event.details))
        self.assertEqual(sum(finding.is_real is True for finding in agent.findings), 6)
        self.assertEqual(agent.verified_count, 6)

    def test_exception_falls_back_without_changing_results(self):
        agent = self.run_agent(MockClient(error=RuntimeError("provider unavailable")))
        self.assertTrue(all(finding.triage_reasoning for finding in agent.findings))
        self.assertEqual(sum(finding.is_real is False for finding in agent.findings), 1)
        self.assertEqual(agent.risk_before, 78)
        self.assertEqual(agent.risk_after, 1)

    def test_valid_llm_patch_is_verified(self):
        proposal = {
            "old_snippet": 'os.system(f"ping {host}")',
            "new_snippet": 'subprocess.run(["ping", "-c", "1", host], check=False, shell=False)',
        }
        agent = self.run_agent(MockClient("A clearer explanation.", proposal=proposal))
        command = next(finding for finding in agent.findings if finding.issue_type == "command_injection")
        self.assertEqual(command.attempts, 2)
        self.assertTrue(command.verification_proof)
        self.assertTrue(any(event.details.get("source") == "llm" for event in agent.events if event.event_type == "fix" and event.details))

    def test_failed_llm_patch_uses_deterministic_fallback(self):
        proposal = {
            "old_snippet": 'os.system(f"ping {host}")',
            "new_snippet": 'os.system(shlex.quote(f"ping {host}"))',
        }
        agent = self.run_agent(MockClient("A clearer explanation.", proposal=proposal))
        command = next(finding for finding in agent.findings if finding.issue_type == "command_injection")
        self.assertEqual(command.attempts, 3)
        self.assertTrue(command.verification_proof)
        self.assertTrue(any("built-in deterministic correction" in event.message for event in agent.events))

    def test_invalid_llm_patch_and_missing_old_snippet_fall_back(self):
        for proposal in (None, {"old_snippet": "missing", "new_snippet": "safe"}):
            agent = self.run_agent(MockClient("A clearer explanation.", proposal=proposal))
            command = next(finding for finding in agent.findings if finding.issue_type == "command_injection")
            self.assertEqual(command.attempts, 3)
            self.assertTrue(command.verification_proof)

    def test_model_does_not_change_triage_or_verification_results(self):
        fallback = self.run_agent(None)
        model = self.run_agent(MockClient("A clearer explanation.", proposal=None))
        self.assertEqual([finding.is_real for finding in fallback.findings], [finding.is_real for finding in model.findings])
        self.assertEqual([bool(finding.verification_proof) for finding in fallback.findings], [bool(finding.verification_proof) for finding in model.findings])


if __name__ == "__main__":
    unittest.main()