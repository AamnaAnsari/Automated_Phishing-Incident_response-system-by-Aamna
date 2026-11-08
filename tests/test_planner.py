import json
import tempfile
import unittest
from pathlib import Path

from agents.extractor_agent import ExtractorAgent
from agents.planner_agent import MANUAL_TAG, PlannerAgent, RationaleWriter
from agents.scanner_agent import ScannerAgent
from config import Config
from review_cli import parse_selection
from tools.activity_log import ActivityLog
from tools.email_loader import EmailLoader
from tools.plan_store import PlanStore
from tools.review_service import ReviewService
from tools.safe_list import SafeList
from tools.vt_client import VTClient, VTError


class FakeChain:
    def __init__(self, result=None, error=None):
        self.result, self.error = result, error

    def invoke(self, _):
        if self.error:
            raise self.error
        return self.result


class SpyClient:
    """VT client that records calls and always answers 'clean'."""
    mode = "MOCK"

    def __init__(self):
        self.calls = []

    def scan(self, value, kind):
        self.calls.append(value)
        return {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 16}


class PipelineCase(unittest.TestCase):
    """Temp folders for everything, so tests never touch your real storage/ and outputs/."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.safe_list = SafeList(root / "Safe_List.json")
        self.store = PlanStore(root / "storage")
        self.logs = ActivityLog(root / "logs")
        self.planner = PlannerAgent(RationaleWriter(), self.store, self.logs)
        self.review = ReviewService(self.store, self.safe_list, self.logs, actor="tester")

    def scan_email(self, filename, client=None, edit=None):
        extracted = ExtractorAgent().extract(EmailLoader().load(Config.EMAIL_DIR / filename))
        if edit:
            edit(extracted)
        return ScannerAgent(client or VTClient(mock=True), self.safe_list).scan(extracted)

    def run_email(self, filename, client=None, edit=None):
        return self.planner.plan(self.scan_email(filename, client, edit))

    def log_text(self, name):
        return (Path(self.tmp.name) / "logs" / name).read_text(encoding="utf-8")


class TestPlanner(PipelineCase):
    def test_malicious_creates_pending_draft(self):
        r = self.run_email("sample_malicious_01.txt")
        self.assertEqual(r["outcome"], "PENDING_APPROVAL")
        plan = json.loads(Path(r["path"]).read_text())
        self.assertEqual(plan["schema"], "approval_draft_v1")
        self.assertEqual(plan["status"], "PENDING_APPROVAL")
        self.assertEqual(plan["rationale_source"], "TEMPLATE")
        self.assertIsNone(plan["human_decision"]["decision"])
        rules = {a["action"]: a["simulated_firewall_rule"] for a in plan["proposed_actions"]}
        self.assertEqual(rules["BLOCK_URL"], "DENY outbound dst-domain malicious-phishing-test.com")
        self.assertEqual(rules["BLOCK_SENDER_DOMAIN"], "DENY inbound sender-domain paypa1-support-test.com")
        self.assertNotIn("BLOCK_IP", rules)  # the IP in this email is clean
        self.assertEqual(len(self.store.pending()), 1)

    def test_clean_email_is_closed_without_draft(self):
        r = self.run_email("sample_clean_01.txt")
        self.assertEqual(r["outcome"], "CLOSED_SAFE")
        self.assertEqual(self.store.pending(), [])
        self.assertIn("CLOSED_SAFE", self.log_text("pipeline.log"))

    def test_suspicious_ip_gets_a_draft(self):
        def only_suspicious_ip(extracted):
            extracted["indicators"]["urls"] = []
            extracted["indicators"]["ips"] = ["198.51.100.23"]
        r = self.run_email("sample_clean_01.txt", edit=only_suspicious_ip)
        self.assertEqual(r["outcome"], "PENDING_APPROVAL")
        self.assertEqual(r["plan"]["overall_risk"], "Suspicious")
        self.assertEqual(r["plan"]["proposed_actions"][0]["action"], "BLOCK_IP")

    def test_api_error_goes_to_manual_review(self):
        def timeout_url(extracted):
            extracted["indicators"]["urls"] = [{"value": "http://timeout-test.com/x", "domain": "timeout-test.com"}]
        r = self.run_email("sample_clean_01.txt", edit=timeout_url)
        self.assertEqual(r["outcome"], "NEEDS_MANUAL_REVIEW")
        self.assertEqual(r["plan"]["tag"], MANUAL_TAG)
        self.assertEqual(r["plan"]["status"], "NEEDS_MANUAL_REVIEW")
        self.assertEqual(len(list(self.store.manual_review.glob("*.json"))), 1)
        self.assertEqual(self.store.pending(), [])  # nothing is waiting for a block approval

    def test_manual_review_keeps_threats_found_before_the_failure(self):
        client = VTClient(mock=True)
        client.fixtures["indicators"]["203.0.113.45"] = {"error": "TIMEOUT"}
        r = self.run_email("sample_malicious_01.txt", client=client)
        self.assertEqual(r["outcome"], "NEEDS_MANUAL_REVIEW")
        self.assertEqual(r["plan"]["overall_risk"], "Malicious")
        self.assertEqual(len(r["plan"]["proposed_actions"]), 1)

    def test_plan_ids_increase(self):
        a = self.run_email("sample_malicious_01.txt")["plan"]["plan_id"]
        b = self.run_email("sample_malicious_02.eml")["plan"]["plan_id"]
        self.assertTrue(a.endswith("-0001"))
        self.assertTrue(b.endswith("-0002"))

    def test_rerun_replaces_old_pending_draft(self):
        self.run_email("sample_malicious_01.txt")
        self.run_email("sample_malicious_01.txt")
        self.assertEqual(len(self.store.pending()), 1)


class TestRationaleWriter(PipelineCase):
    def write_with(self, chain):
        scan = self.scan_email("sample_malicious_01.txt")
        actions = PlannerAgent._build_actions(scan)
        return RationaleWriter(chain).write(scan, actions)

    def test_llm_text_is_used(self):
        self.assertEqual(self.write_with(FakeChain("PayPal lookalike with a flagged link.")),
                         ("PayPal lookalike with a flagged link.", "LLM"))

    def test_llm_failure_falls_back_to_template(self):
        text, source = self.write_with(FakeChain(error=TimeoutError("down")))
        self.assertEqual(source, "TEMPLATE")
        self.assertIn("rated Malicious", text)

    def test_empty_llm_answer_falls_back(self):
        self.assertEqual(self.write_with(FakeChain("   "))[1], "TEMPLATE")


class TestReview(PipelineCase):
    def test_approve_logs_rules_and_archives(self):
        r = self.run_email("sample_malicious_01.txt")
        plan = self.review.approve(r["path"], "looks like phishing")
        self.assertEqual(plan["status"], "APPROVED")
        self.assertEqual(plan["human_decision"]["decided_by"], "tester")
        self.assertEqual(self.store.pending(), [])
        self.assertEqual(len(list(self.store.approved.glob("*.json"))), 1)
        firewall = self.log_text("firewall_sim.log")
        self.assertIn("DENY outbound dst-domain malicious-phishing-test.com", firewall)
        self.assertIn(plan["plan_id"], firewall)
        audit = json.loads(self.log_text("audit_log.jsonl").splitlines()[0])
        self.assertEqual((audit["decision"], audit["actor"]), ("APPROVED", "tester"))

    def test_reject_adds_domains_to_safe_list(self):
        r = self.run_email("sample_clean_02.txt")  # mock false positive: client-portal.com
        self.assertEqual(r["outcome"], "PENDING_APPROVAL")
        plan = self.review.reject(r["path"], "legitimate client site")
        self.assertEqual(plan["status"], "REJECTED")
        self.assertTrue(self.safe_list.contains("client-portal.com"))
        self.assertEqual(plan["human_decision"]["safe_list_added"], ["client-portal.com"])
        self.assertEqual(len(list(self.store.rejected.glob("*.json"))), 1)
        self.assertNotIn("DENY", self.log_text("audit_log.jsonl") + "")  # no block rule was logged
        self.assertFalse((Path(self.tmp.name) / "logs" / "firewall_sim.log").exists())

    def test_reject_can_choose_domains(self):
        r = self.run_email("sample_malicious_01.txt")
        self.review.reject(r["path"], domains=["malicious-phishing-test.com"])
        self.assertTrue(self.safe_list.contains("malicious-phishing-test.com"))
        self.assertFalse(self.safe_list.contains("paypa1-support-test.com"))

    def test_reject_with_no_domains_leaves_safe_list_empty(self):
        r = self.run_email("sample_malicious_01.txt")
        self.review.reject(r["path"], domains=[])
        self.assertEqual(self.safe_list.domains(), set())

    def test_cannot_decide_twice(self):
        r = self.run_email("sample_malicious_01.txt")
        self.review.approve(r["path"])
        approved_file = next(self.store.approved.glob("*.json"))
        with self.assertRaises(ValueError):
            self.review.approve(approved_file)

    def test_full_feedback_loop(self):
        """false positive -> human rejects -> next run is skipped without calling VirusTotal."""
        first = self.run_email("sample_clean_02.txt")
        self.assertEqual(first["outcome"], "PENDING_APPROVAL")
        self.review.reject(first["path"], "false positive")

        spy = SpyClient()
        second = self.run_email("sample_clean_02.txt", client=spy)
        self.assertEqual(second["outcome"], "CLOSED_SAFE")
        self.assertNotIn("https://client-portal.com/login", spy.calls)


class TestParseSelection(unittest.TestCase):
    DOMAINS = ["a.com", "b.com", "c.com"]

    def test_cases(self):
        self.assertEqual(parse_selection("", self.DOMAINS), self.DOMAINS)
        self.assertEqual(parse_selection("n", self.DOMAINS), [])
        self.assertEqual(parse_selection("1,3", self.DOMAINS), ["a.com", "c.com"])
        self.assertEqual(parse_selection("2, 9, x", self.DOMAINS), ["b.com"])


if __name__ == "__main__":
    unittest.main()
