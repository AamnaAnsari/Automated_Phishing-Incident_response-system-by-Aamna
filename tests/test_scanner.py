import json
import tempfile
import unittest
from pathlib import Path

from agents.extractor_agent import ExtractorAgent
from agents.scanner_agent import ScannerAgent
from config import Config
from tools.email_loader import EmailLoader
from tools.safe_list import SafeList
from tools.vt_client import VTClient, VTError

CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 16}


class SpyClient:
    """Fake VT client: records calls, optionally fails on the Nth call."""
    mode = "MOCK"

    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def scan(self, value, kind):
        self.calls.append(value)
        if self.fail_on == len(self.calls):
            raise VTError("TIMEOUT", "simulated")
        return dict(CLEAN)


class ScannerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.safe_list = SafeList(Path(self.tmp.name) / "Safe_List.json")
        self.extractor = ExtractorAgent()

    def extracted(self, filename):
        return self.extractor.extract(EmailLoader().load(Config.EMAIL_DIR / filename))

    def scanner(self, client=None):
        return ScannerAgent(client or VTClient(mock=True), self.safe_list)


class TestClassify(unittest.TestCase):
    def test_thresholds(self):
        cases = [
            ({"malicious": 14, "suspicious": 0}, "Malicious"),
            ({"malicious": 3, "suspicious": 0}, "Malicious"),
            ({"malicious": 2, "suspicious": 0}, "Suspicious"),
            ({"malicious": 1, "suspicious": 0}, "Safe"),  # one engine alone = noise (e.g. google.com)
            ({"malicious": 0, "suspicious": 3}, "Suspicious"),
            ({"malicious": 0, "suspicious": 2}, "Safe"),
            ({"malicious": 0, "suspicious": 0}, "Safe"),
        ]
        for stats, expected in cases:
            with self.subTest(stats=stats):
                self.assertEqual(ScannerAgent.classify(stats), expected)


class TestScan(ScannerTestCase):
    def test_malicious_email(self):
        r = self.scanner().scan(self.extracted("sample_malicious_01.txt"))
        self.assertEqual(r["scan_status"], "COMPLETE")
        self.assertEqual(r["overall_risk"], "Malicious")
        url = next(x for x in r["results"] if x["type"] == "url")
        self.assertEqual(url["risk_level"], "Malicious")
        self.assertEqual(url["vt_stats"]["malicious"], 14)

    def test_clean_email(self):
        r = self.scanner().scan(self.extracted("sample_clean_01.txt"))
        self.assertEqual(r["overall_risk"], "Safe")

    def test_ip_based_phishing_and_suspicious_ip(self):
        r = self.scanner().scan(self.extracted("sample_malicious_02.eml"))
        risks = {x["indicator"]: x["risk_level"] for x in r["results"]}
        self.assertEqual(risks["198.51.100.23"], "Suspicious")
        self.assertEqual(risks["http://198.51.100.77/payroll/login.php?id=4821"], "Malicious")

    def test_sender_domain_is_scanned_once(self):
        r = self.scanner().scan(self.extracted("sample_malicious_01.txt"))
        types = [x["type"] for x in r["results"]]
        self.assertEqual(types.count("domain"), 1)
        # sender domain equals the URL domain in clean_02, so no extra domain scan
        r2 = self.scanner().scan(self.extracted("sample_clean_02.txt"))
        self.assertNotIn("domain", [x["type"] for x in r2["results"]])

    def test_result_has_schema_b_fields(self):
        r = self.scanner().scan(self.extracted("sample_clean_01.txt"))
        for key in ("schema", "email_id", "scanned_at", "scan_status", "scan_mode",
                    "error", "results", "overall_risk"):
            self.assertIn(key, r)
        self.assertEqual(r["scan_mode"], "MOCK")

    def test_save_writes_json(self):
        s = self.scanner()
        path = s.save(s.scan(self.extracted("sample_clean_01.txt")), Path(self.tmp.name))
        self.assertEqual(json.loads(Path(path).read_text())["email_id"], "sample_clean_01")


class TestSafeListSkip(ScannerTestCase):
    def test_false_positive_before_and_after_safe_list(self):
        extracted = self.extracted("sample_clean_02.txt")
        self.assertEqual(self.scanner().scan(extracted)["overall_risk"], "Malicious")  # mock false positive

        self.safe_list.add("client-portal.com", plan_id="PLAN-1", reason="false positive")
        spy = SpyClient()
        r = self.scanner(spy).scan(extracted)
        url = next(x for x in r["results"] if x["type"] == "url")
        self.assertEqual(url["skipped_reason"], "IN_SAFE_LIST")
        self.assertNotIn("https://client-portal.com/login", spy.calls)  # VT not even called
        self.assertEqual(r["overall_risk"], "Safe")


class TestApiFailure(ScannerTestCase):
    def test_total_failure_is_api_error(self):
        extracted = self.extracted("sample_clean_01.txt")
        extracted["indicators"]["urls"] = [{"value": "http://timeout-test.com/x", "domain": "timeout-test.com"}]
        r = self.scanner().scan(extracted)  # mock fixture raises TIMEOUT for this domain
        self.assertEqual(r["scan_status"], "API_ERROR")
        self.assertEqual(r["error"]["type"], "TIMEOUT")
        self.assertEqual(r["error"]["failed_indicator"], "http://timeout-test.com/x")
        self.assertEqual(r["overall_risk"], "Unknown")
        self.assertEqual(r["results"], [])

    def test_partial_failure(self):
        r = self.scanner(SpyClient(fail_on=2)).scan(self.extracted("sample_malicious_02.eml"))
        self.assertEqual(r["scan_status"], "PARTIAL")
        self.assertEqual(len(r["results"]), 1)
        self.assertEqual(r["overall_risk"], "Unknown")  # never "Safe" when we could not check everything

    def test_malicious_found_before_failure_stays_malicious(self):
        extracted = self.extracted("sample_malicious_01.txt")
        client = VTClient(mock=True)
        client.fixtures["indicators"]["203.0.113.45"] = {"error": "TIMEOUT"}  # URL scan ok, IP scan fails
        r = self.scanner(client).scan(extracted)
        self.assertEqual(r["scan_status"], "PARTIAL")
        self.assertEqual(r["overall_risk"], "Malicious")


class TestSafeList(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "Safe_List.json"

    def test_missing_file_is_empty(self):
        self.assertFalse(SafeList(self.path).contains("a.com"))

    def test_add_and_persist(self):
        self.assertTrue(SafeList(self.path).add("Client-Portal.com.", plan_id="PLAN-1", reason="fp"))
        again = SafeList(self.path)  # new object reads the file
        self.assertTrue(again.contains("client-portal.com"))
        entry = json.loads(self.path.read_text())["entries"][0]
        self.assertEqual(entry["domain"], "client-portal.com")
        self.assertEqual(entry["origin_plan_id"], "PLAN-1")

    def test_duplicate_not_added(self):
        sl = SafeList(self.path)
        sl.add("a.com")
        self.assertFalse(sl.add("A.com"))
        self.assertEqual(len(json.loads(self.path.read_text())["entries"]), 1)

    def test_subdomain_matches_but_lookalike_does_not(self):
        sl = SafeList(self.path)
        sl.add("a.com")
        self.assertTrue(sl.contains("www.a.com"))
        self.assertFalse(sl.contains("evil-a.com"))
        self.assertFalse(sl.contains("a.com.evil.test"))


if __name__ == "__main__":
    unittest.main()
