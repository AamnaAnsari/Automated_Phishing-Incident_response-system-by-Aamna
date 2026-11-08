import unittest

from agents.extractor_agent import ExtractorAgent
from agents.validator import IndicatorValidator, ValidationResult
from config import Config
from tools.email_loader import EmailLoader


class FakeChain:
    """Stands in for `prompt | llm.with_structured_output(...)` so tests need no API key."""

    def __init__(self, result=None, error=None):
        self.result, self.error = result, error

    def invoke(self, _):
        if self.error:
            raise self.error
        return self.result


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.mail = EmailLoader().load(Config.EMAIL_DIR / "sample_noisy_04.txt")

    def run_with(self, chain):
        return ExtractorAgent(IndicatorValidator(chain)).extract(self.mail)

    def test_removes_false_positives_keeps_phishing(self):
        verdict = ValidationResult(
            false_urls=["http://example.com/"],
            false_ips=["127.0.0.1", "0.0.0.0"],
            false_emails=["your-name@example.com"],
            reason="Template placeholders.",
        )
        r = self.run_with(FakeChain(verdict))
        urls = [u["value"] for u in r["indicators"]["urls"]]
        self.assertEqual(urls, ["http://secure-bank-login.test/confirm?session=77"])
        self.assertEqual(r["indicators"]["ips"], [])
        self.assertNotIn("your-name@example.com", r["indicators"]["email_addresses"])
        self.assertEqual(len(r["removed_false_positives"]["urls"]), 1)

    def test_llm_cannot_remove_sender_or_unknown_values(self):
        verdict = ValidationResult(false_emails=[self.mail.sender_address], false_urls=["http://invented.test"])
        r = self.run_with(FakeChain(verdict))
        self.assertIn(self.mail.sender_address, r["indicators"]["email_addresses"])
        self.assertEqual(r["counts"]["urls"], 2)  # nothing removed

    def test_llm_cannot_remove_real_phishing_ip_url(self):
        mail = EmailLoader().load(Config.EMAIL_DIR / "sample_malicious_02.eml")
        verdict = ValidationResult(false_urls=["http://198.51.100.77/payroll/login.php?id=4821"],
                                   false_ips=["198.51.100.77"], reason="wrongly thinks it is a placeholder")
        r = ExtractorAgent(IndicatorValidator(FakeChain(verdict))).extract(mail)
        values = [u["value"] for u in r["indicators"]["urls"]]
        self.assertIn("http://198.51.100.77/payroll/login.php?id=4821", values)
        self.assertIn("198.51.100.77", r["indicators"]["ips"])

    def test_no_urls_or_ips_skips_llm(self):
        mail = EmailLoader().load(Config.EMAIL_DIR / "sample_bec_03.txt")
        r = ExtractorAgent(IndicatorValidator(FakeChain(error=ValueError("must not be called")))).extract(mail)
        self.assertIn("Nothing to validate", r["extraction_notes"])

    def test_dict_output_is_accepted(self):
        r = self.run_with(FakeChain({"false_ips": ["0.0.0.0"], "reason": "x"}))
        self.assertNotIn("0.0.0.0", r["indicators"]["ips"])

    def test_llm_failure_falls_back_to_regex(self):
        r = self.run_with(FakeChain(error=TimeoutError("api down")))
        self.assertEqual(r["counts"]["urls"], 2)
        self.assertIn("skipped", r["extraction_notes"])


if __name__ == "__main__":
    unittest.main()
