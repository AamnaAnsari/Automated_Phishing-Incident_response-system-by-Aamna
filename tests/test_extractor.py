import unittest

from config import Config
from agents.extractor_agent import ExtractorAgent
from tools.email_loader import EmailLoader


class TestExtractor(unittest.TestCase):
    def setUp(self):
        self.loader, self.agent = EmailLoader(), ExtractorAgent()

    def run_on(self, name):
        return self.agent.extract(self.loader.load(Config.EMAIL_DIR / name))

    def test_malicious_txt(self):
        r = self.run_on("sample_malicious_01.txt")
        self.assertEqual(r["indicators"]["urls"][0]["domain"], "malicious-phishing-test.com")
        self.assertIn("203.0.113.45", r["indicators"]["ips"])
        self.assertEqual(r["sender"]["domain"], "paypa1-support-test.com")

    def test_clean_txt(self):
        r = self.run_on("sample_clean_01.txt")
        self.assertEqual(r["counts"]["urls"], 1)
        self.assertEqual(r["indicators"]["urls"][0]["value"], "https://www.python.org/about/")

    def test_eml_ip_url_and_trailing_dot(self):
        r = self.run_on("sample_malicious_02.eml")
        values = [u["value"] for u in r["indicators"]["urls"]]
        self.assertIn("http://198.51.100.77/payroll/login.php?id=4821", values)
        self.assertIn("https://examplecorp-hr-docs.test/download?file=letter.pdf", values)  # no trailing "."
        self.assertIn("198.51.100.23", r["indicators"]["ips"])  # from Received header
        self.assertEqual(r["counts"]["emails"], 2)

    def test_no_links_bec(self):
        r = self.run_on("sample_bec_03.txt")
        self.assertEqual(r["counts"]["urls"], 0)

    def test_invalid_ip_ignored(self):
        self.assertEqual(ExtractorAgent.IP_RE.findall("version 999.1.1.1 and 10.0.0.1"), ["10.0.0.1"])


if __name__ == "__main__":
    unittest.main()
