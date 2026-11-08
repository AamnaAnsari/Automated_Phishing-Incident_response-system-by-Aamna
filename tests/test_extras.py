import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from config import Config
from run_demo import ScenarioRunner
from tools.email_loader import EmailLoader
from tools.inbox_watcher import InboxWatcher


class ExtrasCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runner = ScenarioRunner(self.root / "demo", self.root / "scenarios.json")
        self.pipeline, self.review, self.store = self.runner.pipeline, self.runner.review, self.runner.store
        self.notes = self.runner.workdir / "notifications"

    def process(self, filename):
        return self.pipeline.process(EmailLoader().load(Config.EMAIL_DIR / filename))

    def note(self, name):
        return (self.notes / name).read_text(encoding="utf-8")


class TestEmployeeAndItNotifications(ExtrasCase):
    def test_safe_email_gets_a_reply(self):
        self.process("sample_clean_01.txt")
        text = self.note("to_employee_sample_clean_01.txt")
        self.assertIn("no known threats", text)
        self.assertIn("Subject: Re: FW: Please check this email", text)

    def test_manual_review_is_forwarded_to_it_and_employee_is_told(self):
        rec = self.process("sample_timeout_05.txt")
        it = self.note("to_it_team_sample_timeout_05.txt")
        self.assertIn(Config.IT_TEAM_ADDRESS, it)
        self.assertIn("Needs Manual Review - API Error", it)
        self.assertIn(rec["plan_id"], it)
        self.assertIn("do not click", self.note("to_employee_sample_timeout_05.txt"))

    def test_approve_and_reject_reply_to_the_employee(self):
        approved = self.process("sample_malicious_01.txt")
        self.review.approve(approved["plan_path"])
        self.assertIn("confirmed that this email is phishing", self.note("to_employee_sample_malicious_01.txt"))

        rejected = self.process("sample_clean_02.txt")
        self.review.reject(rejected["plan_path"])
        self.assertIn("found it legitimate", self.note("to_employee_sample_clean_02.txt"))


class TestManualReviewResolution(ExtrasCase):
    def test_queue_lists_the_case(self):
        self.process("sample_timeout_05.txt")
        queue = self.review.manual_queue()
        self.assertEqual([plan["email_id"] for _, plan in queue], ["sample_timeout_05"])

    def test_resolve_as_threat(self):
        rec = self.process("sample_timeout_05.txt")
        plan = self.review.resolve_manual(rec["plan_path"], "threat", "checked by hand")
        self.assertEqual(plan["status"], "RESOLVED_THREAT")
        self.assertEqual(self.review.manual_queue(), [])
        self.assertEqual(len(list(self.store.resolved.glob("*.json"))), 1)
        audit = (self.runner.workdir / "logs" / "audit_log.jsonl").read_text(encoding="utf-8")
        self.assertEqual(json.loads(audit.splitlines()[-1])["decision"], "RESOLVED_THREAT")
        self.assertIn("confirmed that this email is phishing", self.note("to_employee_sample_timeout_05.txt"))

    def test_resolve_as_safe(self):
        rec = self.process("sample_timeout_05.txt")
        plan = self.review.resolve_manual(rec["plan_path"], "SAFE")
        self.assertEqual(plan["status"], "RESOLVED_SAFE")
        self.assertIn("found this email legitimate", self.note("to_employee_sample_timeout_05.txt"))

    def test_wrong_status_or_verdict_is_refused(self):
        manual = self.process("sample_timeout_05.txt")
        with self.assertRaises(ValueError):
            self.review.approve(manual["plan_path"])  # a manual-review case cannot be 'approved'
        with self.assertRaises(ValueError):
            self.review.resolve_manual(manual["plan_path"], "maybe")
        pending = self.process("sample_malicious_01.txt")
        with self.assertRaises(ValueError):
            self.review.resolve_manual(pending["plan_path"], "THREAT")  # a pending plan is not a manual case


class TestInboxWatcher(ExtrasCase):
    def setUp(self):
        super().setUp()
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()

    def drop(self, filename):
        shutil.copy(Config.EMAIL_DIR / filename, self.inbox / filename)

    def watcher(self, settle=0):
        return InboxWatcher(self.pipeline, self.inbox, settle_sec=settle)

    def test_picks_up_only_new_emails(self):
        watcher = self.watcher()
        self.drop("sample_malicious_01.txt")
        self.drop("sample_clean_01.txt")
        first = watcher.scan_once()
        self.assertEqual([r["email_id"] for r in first], ["sample_clean_01", "sample_malicious_01"])
        self.assertEqual(watcher.scan_once(), [])  # nothing new

        self.drop("sample_bec_03.txt")
        second = watcher.scan_once()
        self.assertEqual([r["email_id"] for r in second], ["sample_bec_03"])

    def test_ignores_other_file_types(self):
        (self.inbox / "notes.pdf").write_text("not an email")
        self.assertEqual(self.watcher().scan_once(), [])

    def test_waits_for_files_that_are_still_being_written(self):
        self.drop("sample_clean_01.txt")
        self.assertEqual(self.watcher(settle=3600).scan_once(), [])

    def test_run_stops_after_max_loops(self):
        self.drop("sample_clean_01.txt")
        seen = []
        self.watcher().run(interval=0, max_loops=2, on_record=seen.append)
        self.assertEqual(len(seen), 1)


@unittest.skipUnless(importlib.util.find_spec("langchain_core"), "langchain-core is not installed")
class TestLangChainPipeline(ExtrasCase):
    def test_chain_runs_the_three_agents(self):
        mail = EmailLoader().load(Config.EMAIL_DIR / "sample_malicious_01.txt")
        result = self.pipeline.build_chain().invoke(mail)
        self.assertEqual(result["outcome"], "PENDING_APPROVAL")
        self.assertTrue((self.root / "demo" / "outputs" / "extracted" / "sample_malicious_01.json").exists())
        self.assertTrue((self.root / "demo" / "outputs" / "scans" / "sample_malicious_01.json").exists())


if __name__ == "__main__":
    unittest.main()
