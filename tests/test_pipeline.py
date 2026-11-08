import json
import tempfile
import unittest
from pathlib import Path

from agents.extractor_agent import ExtractorAgent
from agents.planner_agent import PlannerAgent, RationaleWriter
from agents.scanner_agent import ScannerAgent
from config import Config
from generate_report import ReportBuilder
from main import Pipeline
from run_demo import CountingClient, ScenarioRunner
from tools.email_loader import EmailLoader


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runner = ScenarioRunner(self.root / "demo", self.root / "scenarios.json")  # isolated workspace
        self.mails = EmailLoader().load_all(Config.EMAIL_DIR)


class TestScenarios(PipelineTestCase):
    def test_all_three_scenarios_pass(self):
        results = self.runner.run_all()
        self.assertEqual([s["id"] for s in results], ["S1", "S2", "S3"])
        for s in results:
            with self.subTest(scenario=s["id"]):
                failed = [c["check"] for c in s["checks"] if not c["passed"]]
                self.assertEqual(failed, [])
        self.assertTrue((self.root / "scenarios.json").exists())


class TestPipeline(PipelineTestCase):
    def test_batch_outcomes_and_summary(self):
        summary = self.runner.pipeline.run(self.mails)
        self.assertEqual(summary["email_count"], len(self.mails))
        self.assertEqual(summary["outcomes"],
                         {"CLOSED_SAFE": 2, "PENDING_APPROVAL": 4, "NEEDS_MANUAL_REVIEW": 1})
        self.assertEqual(summary["scan_mode"], "MOCK")
        first = summary["emails"][0]
        self.assertEqual(set(first["timing_sec"]), {"extract", "scan", "plan", "total"})

    def test_unexpected_error_does_not_stop_the_batch(self):
        class BrokenExtractor(ExtractorAgent):
            def extract(self, email):
                if email.email_id == "sample_bec_03":
                    raise RuntimeError("boom")
                return super().extract(email)

        runner = self.runner
        pipeline = Pipeline(BrokenExtractor(), ScannerAgent(CountingClient(), runner.safe_list),
                            PlannerAgent(RationaleWriter(), runner.store, runner.logs),
                            runner.logs, out_dir=self.root / "out")
        summary = pipeline.run(self.mails)
        by_id = {r["email_id"]: r for r in summary["emails"]}
        self.assertEqual(by_id["sample_bec_03"]["outcome"], "ERROR")
        self.assertIn("boom", by_id["sample_bec_03"]["error"])
        self.assertEqual(by_id["sample_malicious_01"]["outcome"], "PENDING_APPROVAL")
        self.assertIn("ERROR", (runner.logs.dir / "pipeline.log").read_text(encoding="utf-8"))

    def test_rerun_keeps_one_manual_review_file(self):
        mail = EmailLoader().load(Config.EMAIL_DIR / "sample_timeout_05.txt")
        self.runner.pipeline.process(mail)
        self.runner.pipeline.process(mail)
        self.assertEqual(len(list(self.runner.store.manual_review.glob("*.json"))), 1)


class TestReport(PipelineTestCase):
    def test_time_comparison_math(self):
        r = ReportBuilder.time_comparison(0.0)  # 60s human vs 25 min manual
        self.assertEqual(r["reduction_pct"], 96.0)
        self.assertAlmostEqual(r["manual_sec"], 1500.0)

    def test_report_has_all_sections(self):
        self.runner.run_all()
        summary_path = self.root / "run_summary.json"
        summary = self.runner.pipeline.run(self.mails)
        Pipeline.save_summary(summary, summary_path)
        out = ReportBuilder(summary_path, self.root / "scenarios.json", self.runner.logs.dir,
                            self.runner.safe_list, self.root / "report.md").save()
        text = Path(out).read_text(encoding="utf-8")
        for part in ("## 1. Results per email", "## 2. Time comparison", "## 3. Scenario tests",
                     "## 4. Accuracy check", "## 5. Single-agent baseline comparison",
                     "## 6. Human decisions", "## 7. Limitations", "PENDING_APPROVAL",
                     "Estimated time saved", "client-portal.com", "S3"):
            self.assertIn(part, text)

    def test_missing_summary_gives_clear_error(self):
        builder = ReportBuilder(self.root / "none.json", out_path=self.root / "r.md")
        with self.assertRaises(FileNotFoundError) as ctx:
            builder.build()
        self.assertIn("python main.py", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
