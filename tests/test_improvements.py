import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from compare_agents import AgentComparison, SingleAgent, comparison_markdown, score_extraction
from config import Config
from generate_report import ReportBuilder
from main import Pipeline
from run_demo import ScenarioRunner
from time_study import ManualTimeStudy
from tools.email_loader import EmailLoader


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runner = ScenarioRunner(self.root / "demo", self.root / "scenarios.json")
        self.review, self.store = self.runner.review, self.runner.store
        self.fw_dir = self.runner.workdir / "firewall"

    def process(self, filename):
        return self.runner.pipeline.process(EmailLoader().load(Config.EMAIL_DIR / filename))

    def lines(self, name):
        return (self.fw_dir / name).read_text(encoding="utf-8").split()


class TestFirewallExport(Base):
    def test_approval_exports_blocklists(self):
        self.review.approve(self.process("sample_malicious_02.eml")["plan_path"])
        self.assertEqual(self.lines("blocked_domains.txt"), ["examplecorp-hr-docs.test"])
        self.assertEqual(self.lines("blocked_ips.txt"), ["198.51.100.23", "198.51.100.77"])  # a URL on a bare IP blocks the IP
        self.assertIn("http://198.51.100.77/payroll/login.php?id=4821", self.lines("blocked_urls.txt"))
        self.assertIn("DENY outbound dst-ip 198.51.100.23",
                      (self.runner.workdir / "logs" / "firewall_sim.log").read_text(encoding="utf-8"))

    def test_applying_twice_adds_nothing_new(self):
        plan = self.store.load(self.process("sample_malicious_01.txt")["plan_path"])
        first = self.review.firewall.apply(plan)
        second = self.review.firewall.apply(plan)
        self.assertEqual(first, {"domains": 2, "ips": 0, "urls": 1})
        self.assertEqual(second, {"domains": 0, "ips": 0, "urls": 0})
        self.assertEqual(self.lines("blocked_domains.txt"),
                         ["malicious-phishing-test.com", "paypa1-support-test.com"])

    def test_rejection_exports_nothing(self):
        self.review.reject(self.process("sample_clean_02.txt")["plan_path"])
        self.assertEqual(list(self.fw_dir.glob("*.txt")), [])


class TestMeasuredReviewTime(Base):
    def test_review_seconds_are_stored(self):
        plan = self.review.approve(self.process("sample_malicious_01.txt")["plan_path"], review_sec=12.34)
        self.assertEqual(plan["human_decision"]["review_seconds"], 12.3)
        audit = (self.runner.workdir / "logs" / "audit_log.jsonl").read_text(encoding="utf-8")
        self.assertEqual(json.loads(audit.splitlines()[-1])["review_seconds"], 12.3)

    def test_review_seconds_are_optional(self):
        plan = self.review.reject(self.process("sample_clean_02.txt")["plan_path"])
        self.assertIsNone(plan["human_decision"]["review_seconds"])


class TestManualTimeStudy(unittest.TestCase):
    def test_summary_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            self.assertIsNone(ManualTimeStudy.load(path))
            study = ManualTimeStudy(path)
            for email_id, sec in (("a", 120), ("b", 240), ("c", 600)):
                study.record(email_id, sec)
            self.assertEqual(study.summary(), {"n": 3, "mean_sec": 320.0, "median_sec": 240})
            study.save()
            loaded = ManualTimeStudy.load(path)
            self.assertEqual((loaded["n"], loaded["mean_sec"]), (3, 320.0))
            self.assertEqual(loaded["schema"], "manual_baseline_v1")


class TestReportUsesMeasuredTimes(Base):
    def build_report(self, with_measurements):
        logs = self.runner.workdir / "logs"
        if with_measurements:
            for sec in (10, 20, 30):
                self.runner.logs.audit({"decision": "APPROVED", "review_seconds": sec})
            study = ManualTimeStudy(logs / "manual_baseline.json")
            study.record("a", 300)
            study.record("b", 300)
            study.save()
        summary = self.runner.pipeline.run(EmailLoader().load_all(Config.EMAIL_DIR))
        Pipeline.save_summary(summary, self.root / "run_summary.json")
        out = ReportBuilder(self.root / "run_summary.json", self.root / "scenarios.json", logs,
                            self.runner.safe_list, self.root / "report.md").save()
        return Path(out).read_text(encoding="utf-8")

    def test_measured_inputs_are_used_and_labelled(self):
        text = self.build_report(with_measurements=True)
        self.assertIn("measured, median of 3 decisions", text)
        self.assertIn("measured by hand on 2 emails", text)
        self.assertIn("about 5.0 min per email", text)
        self.assertIn("**Estimated time saved: 93.", text)  # (20s + tiny) against 300s

    def test_falls_back_to_cited_and_assumed_values(self):
        text = self.build_report(with_measurements=False)
        self.assertIn("cited research", text)
        self.assertIn("assumption", text)
        self.assertIn("## 5. Single-agent baseline comparison", text)
        self.assertIn("Not run yet. Use `python compare_agents.py`", text)

    def test_time_comparison_with_explicit_values(self):
        r = ReportBuilder.time_comparison(0.0, human_sec=30, manual_sec=300)
        self.assertEqual(r["reduction_pct"], 90.0)


class TestReviewConsole(Base):
    """Drives review_cli.main() with typed answers, so the console code is really executed."""

    def run_console(self, answers):
        import review_cli
        with mock.patch.object(review_cli, "ReviewService", return_value=self.review), \
                mock.patch("builtins.input", side_effect=answers), mock.patch("builtins.print"):
            review_cli.main()

    def test_pending_and_manual_cases_with_measured_time(self):
        self.process("sample_clean_02.txt")      # false positive  -> reject
        self.process("sample_malicious_01.txt")  # phishing        -> approve
        self.process("sample_timeout_05.txt")    # API failure     -> manual review, confirmed threat
        self.run_console(["r", "legit client", "", "a", "", "t", "checked by hand"])
        self.assertEqual(self.store.pending(), [])
        self.assertEqual(self.review.manual_queue(), [])
        self.assertTrue(self.runner.safe_list.contains("client-portal.com"))
        audit = (self.runner.workdir / "logs" / "audit_log.jsonl").read_text(encoding="utf-8")
        records = [json.loads(line) for line in audit.splitlines()]
        self.assertEqual(sorted(r["decision"] for r in records), ["APPROVED", "REJECTED", "RESOLVED_THREAT"])
        self.assertTrue(all(r["review_seconds"] is not None for r in records))

    def test_keep_in_queue_and_quit(self):
        self.process("sample_timeout_05.txt")
        self.run_console(["k"])
        self.assertEqual(len(self.review.manual_queue()), 1)


class TestZeroValuesDoNotBreakTheReport(Base):
    def test_zero_second_baseline_is_ignored(self):
        logs = self.runner.workdir / "logs"
        study = ManualTimeStudy(logs / "manual_baseline.json")
        study.record("a", 0)
        study.save()
        summary = self.runner.pipeline.run(EmailLoader().load_all(Config.EMAIL_DIR))
        Pipeline.save_summary(summary, self.root / "run_summary.json")
        text = ReportBuilder(self.root / "run_summary.json", self.root / "scenarios.json", logs,
                             self.runner.safe_list, self.root / "r.md").save().read_text(encoding="utf-8")
        self.assertIn("cited research", text)

    def test_time_comparison_ignores_zero_manual_time(self):
        self.assertEqual(ReportBuilder.time_comparison(0.0, manual_sec=0)["manual_sec"], 1500.0)


class FuncChain:
    def __init__(self, fn):
        self.fn = fn

    def invoke(self, inputs):
        return self.fn(inputs)


class TestAgentComparison(Base):
    def compare(self, fn):
        comparison = AgentComparison(SingleAgent(FuncChain(fn)), workdir=self.root / "cmp",
                                     results_path=self.root / "cmp.json", table_path=self.root / "cmp.md")
        return comparison.run()

    def test_multi_agent_side_matches_the_accuracy_check(self):
        result = self.compare(lambda _: {"urls": [], "ips": [], "overall_risk": "Safe"})
        m = result["summary"]["multi"]
        self.assertEqual((m["extraction_fn"], m["extraction_fp"]), (0, 3))  # regex only: 3 noise items kept
        self.assertEqual(m["invented_indicators"], 0)
        self.assertEqual(m["verdicts"], {"FN": 1, "TN": 1, "FP": 1, "TP": 3, "DEFERRED": 1})

    def test_lazy_single_agent_misses_everything(self):
        s = self.compare(lambda _: {"urls": [], "ips": [], "overall_risk": "Safe"})["summary"]["single"]
        self.assertEqual((s["threats_missed"], s["false_alarms"]), (5, 0))
        self.assertEqual(s["extraction_recall"], 0.0)
        self.assertIsNone(s["extraction_precision"])

    def test_invented_indicators_are_counted(self):
        s = self.compare(lambda _: {"urls": ["http://invented.test/x"], "ips": [], "overall_risk": "Malicious"}
                         )["summary"]["single"]
        self.assertEqual(s["invented_indicators"], 7)
        self.assertEqual(s["false_alarms"], 2)

    def test_single_agent_failure_is_counted_not_fatal(self):
        def broken(_):
            raise TimeoutError("llm down")
        result = self.compare(broken)
        self.assertEqual(result["summary"]["single"]["errors"], 7)
        self.assertEqual(result["summary"]["multi"]["errors"], 0)

    def test_files_are_written_and_report_includes_them(self):
        result = self.compare(lambda _: {"urls": [], "ips": [], "overall_risk": "Safe"})
        self.assertIn("Single agent", (self.root / "cmp.md").read_text(encoding="utf-8"))
        self.assertIn("not a benchmark", comparison_markdown(result))
        summary = self.runner.pipeline.run(EmailLoader().load_all(Config.EMAIL_DIR))
        Pipeline.save_summary(summary, self.root / "run_summary.json")
        text = ReportBuilder(self.root / "run_summary.json", self.root / "scenarios.json",
                             self.runner.workdir / "logs", self.runner.safe_list, self.root / "r.md",
                             comparison_path=self.root / "cmp.json").save().read_text(encoding="utf-8")
        self.assertIn("Invented indicators", text)


class TestScoreExtraction(unittest.TestCase):
    TRUTH = {"urls": ["http://198.51.100.77/login", "https://a.test/x"], "ips": ["198.51.100.23"]}

    def test_scoring(self):
        raw = "http://198.51.100.77/login https://a.test/x 198.51.100.23"
        perfect = score_extraction(["http://198.51.100.77/login", "https://a.test/x."], ["198.51.100.23", "198.51.100.77"],
                                   self.TRUTH, raw)
        self.assertEqual((perfect["tp"], perfect["fp"], perfect["fn"], perfect["invented"]), (3, 0, 0, []))
        bad = score_extraction(["https://a.test/x", "http://made-up.test"], [], self.TRUTH, raw)
        self.assertEqual((bad["tp"], bad["fp"], bad["fn"]), (1, 1, 2))
        self.assertEqual(bad["invented"], ["http://made-up.test"])


if __name__ == "__main__":
    unittest.main()
