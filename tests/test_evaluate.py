import json
import tempfile
import unittest
from pathlib import Path

from config import Config
from evaluate import AccuracyEvaluator
from tools.email_loader import EmailLoader


class TestAccuracyEvaluator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.table = root / "table.md"
        self.result = AccuracyEvaluator(root / "work", results_path=root / "acc.json",
                                        table_path=self.table).run()

    def results_by_email(self):
        return {r["email_id"]: r["result"] for r in self.result["rows"]}

    def test_every_email_has_a_label(self):
        truth = json.loads(Config.TRUTH_FILE.read_text(encoding="utf-8"))
        truth.pop("_comment")
        self.assertEqual(set(truth), {m.email_id for m in EmailLoader().load_all(Config.EMAIL_DIR)})

    def test_per_email_results(self):
        self.assertEqual(self.results_by_email(), {
            "sample_malicious_01": "TP", "sample_malicious_02": "TP", "sample_noisy_04": "TP",
            "sample_clean_01": "TN", "sample_clean_02": "FP",
            "sample_bec_03": "FN", "sample_timeout_05": "DEFERRED"})

    def test_metrics(self):
        m = self.result["metrics"]
        self.assertEqual((m["tp"], m["tn"], m["fp"], m["fn"], m["deferred"]), (3, 1, 1, 1, 1))
        self.assertEqual(m["precision"], 0.75)
        self.assertEqual(m["recall"], 0.75)
        self.assertEqual(m["accuracy_decided"], 0.667)

    def test_human_gate_stops_the_false_alarm(self):
        m = self.result["metrics"]
        self.assertEqual(m["threats_blocked_after_review"], 3)
        self.assertEqual(m["false_alarms_stopped_by_human"], 1)

    def test_table_is_written_and_honest_about_the_miss(self):
        text = self.table.read_text(encoding="utf-8")
        self.assertIn("sample_bec_03", text)
        self.assertIn("MISSED", text)
        self.assertIn("not a real-world accuracy benchmark", text)


if __name__ == "__main__":
    unittest.main()
