"""Accuracy check: compares the system's verdict with the true label of every dummy email.

Run:  python evaluate.py
Uses mock VirusTotal answers in an isolated folder (outputs/eval_run), so your real storage,
Safe List and logs are not touched. Result: outputs/reports/accuracy_results.json and accuracy_table.md
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from config import Config
from run_demo import ScenarioRunner
from tools.email_loader import EmailLoader

CAVEAT = ("Only 7 dummy emails and mock VirusTotal answers written by us: this shows how the system "
          "behaves, it is not a real-world accuracy benchmark.")


class AccuracyEvaluator:
    def __init__(self, workdir=None, truth_path=None, results_path=None, table_path=None):
        truth = json.loads(Path(truth_path or Config.TRUTH_FILE).read_text(encoding="utf-8"))
        truth.pop("_comment", None)
        self.truth = truth
        self.runner = ScenarioRunner(workdir or Config.EVAL_DIR)
        self.results_path = Path(results_path or Config.REPORT_DIR / "accuracy_results.json")
        self.table_path = Path(table_path or Config.REPORT_DIR / "accuracy_table.md")

    def run(self) -> dict:
        summary = self.runner.pipeline.run(EmailLoader().load_all(Config.EMAIL_DIR))
        rows = [self._row(rec) for rec in summary["emails"]]
        metrics = self._metrics(rows)
        metrics.update(self._simulate_admin(summary["emails"], rows))
        result = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "scan_mode": summary["scan_mode"], "rows": rows, "metrics": metrics, "caveat": CAVEAT}
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        self.results_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        self.table_path.write_text("## Accuracy check\n\n" + table_markdown(result), encoding="utf-8")
        return result

    # ---------- helpers ----------
    def _row(self, rec: dict) -> dict:
        entry = self.truth.get(rec["email_id"])
        if entry is None:
            raise ValueError(f"No label for {rec['email_id']} in data/ground_truth.json")
        result = self._judge(entry["label"], rec["outcome"])
        comment = {
            "TP": "Correctly flagged",
            "TN": "Correctly cleared",
            "FP": "False alarm: a human reject adds the domain to the Safe List",
            "FN": "MISSED: " + entry["note"],
            "DEFERRED": "Sent to manual review (VirusTotal failed), not decided automatically",
            "ERROR": "Pipeline error",
        }[result]
        return {"email_id": rec["email_id"], "true_label": entry["label"],
                "system_risk": rec["overall_risk"], "outcome": rec["outcome"],
                "result": result, "comment": comment}

    @staticmethod
    def _judge(label: str, outcome: str) -> str:
        if outcome == "ERROR":
            return "ERROR"
        if outcome == "NEEDS_MANUAL_REVIEW":
            return "DEFERRED"
        flagged = outcome == "PENDING_APPROVAL"
        if label == "phishing":
            return "TP" if flagged else "FN"
        return "FP" if flagged else "TN"

    @staticmethod
    def _metrics(rows: list) -> dict:
        n = {k: sum(r["result"] == k for r in rows) for k in ("TP", "FP", "FN", "TN", "DEFERRED", "ERROR")}

        def ratio(a, b):
            return round(a / b, 3) if b else None

        return {"tp": n["TP"], "fp": n["FP"], "fn": n["FN"], "tn": n["TN"],
                "deferred": n["DEFERRED"], "errors": n["ERROR"],
                "precision": ratio(n["TP"], n["TP"] + n["FP"]),
                "recall": ratio(n["TP"], n["TP"] + n["FN"]),
                "accuracy_decided": ratio(n["TP"] + n["TN"], n["TP"] + n["TN"] + n["FP"] + n["FN"])}

    def _simulate_admin(self, records: list, rows: list) -> dict:
        """An admin who knows the truth: approves real threats, rejects false alarms."""
        blocked = stopped = 0
        for rec, row in zip(records, rows):
            if rec["outcome"] != "PENDING_APPROVAL":
                continue
            if row["true_label"] == "legitimate":
                self.runner.review.reject(rec["plan_path"], "Simulated admin: legitimate email", None)
                stopped += 1
            else:
                self.runner.review.approve(rec["plan_path"], "Simulated admin: confirmed phishing")
                blocked += 1
        return {"threats_blocked_after_review": blocked, "false_alarms_stopped_by_human": stopped}


def _pct(value) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def table_markdown(result: dict) -> str:
    m = result["metrics"]
    lines = ["| Email | True label | System risk | System outcome | Result | Comment |", "|---|---|---|---|---|---|"]
    for r in result["rows"]:
        lines.append(f"| {r['email_id']} | {r['true_label']} | {r['system_risk'] or '-'} | "
                     f"{r['outcome']} | {r['result']} | {r['comment']} |")
    lines += [
        "",
        "TP = threat flagged, TN = clean cleared, FP = false alarm, FN = threat missed, "
        "DEFERRED = sent to a human because the API failed.", "",
        f"- Flagged correctly (TP): {m['tp']}, cleared correctly (TN): {m['tn']}, "
        f"false alarms (FP): {m['fp']}, missed threats (FN): {m['fn']}, deferred: {m['deferred']}",
        f"- Precision: {_pct(m['precision'])}, recall: {_pct(m['recall'])}, "
        f"accuracy on decided emails: {_pct(m['accuracy_decided'])}",
        f"- With a simulated admin who knows the true labels: {m['threats_blocked_after_review']} threat plans approved, "
        f"{m['false_alarms_stopped_by_human']} false alarm(s) stopped before reaching the firewall",
        "", f"Note: {result['caveat']}", "",
    ]
    return "\n".join(lines)


def main() -> None:
    result = AccuracyEvaluator().run()
    print(f"Accuracy check (scan mode: {result['scan_mode']})\n")
    print(f"{'Email':<22} {'True label':<11} {'System':<10} {'Outcome':<20} Result")
    for r in result["rows"]:
        print(f"{r['email_id']:<22} {r['true_label']:<11} {str(r['system_risk']):<10} {r['outcome']:<20} {r['result']}")
    m = result["metrics"]
    print(f"\nTP {m['tp']}  TN {m['tn']}  FP {m['fp']}  FN {m['fn']}  Deferred {m['deferred']}")
    print(f"Precision {_pct(m['precision'])}  Recall {_pct(m['recall'])}  Accuracy (decided) {_pct(m['accuracy_decided'])}")
    print(f"\nMissed threats are listed in the Comment column of {Config.REPORT_DIR / 'accuracy_table.md'}")


if __name__ == "__main__":
    main()
