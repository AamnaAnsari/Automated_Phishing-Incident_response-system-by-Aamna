"""Runs the 3 evaluation scenarios automatically (mock mode) in an isolated folder.

Run:  python run_demo.py
Your real storage/ and outputs/ are not touched: everything goes to outputs/demo_run/.
Result: outputs/reports/scenario_results.json (used by generate_report.py)
"""
import json
import shutil
from pathlib import Path

from agents.extractor_agent import ExtractorAgent
from agents.planner_agent import MANUAL_TAG, PlannerAgent, RationaleWriter
from agents.scanner_agent import ScannerAgent
from config import Config
from main import Pipeline
from tools.activity_log import ActivityLog
from tools.email_loader import EmailLoader
from tools.plan_store import PlanStore
from tools.review_service import ReviewService
from tools.safe_list import SafeList
from tools.vt_client import VTClient


class CountingClient:
    """Wraps the mock VT client and remembers which indicators were sent to VirusTotal."""
    mode = "MOCK"

    def __init__(self):
        self.client, self.calls = VTClient(mock=True), []

    def scan(self, value, kind):
        self.calls.append(value)
        return self.client.scan(value, kind)


class ScenarioRunner:
    def __init__(self, workdir=None, results_path=None):
        self.workdir = Path(workdir or Config.DEMO_DIR)
        self.results_path = Path(results_path or Config.REPORT_DIR / "scenario_results.json")
        if self.workdir.exists():
            shutil.rmtree(self.workdir)  # every run starts from zero
        self.safe_list = SafeList(self.workdir / "Safe_List.json")
        self.store = PlanStore(self.workdir / "storage")
        self.logs = ActivityLog(self.workdir / "logs")
        self.client = CountingClient()
        self.pipeline = Pipeline(
            ExtractorAgent(), ScannerAgent(self.client, self.safe_list),
            PlannerAgent(RationaleWriter(), self.store, self.logs),
            self.logs, out_dir=self.workdir / "outputs")
        self.review = ReviewService(self.store, self.safe_list, self.logs, actor="demo_admin")

    def run_all(self) -> list:
        results = [self.malicious_email(), self.api_failure(), self.feedback_loop()]
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        self.results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        return results

    # ---------- scenarios ----------
    def malicious_email(self) -> dict:
        rec = self._process("sample_malicious_01.txt")
        firewall = self.logs.dir / "firewall_sim.log"
        checks = [
            ("Planner proposed a block plan (PENDING_APPROVAL)", rec["outcome"] == "PENDING_APPROVAL"),
            ("Draft is waiting in Needs_Action", len(self.store.pending()) == 1),
            ("Nothing was blocked before human approval", not firewall.exists()),
        ]
        plan = self.review.approve(rec["plan_path"], "Confirmed phishing")
        checks += [
            ("Approval recorded (status APPROVED)", plan["status"] == "APPROVED"),
            ("Simulated firewall rule logged", "DENY outbound dst-domain malicious-phishing-test.com"
                                              in firewall.read_text(encoding="utf-8")),
            ("Plan archived in Approved/", len(list(self.store.approved.glob("*.json"))) == 1),
        ]
        return self._result("S1", "Malicious email -> plan -> human approval", checks)

    def api_failure(self) -> dict:
        rec = self._process("sample_timeout_05.txt")  # mock fixture simulates a VirusTotal timeout
        plan = self.store.load(rec["plan_path"]) if rec["plan_path"] else {}
        checks = [
            ("Pipeline did not crash", rec["outcome"] != "ERROR"),
            ("Outcome is NEEDS_MANUAL_REVIEW", rec["outcome"] == "NEEDS_MANUAL_REVIEW"),
            (f"Tagged '{MANUAL_TAG}'", plan.get("tag") == MANUAL_TAG),
            ("Saved in Manual_Review/", len(list(self.store.manual_review.glob("*.json"))) == 1),
            ("Nothing was queued for blocking", not any(
                p[1]["email_id"] == "sample_timeout_05" for p in self.store.pending())),
        ]
        return self._result("S2", "VirusTotal API failure -> manual review (no crash)", checks)

    def feedback_loop(self) -> dict:
        first = self._process("sample_clean_02.txt")  # mock false positive: client-portal.com
        checks = [("False positive was flagged first", first["outcome"] == "PENDING_APPROVAL")]
        self.review.reject(first["plan_path"], "Legitimate client website", None)
        checks.append(("Rejection added client-portal.com to the Safe List", self.safe_list.contains("client-portal.com")))

        self.client.calls.clear()
        second = self._process("sample_clean_02.txt")
        checks += [
            ("Same email is now CLOSED_SAFE", second["outcome"] == "CLOSED_SAFE"),
            ("VirusTotal was not called for the safe-listed domain",
             not any("client-portal.com" in c for c in self.client.calls)),
        ]
        return self._result("S3", "Reject -> Safe List -> re-run is not flagged again", checks)

    # ---------- helpers ----------
    def _process(self, filename: str) -> dict:
        return self.pipeline.process(EmailLoader().load(Config.EMAIL_DIR / filename))

    @staticmethod
    def _result(sid, name, checks) -> dict:
        return {"id": sid, "name": name, "passed": all(ok for _, ok in checks),
                "checks": [{"check": c, "passed": ok} for c, ok in checks]}


def main() -> None:
    runner = ScenarioRunner()
    for s in runner.run_all():
        print(f"\n{s['id']}  {s['name']}   [{'PASS' if s['passed'] else 'FAIL'}]")
        for c in s["checks"]:
            print(f"   [{'x' if c['passed'] else ' '}] {c['check']}")
    print(f"\nEvidence: {runner.workdir}   Results: {runner.results_path}")


if __name__ == "__main__":
    main()
