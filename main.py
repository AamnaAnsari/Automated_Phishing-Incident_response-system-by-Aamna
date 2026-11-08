"""Pipeline runner: Extractor -> Scanner -> Planner for every email in data/emails/.

Run:  python main.py [--llm] [--live] [--watch | --chain]
        --llm    use the LLM (extractor validation + plan summary)
        --live   use the real VirusTotal API (default follows MOCK_MODE in .env)
        --watch  keep running and pick up new emails dropped into data/emails/ (Ctrl+C to stop)
        --chain  run the same three agents as one LangChain pipeline: extractor | scanner | planner
"""
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from agents.extractor_agent import ExtractorAgent
from agents.planner_agent import PlannerAgent, RationaleWriter
from agents.scanner_agent import ScannerAgent
from config import Config
from tools.activity_log import ActivityLog
from tools.email_loader import EmailLoader
from tools.vt_client import VTClient


class Pipeline:
    def __init__(self, extractor, scanner, planner, logs=None, llm_used=False, out_dir=None):
        self.extractor, self.scanner, self.planner = extractor, scanner, planner
        self.logs = logs or ActivityLog()
        self.llm_used = llm_used
        self.extracted_dir = Path(out_dir) / "extracted" if out_dir else None  # None = Config default
        self.scans_dir = Path(out_dir) / "scans" if out_dir else None

    @classmethod
    def build(cls, use_llm=False, live=False) -> "Pipeline":
        validator = writer = None
        if use_llm:
            from agents.validator import IndicatorValidator
            validator, writer = IndicatorValidator.from_config(), RationaleWriter.from_config()
        client = VTClient(mock=False) if live else VTClient()
        return cls(ExtractorAgent(validator), ScannerAgent(client), PlannerAgent(writer), llm_used=use_llm)

    def build_chain(self):
        """The three agents as one LangChain runnable: extractor | scanner | planner.
        Input: an EmailData object. Output: the Planner result {"outcome", "plan", "path"}.
        Intermediate JSON (schemas A and B) is still saved to disk."""
        from langchain_core.runnables import RunnableLambda

        def save_extracted(extracted):
            self.extractor.save(extracted, self.extracted_dir)
            return extracted

        def save_scan(scan):
            self.scanner.save(scan, self.scans_dir)
            return scan

        return (RunnableLambda(self.extractor.extract) | RunnableLambda(save_extracted)
                | RunnableLambda(self.scanner.scan) | RunnableLambda(save_scan)
                | RunnableLambda(self.planner.plan))

    def process(self, mail) -> dict:
        """Runs one email through all three agents. A failure in one email never stops the batch."""
        try:
            t0 = time.perf_counter()
            extracted = self.extractor.extract(mail)
            self.extractor.save(extracted, self.extracted_dir)
            t1 = time.perf_counter()
            scan = self.scanner.scan(extracted)
            self.scanner.save(scan, self.scans_dir)
            t2 = time.perf_counter()
            result = self.planner.plan(scan)
            t3 = time.perf_counter()
        except Exception as exc:  # unexpected bug or bad file: log it and move on
            message = f"{type(exc).__name__}: {exc}"
            self.logs.pipeline(f"{mail.email_id} ERROR {message}")
            return {"email_id": mail.email_id, "outcome": "ERROR", "overall_risk": None, "scan_status": None,
                    "plan_id": None, "plan_path": None, "rationale_source": None, "indicators_checked": 0,
                    "timing_sec": None, "error": message}

        plan = result["plan"] or {}
        return {
            "email_id": mail.email_id,
            "outcome": result["outcome"],
            "overall_risk": scan["overall_risk"],
            "scan_status": scan["scan_status"],
            "plan_id": plan.get("plan_id"),
            "plan_path": result["path"],
            "rationale_source": plan.get("rationale_source"),
            "indicators_checked": len(scan["results"]),
            "timing_sec": {"extract": round(t1 - t0, 3), "scan": round(t2 - t1, 3),
                           "plan": round(t3 - t2, 3), "total": round(t3 - t0, 3)},
            "error": None,
        }

    def run(self, emails) -> dict:
        started = datetime.now(timezone.utc)
        records = [self.process(mail) for mail in emails]
        totals = [r["timing_sec"]["total"] for r in records if r["timing_sec"]]
        summary = {
            "run_id": started.strftime("RUN-%Y%m%d-%H%M%S"),
            "started_at": started.isoformat(timespec="seconds"),
            "scan_mode": getattr(self.scanner.client, "mode", "UNKNOWN"),
            "llm_used": self.llm_used,
            "email_count": len(records),
            "outcomes": dict(Counter(r["outcome"] for r in records)),
            "avg_total_sec": round(sum(totals) / len(totals), 3) if totals else 0.0,
            "emails": records,
        }
        self.logs.pipeline(f"{summary['run_id']} finished: {summary['outcomes']}")
        return summary

    @staticmethod
    def save_summary(summary: dict, path=None) -> str:
        path = Path(path or Config.LOG_DIR / "run_summary.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return str(path)


def watch(pipeline) -> None:
    from tools.inbox_watcher import InboxWatcher

    print(f"Watching {Config.EMAIL_DIR} for new emails. Press Ctrl+C to stop.\n")

    def show(r):
        seconds = f"{r['timing_sec']['total']}s" if r["timing_sec"] else "-"
        print(f"{r['email_id']:<22} risk={str(r['overall_risk']):<10} -> {r['outcome']:<20} {seconds}")

    try:
        InboxWatcher(pipeline).run(interval=5.0, on_record=show)
    except KeyboardInterrupt:
        print("\nStopped.")


def run_chain(pipeline) -> None:
    print("LangChain pipeline: extractor | scanner | planner\n")
    chain = pipeline.build_chain()
    for mail in EmailLoader().load_all(Config.EMAIL_DIR):
        try:
            result = chain.invoke(mail)
            print(f"{mail.email_id:<22} -> {result['outcome']}")
        except Exception as exc:
            print(f"{mail.email_id:<22} -> ERROR {type(exc).__name__}: {exc}")
    print("\nNext: python review_cli.py")


def main() -> None:
    pipeline = Pipeline.build(use_llm="--llm" in sys.argv, live="--live" in sys.argv)
    print(f"Scan mode: {pipeline.scanner.client.mode}   LLM: {'on' if pipeline.llm_used else 'off'}\n")
    if "--watch" in sys.argv:
        return watch(pipeline)
    if "--chain" in sys.argv:
        return run_chain(pipeline)

    summary = pipeline.run(EmailLoader().load_all(Config.EMAIL_DIR))
    for r in summary["emails"]:
        seconds = f"{r['timing_sec']['total']}s" if r["timing_sec"] else "-"
        print(f"{r['email_id']:<22} risk={str(r['overall_risk']):<10} -> {r['outcome']:<20} {seconds}")

    path = pipeline.save_summary(summary)
    print(f"\n{summary['email_count']} emails, average {summary['avg_total_sec']}s each. Outcomes: {summary['outcomes']}")
    print(f"Run summary: {path}")
    print("Next: python review_cli.py   (human decisions)   then   python generate_report.py")


if __name__ == "__main__":
    main()
