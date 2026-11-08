"""Builds outputs/reports/final_report.md from the run summary, scenario results and logs.

Run order:  main.py -> review_cli.py -> run_demo.py -> evaluate.py -> (time_study.py, compare_agents.py) -> generate_report.py
"""
import json
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from compare_agents import comparison_markdown
from config import Config
from evaluate import table_markdown
from time_study import ManualTimeStudy
from tools.safe_list import SafeList

LIMITATIONS = [
    "Prototype uses dummy emails; a production version would read the IT Helpdesk inbox (Gmail / Outlook Graph API).",
    "VirusTotal free tier allows about 4 requests per minute, so large batches run slowly.",
    "A URL that VirusTotal has never seen returns no detections and is treated as having none.",
    "Only URLs, IP addresses and the sender domain are checked; attachments and malware sandboxing are out of scope.",
    "Business Email Compromise without links is not detected (sample_bec_03 is missed); a content-analysis agent is future work.",
    "The accuracy check uses 7 dummy emails and mock VirusTotal answers, so it shows behaviour, not real-world accuracy.",
    "The LLM only cleans extraction noise and writes summaries; verdicts and block rules come from code.",
    "Approved rules are not pushed to a live firewall: they are logged and exported as plain-text blocklists for an admin or firewall to import.",
    "Employee replies and IT-team escalations are simulated text files (no mail server), and the dummy emails do not record who forwarded them.",
    "Approval happens in a console tool (review_cli.py); a web dashboard with one-click approve is future work.",
]


class ReportBuilder:
    def __init__(self, summary_path=None, scenario_path=None, log_dir=None, safe_list=None, out_path=None,
                 accuracy_path=None, manual_baseline_path=None, comparison_path=None):
        self.summary_path = Path(summary_path or Config.LOG_DIR / "run_summary.json")
        self.scenario_path = Path(scenario_path or Config.REPORT_DIR / "scenario_results.json")
        self.accuracy_path = Path(accuracy_path or Config.REPORT_DIR / "accuracy_results.json")
        self.log_dir = Path(log_dir or Config.LOG_DIR)
        self.manual_baseline_path = Path(manual_baseline_path or self.log_dir / "manual_baseline.json")
        self.comparison_path = Path(comparison_path or Config.REPORT_DIR / "agent_comparison.json")
        self.safe_list = safe_list or SafeList()
        self.out_path = Path(out_path or Config.REPORT_DIR / "final_report.md")

    @staticmethod
    def time_comparison(avg_auto_sec: float, human_sec=None, manual_sec=None) -> dict:
        """Our per-email time versus the manual baseline.
        human_sec / manual_sec default to the assumption and the cited research from config.py."""
        if manual_sec is None or manual_sec <= 0:
            low, high = Config.MANUAL_MINUTES
            manual_sec = (low + high) / 2 * 60
        if human_sec is None:
            human_sec = Config.HUMAN_REVIEW_SEC_ASSUMED
        total = avg_auto_sec + human_sec
        return {"manual_sec": manual_sec, "auto_sec": avg_auto_sec, "human_sec": human_sec,
                "total_sec": total, "reduction_pct": round((1 - total / manual_sec) * 100, 1)}

    def build(self) -> str:
        if not self.summary_path.exists():
            raise FileNotFoundError(f"{self.summary_path} not found. Run `python main.py` first.")
        summary = json.loads(self.summary_path.read_text(encoding="utf-8"))
        lines = [
            "# Automated Phishing Incident Response System - Run Report", "",
            f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}  ",
            f"Run: {summary['run_id']} | Scan mode: {summary['scan_mode']} | "
            f"LLM: {'on' if summary['llm_used'] else 'off'} | Emails: {summary['email_count']}", "",
        ]
        lines += self._results_section(summary)
        lines += self._time_section(summary)
        lines += self._scenario_section()
        lines += self._accuracy_section()
        lines += self._comparison_section()
        lines += self._decisions_section()
        lines += ["## 7. Limitations", ""] + [f"- {item}" for item in LIMITATIONS] + [""]
        return "\n".join(lines)

    def save(self) -> Path:
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.out_path.write_text(self.build(), encoding="utf-8")
        return self.out_path

    # ---------- sections ----------
    @staticmethod
    def _results_section(summary) -> list:
        lines = ["## 1. Results per email", "",
                 "| Email | Risk | Scan status | Outcome | Plan ID | Time |", "|---|---|---|---|---|---|"]
        for r in summary["emails"]:
            seconds = f"{r['timing_sec']['total']}s" if r["timing_sec"] else "-"
            lines.append(f"| {r['email_id']} | {r['overall_risk'] or '-'} | {r['scan_status'] or '-'} | "
                         f"{r['outcome']} | {r['plan_id'] or '-'} | {seconds} |")
        counts = ", ".join(f"{k}: {v}" for k, v in sorted(summary["outcomes"].items()))
        return lines + ["", f"Outcomes: {counts}", ""]

    def _measured_review_seconds(self) -> list:
        """How long the admin needed per decision (measured by review_cli.py, stored in the audit log)."""
        audit = self.log_dir / "audit_log.jsonl"
        values = []
        if audit.exists():
            for line in audit.read_text(encoding="utf-8").splitlines():
                if line.strip() and json.loads(line).get("review_seconds") is not None:
                    values.append(json.loads(line)["review_seconds"])
        return values

    def _time_section(self, summary) -> list:
        timed = [r["timing_sec"] for r in summary["emails"] if r["timing_sec"]]
        if not timed:
            return ["## 2. Time comparison", "", "No timing data available.", ""]
        avg = {k: sum(t[k] for t in timed) / len(timed) for k in ("extract", "scan", "plan", "total")}

        reviews = self._measured_review_seconds()
        human_sec, human_src = ((statistics.median(reviews), f"measured, median of {len(reviews)} decisions")
                                if reviews else (None, "assumption"))
        baseline = ManualTimeStudy.load(self.manual_baseline_path)
        has_baseline = bool(baseline and baseline.get("n") and baseline.get("mean_sec", 0) > 0)
        low, high = Config.MANUAL_MINUTES
        manual_sec, manual_src = ((baseline["mean_sec"], f"measured by hand on {baseline['n']} emails")
                                  if has_baseline else (None, f"cited research, {low}-{high} min"))

        cmp_ = self.time_comparison(avg["total"], human_sec, manual_sec)
        latency = ("Mock mode: no network latency is included, so real runs will be slower."
                   if summary["scan_mode"] == "MOCK"
                   else "Live mode: includes VirusTotal latency and rate-limit waits.")
        return [
            "## 2. Time comparison", "",
            f"- Manual baseline ({manual_src}): about {cmp_['manual_sec'] / 60:.1f} min per email",
            f"- Automated processing, average over {len(timed)} emails: {avg['total']:.3f}s "
            f"(extract {avg['extract']:.3f}s, scan {avg['scan']:.3f}s, plan {avg['plan']:.3f}s)",
            f"- Human review of a ready plan ({human_src}): {cmp_['human_sec']:.0f}s",
            f"- Estimated total per email: {cmp_['total_sec']:.1f}s",
            f"- **Estimated time saved: {cmp_['reduction_pct']}%** (project target: 80%)", "",
            f"Note: {latency} Manual baseline: {manual_src}. Human review: {human_src}. "
            "Measured values come from one person and a few simple dummy emails, so treat the figure as indicative.", "",
        ]

    def _scenario_section(self) -> list:
        lines = ["## 3. Scenario tests", ""]
        if not self.scenario_path.exists():
            return lines + ["Not run yet. Use `python run_demo.py`.", ""]
        for s in json.loads(self.scenario_path.read_text(encoding="utf-8")):
            lines += [f"**{s['id']} - {s['name']}: {'PASS' if s['passed'] else 'FAIL'}**", ""]
            lines += [f"- {'PASS' if c['passed'] else 'FAIL'}: {c['check']}" for c in s["checks"]] + [""]
        return lines

    def _accuracy_section(self) -> list:
        lines = ["## 4. Accuracy check", ""]
        if not self.accuracy_path.exists():
            return lines + ["Not run yet. Use `python evaluate.py`.", ""]
        result = json.loads(self.accuracy_path.read_text(encoding="utf-8"))
        return lines + [table_markdown(result)]

    def _comparison_section(self) -> list:
        lines = ["## 5. Single-agent baseline comparison", ""]
        if not self.comparison_path.exists():
            return lines + ["Not run yet. Use `python compare_agents.py` (needs an LLM key).", ""]
        return lines + [comparison_markdown(json.loads(self.comparison_path.read_text(encoding="utf-8")))]

    def _decisions_section(self) -> list:
        lines = ["## 6. Human decisions and feedback loop", ""]
        audit = self.log_dir / "audit_log.jsonl"
        decisions = Counter()
        if audit.exists():
            for line in audit.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    decisions[json.loads(line)["decision"]] += 1
        lines.append("Decisions in audit log: " + (", ".join(f"{k}: {v}" for k, v in decisions.items())
                                                   if decisions else "none yet"))
        entries = json.loads(self.safe_list.path.read_text(encoding="utf-8"))["entries"] \
            if self.safe_list.path.exists() else []
        lines += ["", "Safe List:" if entries else "Safe List: empty"]
        lines += [f"- {e['domain']} (from {e['origin_plan_id']}: {e['reason']})" for e in entries]
        return lines + [""]


def main() -> None:
    try:
        path = ReportBuilder().save()
    except FileNotFoundError as exc:
        print(exc)
        return
    print(f"Report written: {path}")


if __name__ == "__main__":
    main()
