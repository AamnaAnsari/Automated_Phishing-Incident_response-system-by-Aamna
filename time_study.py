"""Manual baseline time study: measure how long the OLD manual workflow takes, by hand, on our dummy emails.

Run:  python time_study.py                      (3 default emails)
      python time_study.py sample_clean_01 ...  (choose emails)
Result: outputs/logs/manual_baseline.json, used by generate_report.py instead of the cited 23-27 minutes.
"""
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from config import Config

DEFAULT_EMAILS = ["sample_malicious_01", "sample_clean_01", "sample_malicious_02"]
MIN_REAL_SECONDS = 10  # a manual check cannot take less; shorter entries are a mis-pressed Enter


class ManualTimeStudy:
    def __init__(self, path=None):
        self.path = Path(path or Config.LOG_DIR / "manual_baseline.json")
        self.records = []

    def record(self, email_id: str, seconds: float) -> None:
        self.records.append({"email_id": email_id, "seconds": round(seconds, 1)})

    def summary(self) -> dict:
        times = [r["seconds"] for r in self.records]
        return {"n": len(times),
                "mean_sec": round(statistics.mean(times), 1) if times else None,
                "median_sec": round(statistics.median(times), 1) if times else None}

    def save(self) -> str:
        data = {"schema": "manual_baseline_v1",
                "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "records": self.records, **self.summary()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(self.path)

    @staticmethod
    def load(path=None):
        """Returns the saved study, or None if it was never run."""
        path = Path(path or Config.LOG_DIR / "manual_baseline.json")
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def main() -> None:
    emails = sys.argv[1:] or DEFAULT_EMAILS
    study = ManualTimeStudy()
    print("MANUAL TIME STUDY: do the old workflow BY HAND and let the stopwatch run.\n")
    print("For each email: open the file, copy every link / IP address, check each one on")
    print("https://www.virustotal.com, decide, then write the firewall block rule and a one-line")
    print("reply to the employee (in Notepad). Work at your normal speed.\n")
    for email_id in emails:
        path = next(iter(sorted(Config.EMAIL_DIR.glob(f"{email_id}.*"))), None)
        if path is None:
            print(f"Skipping {email_id}: file not found in {Config.EMAIL_DIR}")
            continue
        input(f"Next email: {path.name}\nPress Enter to START the clock ...")
        started = time.perf_counter()
        input("Press Enter when you have decided and written the rule and the reply ...")
        seconds = time.perf_counter() - started
        if seconds < MIN_REAL_SECONDS:
            print(f"  {email_id}: only {seconds:.0f} s, too short to be real work. Not saved, run it again.\n")
            continue
        study.record(email_id, seconds)
        print(f"  {email_id}: {seconds:.0f} s\n")
    if not study.records:
        print("Nothing recorded.")
        return
    summary = study.summary()
    print(f"Saved {study.save()}")
    print(f"{summary['n']} emails, mean {summary['mean_sec']} s, median {summary['median_sec']} s per email")


if __name__ == "__main__":
    main()
