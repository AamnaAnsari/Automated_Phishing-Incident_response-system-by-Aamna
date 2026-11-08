"""Inbox watcher: picks up new forwarded emails automatically (simulates the helpdesk inbox).

It watches a folder (data/emails/ by default). Every new .txt / .eml file is run through the pipeline.
A production version would poll the helpdesk mailbox through the Gmail / Outlook Graph API instead.
"""
import time
from pathlib import Path

from config import Config
from tools.email_loader import EmailLoader


class InboxWatcher:
    def __init__(self, pipeline, folder=None, settle_sec: float = 1.0):
        self.pipeline = pipeline
        self.folder = Path(folder or Config.EMAIL_DIR)
        self.settle_sec = settle_sec  # ignore files changed in the last N seconds (still being copied)
        self.loader = EmailLoader()
        self.seen = set()

    def scan_once(self) -> list:
        """Processes every file that has not been seen yet. Returns one record per new email."""
        records = []
        for path in sorted(self.folder.iterdir()):
            if path.suffix.lower() not in EmailLoader.SUPPORTED or path.name in self.seen:
                continue
            if time.time() - path.stat().st_mtime < self.settle_sec:
                continue  # try again on the next round
            self.seen.add(path.name)
            try:
                mail = self.loader.load(path)
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                self.pipeline.logs.pipeline(f"{path.stem} ERROR {message}")
                records.append({"email_id": path.stem, "outcome": "ERROR", "overall_risk": None,
                                "scan_status": None, "plan_id": None, "plan_path": None,
                                "rationale_source": None, "indicators_checked": 0,
                                "timing_sec": None, "error": message})
                continue
            records.append(self.pipeline.process(mail))
        return records

    def run(self, interval: float = 5.0, max_loops=None, on_record=None) -> None:
        loops = 0
        while max_loops is None or loops < max_loops:
            for record in self.scan_once():
                if on_record:
                    on_record(record)
            loops += 1
            if max_loops is None or loops < max_loops:
                time.sleep(interval)
