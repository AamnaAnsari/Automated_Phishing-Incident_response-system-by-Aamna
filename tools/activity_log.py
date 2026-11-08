"""Append-only logs: audit trail (JSONL), simulated firewall and pipeline log."""
import json
from datetime import datetime, timezone
from pathlib import Path

from config import Config


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ActivityLog:
    def __init__(self, log_dir=None):
        self.dir = Path(log_dir or Config.LOG_DIR)
        self.dir.mkdir(parents=True, exist_ok=True)

    def audit(self, record: dict) -> None:
        """One JSON line per human decision."""
        self._append("audit_log.jsonl", json.dumps({"ts": _now(), **record}))

    def firewall(self, plan_id: str, rule: str) -> None:
        """Simulated firewall: we only log the rule, nothing is really blocked."""
        self._append("firewall_sim.log", f"{_now()} [{plan_id}] {rule}")

    def pipeline(self, message: str) -> None:
        self._append("pipeline.log", f"{_now()} {message}")

    def _append(self, filename: str, line: str) -> None:
        with (self.dir / filename).open("a", encoding="utf-8") as f:
            f.write(line + "\n")
