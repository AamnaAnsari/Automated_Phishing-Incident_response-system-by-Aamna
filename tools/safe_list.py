"""Safe List: domains a human admin rejected as false positives (schema D)."""
import json
from datetime import datetime, timezone
from pathlib import Path

from config import Config


class SafeList:
    def __init__(self, path=None):
        self.path = Path(path or Config.SAFE_LIST_FILE)

    def contains(self, domain: str) -> bool:
        """True for the domain itself or any of its subdomains (www.x.com matches x.com)."""
        domain = self._normalize(domain)
        return bool(domain) and any(domain == d or domain.endswith("." + d) for d in self.domains())

    def add(self, domain, plan_id=None, reason="", added_by="admin", source="HUMAN_REJECTION") -> bool:
        """Adds a domain. Returns False if it was already on the list."""
        domain = self._normalize(domain)
        if not domain or domain in self.domains():
            return False
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        data = self._load()
        data["entries"].append({
            "domain": domain,
            "added_by": added_by,
            "added_at": now,
            "source": source,
            "origin_plan_id": plan_id,
            "reason": reason,
        })
        data["last_updated"] = now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True

    def domains(self) -> set:
        return {e["domain"] for e in self._load()["entries"]}

    def _load(self) -> dict:
        if not self.path.exists():
            return {"schema": "safe_list_v1", "last_updated": None, "entries": []}
        return json.loads(self.path.read_text(encoding="utf-8"))

    @staticmethod
    def _normalize(domain) -> str:
        return (domain or "").strip().lower().rstrip(".")