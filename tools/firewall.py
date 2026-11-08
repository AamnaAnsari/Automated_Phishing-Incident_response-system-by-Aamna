"""Firewall adapter for approved block plans.

Nothing is pushed to a live firewall. Approving a plan does two things:
  1. every rule is written to firewall_sim.log (audit trail), and
  2. the blocked targets are exported as plain-text lists (one entry per line) in outputs/firewall/:
     blocked_domains.txt, blocked_ips.txt, blocked_urls.txt
Firewalls and DNS filters can import such lists (for example as an "external list" / "dynamic list");
check your firewall's documentation for the exact format it expects.
"""
import ipaddress
from pathlib import Path


class Firewall:
    def __init__(self, logs, out_dir=None):
        self.logs = logs
        self.dir = Path(out_dir or logs.dir.parent / "firewall")
        self.dir.mkdir(parents=True, exist_ok=True)

    def apply(self, plan: dict) -> dict:
        """Logs the rules of an approved plan and exports the blocklists. Returns new entries per list."""
        entries = {"domains": set(), "ips": set(), "urls": set()}
        for action in plan["proposed_actions"]:
            self.logs.firewall(plan["plan_id"], action["simulated_firewall_rule"])
            for kind, value in self._targets(action):
                entries[kind].add(value)
        return {kind: self._merge(f"blocked_{kind}.txt", new) for kind, new in entries.items()}

    # ---------- helpers ----------
    @classmethod
    def _targets(cls, action: dict) -> list:
        if action["action"] == "BLOCK_IP":
            return [("ips", action["target"])]
        if action["action"] == "BLOCK_SENDER_DOMAIN":
            return [("domains", action["domain"])]
        host = action.get("domain") or ""
        found = [("urls", action["target"])]
        if host:
            found.append((cls._host_kind(host), host))  # a URL on a bare IP blocks that IP
        return found

    @staticmethod
    def _host_kind(host: str) -> str:
        try:
            ipaddress.ip_address(host)
            return "ips"
        except ValueError:
            return "domains"

    def _merge(self, filename: str, new: set) -> int:
        """Adds entries to the list without duplicates. Returns how many were really new."""
        path = self.dir / filename
        existing = set(path.read_text(encoding="utf-8").split()) if path.exists() else set()
        fresh = {e for e in new if e and e not in existing}
        if fresh:
            path.write_text("\n".join(sorted(existing | fresh)) + "\n", encoding="utf-8")
        return len(fresh)
