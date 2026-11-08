"""Human-in-the-loop logic: approve or reject a pending plan, or close a manual-review case."""
import getpass
from datetime import datetime, timezone

from tools.activity_log import ActivityLog
from tools.firewall import Firewall
from tools.notifier import Notifier
from tools.plan_store import PlanStore
from tools.safe_list import SafeList


class ReviewService:
    def __init__(self, store=None, safe_list=None, logs=None, actor=None, notifier=None, firewall=None):
        self.store = store or PlanStore()
        self.safe_list = safe_list or SafeList()
        self.logs = logs or ActivityLog()
        self.actor = actor or getpass.getuser()
        self.notifier = notifier or Notifier(self.logs.dir.parent / "notifications")
        self.firewall = firewall or Firewall(self.logs)

    def pending(self) -> list:
        return self.store.pending()

    def manual_queue(self) -> list:
        return self.store.manual_queue()

    def approve(self, path, reason: str = "", review_sec=None) -> dict:
        """Approved: apply the (simulated) firewall rules and archive the plan.
        review_sec = how long the admin needed to decide (measured by the console tool)."""
        plan = self._open(path)
        self.firewall.apply(plan)
        self._finish(path, plan, "APPROVED", reason, self.store.approved, [], review_sec)
        return plan

    def reject(self, path, reason: str = "", domains=None, review_sec=None) -> dict:
        """Rejected: the chosen domains go to the Safe List so they are not flagged again.
        domains=None means every domain in the plan; domains=[] means none."""
        plan = self._open(path)
        candidates = sorted({a["domain"] for a in plan["proposed_actions"] if a.get("domain")})
        chosen = candidates if domains is None else [d for d in domains if d in candidates]
        added = [d for d in chosen if self.safe_list.add(
            d, plan_id=plan["plan_id"], added_by=self.actor,
            reason=reason or "Rejected by admin as false positive")]
        self._finish(path, plan, "REJECTED", reason, self.store.rejected, added, review_sec)
        return plan

    def resolve_manual(self, path, verdict: str, reason: str = "", review_sec=None) -> dict:
        """Closes a Needs-Manual-Review case after the admin checked it by hand.
        verdict: 'THREAT' (indicators already flagged are blocked) or 'SAFE'."""
        verdict = verdict.upper()
        if verdict not in ("THREAT", "SAFE"):
            raise ValueError("verdict must be THREAT or SAFE")
        plan = self._open(path, expected="NEEDS_MANUAL_REVIEW")
        if verdict == "THREAT":
            self.firewall.apply(plan)
        self._finish(path, plan, f"RESOLVED_{verdict}", reason, self.store.resolved, [], review_sec)
        return plan

    # ---------- helpers ----------
    def _open(self, path, expected: str = "PENDING_APPROVAL") -> dict:
        plan = self.store.load(path)
        if plan["status"] != expected:
            raise ValueError(f"{plan['plan_id']} is {plan['status']}, expected {expected}")
        return plan

    def _finish(self, path, plan, decision, reason, dest_folder, safe_list_added, review_sec=None) -> None:
        seconds = round(review_sec, 1) if review_sec is not None else None
        plan["status"] = decision
        plan["human_decision"] = {
            "decision": decision,
            "decided_by": self.actor,
            "decided_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "reason": reason or None,
            "safe_list_added": safe_list_added,
            "review_seconds": seconds,
        }
        self.store.move(path, plan, dest_folder)
        self.logs.audit({
            "plan_id": plan["plan_id"],
            "email_id": plan["email_id"],
            "decision": decision,
            "actor": self.actor,
            "targets": [a["target"] for a in plan["proposed_actions"]],
            "reason": reason or None,
            "safe_list_added": safe_list_added,
            "review_seconds": seconds,
        })
        self.logs.pipeline(f"{plan['email_id']} {decision} {plan['plan_id']} by {self.actor}")
        self.notifier.employee_reply(plan["email_id"], plan["subject"], decision, plan["plan_id"])
