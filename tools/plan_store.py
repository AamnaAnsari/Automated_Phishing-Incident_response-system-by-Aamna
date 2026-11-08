"""Storage for approval drafts: Needs_Action -> Approved / Rejected, plus Manual_Review."""
import json
from datetime import datetime, timezone
from pathlib import Path

from config import Config


class PlanStore:
    def __init__(self, root=None):
        if root:
            root = Path(root)
            self.needs_action = root / "Needs_Action"
            self.approved = root / "Approved"
            self.rejected = root / "Rejected"
            self.manual_review = root / "Manual_Review"
            self.resolved = root / "Resolved"
        else:
            self.needs_action = Config.NEEDS_ACTION_DIR
            self.approved = Config.APPROVED_DIR
            self.rejected = Config.REJECTED_DIR
            self.manual_review = Config.MANUAL_REVIEW_DIR
            self.resolved = Config.RESOLVED_DIR
        self.dirs = (self.needs_action, self.approved, self.rejected, self.manual_review, self.resolved)
        for d in self.dirs:
            d.mkdir(parents=True, exist_ok=True)

    def next_plan_id(self) -> str:
        """PLAN-YYYYMMDD-0001, 0002 ... (looks at every folder so ids never repeat)."""
        prefix = f"PLAN-{datetime.now(timezone.utc):%Y%m%d}-"
        numbers = [0]
        for folder in self.dirs:
            for path in folder.glob("*.json"):
                try:
                    plan_id = json.loads(path.read_text(encoding="utf-8")).get("plan_id", "")
                except ValueError:
                    continue
                if plan_id.startswith(prefix) and plan_id[len(prefix):].isdigit():
                    numbers.append(int(plan_id[len(prefix):]))
        return f"{prefix}{max(numbers) + 1:04d}"

    def save(self, plan: dict, folder: Path) -> Path:
        path = folder / f"{plan['plan_id']}_{plan['email_id']}.json"
        path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        return path

    def load(self, path) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def pending(self) -> list:
        """[(path, plan), ...] waiting for a human decision."""
        return [(p, self.load(p)) for p in sorted(self.needs_action.glob("*.json"))]

    def manual_queue(self) -> list:
        """[(path, plan), ...] emails that need a human because the API failed."""
        return [(p, self.load(p)) for p in sorted(self.manual_review.glob("*.json"))]

    def discard(self, email_id: str, folder: Path) -> None:
        """Removes old drafts of this email from `folder` (a re-run replaces them)."""
        for path in folder.glob("*.json"):
            if self.load(path).get("email_id") == email_id:
                path.unlink()

    def discard_pending(self, email_id: str) -> None:
        self.discard(email_id, self.needs_action)

    def move(self, path, plan: dict, dest_folder: Path) -> Path:
        """Writes the updated plan into dest_folder and removes the old file."""
        path = Path(path)
        dest = dest_folder / path.name
        dest.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        if dest != path:
            path.unlink()
        return dest
