"""Simulated notifications: replies to the reporting employee and escalations to the IT team.

Nothing is sent. Each message is saved as a small text file so the behaviour can be shown and tested.
"""
from pathlib import Path

from config import Config

EMPLOYEE_TEXT = {
    "SAFE_AUTO": "Our automated check found no known threats in this email. "
                 "If it still looks suspicious to you, please tell the IT team.",
    "APPROVED": "IT confirmed that this email is phishing and the malicious links and senders are being blocked. "
                "Please delete it and do not click any link in it.",
    "REJECTED": "IT reviewed this email and found it legitimate, so it is safe to use. Thank you for checking.",
    "RESOLVED_THREAT": "After a manual check, IT confirmed that this email is phishing. "
                       "Please delete it and do not click any link in it.",
    "RESOLVED_SAFE": "After a manual check, IT found this email legitimate. It is safe to use.",
    "MANUAL_PENDING": "We could not finish the automatic check, so the IT team will review this email by hand. "
                      "Until you hear back, please do not click any link in it.",
}


class Notifier:
    def __init__(self, out_dir=None):
        self.dir = Path(out_dir or Config.BASE_DIR / "outputs" / "notifications")
        self.dir.mkdir(parents=True, exist_ok=True)

    def employee_reply(self, email_id: str, subject: str, kind: str, plan_id: str = None) -> Path:
        """Closes the loop with the employee who reported the email."""
        lines = [f"To: {Config.REPORTER_PLACEHOLDER}", f"From: {Config.SECURITY_MAILBOX}",
                 f"Subject: Re: {subject}"]
        if plan_id:
            lines.append(f"Reference: {plan_id}")
        lines += ["", "Hello,", "", EMPLOYEE_TEXT[kind], "", "IT Security Team",
                  "", "(Simulated message: saved to a file, nothing was sent.)"]
        return self._write(f"to_employee_{email_id}.txt", lines)

    def escalate_to_it(self, plan: dict) -> Path:
        """Forwards an email that could not be checked automatically to the human IT team."""
        lines = [f"To: {Config.IT_TEAM_ADDRESS}", f"From: {Config.SECURITY_MAILBOX}",
                 f"Subject: [{plan['tag']}] {plan['subject']}", f"Reference: {plan['plan_id']}", "",
                 f"Sender : {plan['sender']['address']}", f"Summary: {plan['summary']}",
                 f"Already flagged indicators: {len(plan['proposed_actions'])}", "",
                 "Please review this email manually: python review_cli.py",
                 "", "(Simulated message: saved to a file, nothing was sent.)"]
        return self._write(f"to_it_team_{plan['email_id']}.txt", lines)

    def _write(self, filename: str, lines: list) -> Path:
        path = self.dir / filename
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
