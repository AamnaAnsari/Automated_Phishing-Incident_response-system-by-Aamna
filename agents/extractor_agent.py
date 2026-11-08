"""Data Extractor Agent: regex extraction + optional LLM validation (schema A)."""
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import Config
from tools.email_loader import EmailData, EmailLoader


class ExtractorAgent:
    URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
    EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    IP_RE = re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
    )
    TRAILING = ".,;:!?"

    def __init__(self, validator=None):
        self.validator = validator  # IndicatorValidator or None (= regex only)

    def extract(self, email: EmailData) -> dict:
        text = email.body
        header_text = " ".join(email.headers.values())

        indicators = {
            "urls": self._find_urls(text),
            "ips": self._unique(self.IP_RE.findall(text + " " + header_text)),
            "email_addresses": self._unique(
                [e.lower() for e in self.EMAIL_RE.findall(text)] + [email.sender_address]
            ),
        }

        notes, removed = "Regex only (LLM validation not used).", {}
        if self.validator:
            indicators, report = self.validator.validate(email, indicators)
            notes, removed = report["notes"], report["removed"]

        return {
            "schema": "extractor_output_v1",
            "email_id": email.email_id,
            "source_file": email.source_file,
            "extracted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sender": {
                "address": email.sender_address,
                "display_name": email.sender_name,
                "domain": email.sender_address.split("@")[-1] if "@" in email.sender_address else "",
            },
            "subject": email.subject,
            "indicators": indicators,
            "extraction_notes": notes,
            "removed_false_positives": removed,
            "counts": {
                "urls": len(indicators["urls"]),
                "ips": len(indicators["ips"]),
                "emails": len(indicators["email_addresses"]),
            },
        }

    def save(self, result: dict, folder=None) -> str:
        folder = folder or Config.EXTRACTED_DIR
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{result['email_id']}.json"
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return str(path)

    def _find_urls(self, text: str) -> list:
        found = [u.rstrip(self.TRAILING) for u in self.URL_RE.findall(text)]
        return [{"value": u, "domain": urlparse(u).hostname or ""} for u in self._unique(found)]

    @staticmethod
    def _unique(items) -> list:
        return list(dict.fromkeys(items))  # removes duplicates, keeps order


if __name__ == "__main__":
    validator = None
    if "--llm" in sys.argv:
        from agents.validator import IndicatorValidator
        validator = IndicatorValidator.from_config()

    loader, agent = EmailLoader(), ExtractorAgent(validator)
    for mail in loader.load_all(Config.EMAIL_DIR):
        result = agent.extract(mail)
        agent.save(result)
        print(f"{mail.email_id:<24} -> {result['counts']}  | {result['extraction_notes']}")
