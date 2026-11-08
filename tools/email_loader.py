"""Reads .txt and .eml files into a simple EmailData object."""
from dataclasses import dataclass, field
from email import message_from_string
from email.policy import default
from email.utils import parseaddr
from pathlib import Path


@dataclass
class EmailData:
    email_id: str
    source_file: str
    sender_name: str
    sender_address: str
    subject: str
    body: str
    headers: dict = field(default_factory=dict)  # extra headers that may hold IPs


class EmailLoader:
    """Both .txt (with headers) and .eml are RFC-822 style, so one parser works."""

    SUPPORTED = {".txt", ".eml"}
    IP_HEADERS = ("X-Originating-IP", "Received", "X-Forwarded-For")

    def load(self, path) -> EmailData:
        path = Path(path)
        if path.suffix.lower() not in self.SUPPORTED:
            raise ValueError(f"Unsupported file type: {path.suffix}")

        raw = path.read_text(encoding="utf-8", errors="ignore")
        msg = message_from_string(raw, policy=default)
        name, address = parseaddr(str(msg.get("From", "")))

        return EmailData(
            email_id=path.stem,
            source_file=str(path),
            sender_name=name,
            sender_address=address.lower(),
            subject=str(msg.get("Subject", "")),
            body=self._get_body(msg),
            headers={h: str(msg[h]) for h in self.IP_HEADERS if msg[h]},
        )

    def load_all(self, folder) -> list:
        files = sorted(p for p in Path(folder).iterdir() if p.suffix.lower() in self.SUPPORTED)
        return [self.load(p) for p in files]

    @staticmethod
    def _get_body(msg) -> str:
        part = msg.get_body(preferencelist=("plain", "html"))
        return part.get_content() if part else ""
