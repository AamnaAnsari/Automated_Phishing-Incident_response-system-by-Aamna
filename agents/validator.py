"""LLM validator: removes obvious false positives from the regex results.

LCEL chain:  prompt | llm.with_structured_output(ValidationResult)
Safety rules (enforced in code, not just in the prompt):
  * the LLM can only REMOVE indicators, never add new ones
  * it can only remove values that regex really found
  * a removal is accepted only if a code rule also agrees (placeholder domains, loopback IPs)
  * the sender address is never removed
  * if the LLM fails for any reason, the regex results are kept
"""
import json
from typing import List
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ValidationResult(BaseModel):
    """Indicators that are clearly harmless noise and should be removed."""

    false_urls: List[str] = Field(default_factory=list, description="URLs to remove, copied exactly from the input")
    false_ips: List[str] = Field(default_factory=list, description="IP addresses to remove, copied exactly")
    false_emails: List[str] = Field(default_factory=list, description="Email addresses to remove, copied exactly")
    reason: str = Field(default="", description="One short sentence explaining the removals")


SYSTEM_PROMPT = (
    "You help a security team clean indicator lists extracted from a forwarded suspicious email. "
    "Return ONLY the items that are clearly harmless noise and should be removed. "
    "Remove: placeholder domains such as example.com, example.org or example.net; "
    "loopback or unspecified IPs (127.x.x.x, 0.0.0.0) and the broadcast IP 255.255.255.255; "
    "obvious template text such as your-name@domain.com. "
    "Never remove a link that asks the reader to click, log in, verify, download or pay. "
    "Never invent new items and copy values exactly as given. "
    "When in doubt, KEEP the item (return empty lists)."
)

HUMAN_PROMPT = (
    "Sender: {sender}\nSubject: {subject}\n\nEmail body:\n{body}\n\n"
    "Extracted indicators (JSON):\n{indicators}"
)


PLACEHOLDER_DOMAINS = ("example.com", "example.org", "example.net")
PLACEHOLDER_IPS = ("0.0.0.0", "255.255.255.255")


def _is_noise_domain(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in PLACEHOLDER_DOMAINS)


def _is_noise_ip(ip: str) -> bool:
    return ip in PLACEHOLDER_IPS or ip.startswith("127.")


def _is_noise_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return _is_noise_domain(host) or _is_noise_ip(host)


def _is_noise_email(addr: str) -> bool:
    return _is_noise_domain(addr.split("@")[-1])


class IndicatorValidator:
    def __init__(self, chain):
        self.chain = chain  # any object with .invoke(dict) -> ValidationResult | dict

    @classmethod
    def from_config(cls) -> "IndicatorValidator":
        from langchain_core.prompts import ChatPromptTemplate

        from tools.llm_factory import get_llm

        prompt = ChatPromptTemplate.from_messages([("system", SYSTEM_PROMPT), ("human", HUMAN_PROMPT)])
        return cls(prompt | get_llm().with_structured_output(ValidationResult))

    def validate(self, email, indicators: dict) -> tuple:
        """Returns (cleaned_indicators, report). Never raises."""
        if not indicators["urls"] and not indicators["ips"] and len(indicators["email_addresses"]) <= 1:
            return indicators, {"removed": {}, "notes": "Nothing to validate (no URLs or IPs)."}

        try:
            verdict = self.chain.invoke({
                "sender": email.sender_address,
                "subject": email.subject,
                "body": email.body[:4000],
                "indicators": json.dumps(indicators),
            })
            if isinstance(verdict, dict):
                verdict = ValidationResult(**verdict)
        except Exception as exc:  # API down, bad key, parse error ...
            return indicators, {"removed": {}, "notes": f"LLM validation skipped ({type(exc).__name__}); regex results kept."}

        # The LLM only SUGGESTS; a removal is accepted only if a code rule also calls it noise.
        urls = [u for u in indicators["urls"]
                if not (u["value"] in verdict.false_urls and _is_noise_url(u["value"]))]
        ips = [i for i in indicators["ips"]
               if not (i in verdict.false_ips and _is_noise_ip(i))]
        emails = [e for e in indicators["email_addresses"]
                  if e == email.sender_address or not (e in verdict.false_emails and _is_noise_email(e))]

        removed = {
            "urls": [u["value"] for u in indicators["urls"] if u not in urls],
            "ips": [i for i in indicators["ips"] if i not in ips],
            "email_addresses": [e for e in indicators["email_addresses"] if e not in emails],
        }
        n = sum(len(v) for v in removed.values())
        notes = f"LLM validation removed {n} false positive(s)." + (f" {verdict.reason}" if n else "")
        cleaned = {"urls": urls, "ips": ips, "email_addresses": emails}
        return cleaned, {"removed": removed, "notes": notes}
