"""Scanner Agent: checks extracted indicators with VirusTotal (schema B).

Pure Python on purpose: the risk level comes from thresholds in config.py, not from an LLM.
"""
import json
import sys
import time
from datetime import datetime, timezone

from config import Config
from tools.safe_list import SafeList
from tools.vt_client import VTClient, VTError

RISK_RANK = {"Safe": 0, "Suspicious": 1, "Malicious": 2}


class ScannerAgent:
    def __init__(self, client=None, safe_list=None):
        self.client = client or VTClient()
        self.safe_list = safe_list or SafeList()

    @staticmethod
    def classify(stats: dict) -> str:
        if stats["malicious"] >= Config.MALICIOUS_MIN:
            return "Malicious"
        if stats["malicious"] >= Config.SUSPICIOUS_MALICIOUS_MIN or stats["suspicious"] >= Config.SUSPICIOUS_MIN:
            return "Suspicious"
        return "Safe"

    def scan(self, extracted: dict) -> dict:
        """Takes schema A, returns schema B. Never crashes on API problems."""
        started = time.perf_counter()
        results, error = [], None

        for value, kind, domain in self._targets(extracted):
            if domain and self.safe_list.contains(domain):
                results.append(self._entry(value, kind, domain, None, "Safe", "IN_SAFE_LIST"))
                continue
            try:
                stats = self.client.scan(value, kind)
            except VTError as err:
                error = {**err.to_dict(), "failed_indicator": value}
                break  # stop here; the Planner sends the email to manual review
            results.append(self._entry(value, kind, domain, stats, self.classify(stats)))

        return {
            "schema": "scanner_output_v1",
            "email_id": extracted["email_id"],
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scan_status": self._status(results, error),
            "scan_mode": getattr(self.client, "mode", "UNKNOWN"),
            "error": error,
            "sender": extracted["sender"],
            "subject": extracted["subject"],
            "results": results,
            "overall_risk": self._overall(results, error),
            "duration_sec": round(time.perf_counter() - started, 3),
        }

    def save(self, result: dict, folder=None) -> str:
        folder = folder or Config.SCANS_DIR
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{result['email_id']}.json"
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return str(path)

    # ---------- helpers ----------
    @staticmethod
    def _targets(extracted: dict) -> list:
        """(value, type, domain) for every URL, IP and the sender domain."""
        ind = extracted["indicators"]
        targets = [(u["value"], "url", u["domain"]) for u in ind["urls"]]
        targets += [(ip, "ip", None) for ip in ind["ips"]]
        sender = extracted["sender"]["domain"]
        if sender and sender not in {u["domain"] for u in ind["urls"]}:
            targets.append((sender, "domain", sender))  # lookalike sender domains matter too
        return targets

    @staticmethod
    def _entry(value, kind, domain, stats, risk, skipped=None) -> dict:
        return {"indicator": value, "type": kind, "domain": domain,
                "skipped_reason": skipped, "vt_stats": stats, "risk_level": risk}

    @staticmethod
    def _status(results, error) -> str:
        if not error:
            return "COMPLETE"
        return "PARTIAL" if results else "API_ERROR"

    @staticmethod
    def _overall(results, error) -> str:
        worst = max((r["risk_level"] for r in results), key=RISK_RANK.get, default="Safe")
        if error and worst != "Malicious":
            return "Unknown"  # we could not check everything, so we cannot call it safe
        return worst


if __name__ == "__main__":
    # Full Extractor -> Scanner run:  python -m agents.scanner_agent [--llm]
    from agents.extractor_agent import ExtractorAgent
    from tools.email_loader import EmailLoader

    validator = None
    if "--llm" in sys.argv:
        from agents.validator import IndicatorValidator
        validator = IndicatorValidator.from_config()

    extractor, scanner = ExtractorAgent(validator), ScannerAgent()
    print(f"Scan mode: {scanner.client.mode}\n")
    for mail in EmailLoader().load_all(Config.EMAIL_DIR):
        extracted = extractor.extract(mail)
        extractor.save(extracted)
        scan = scanner.scan(extracted)
        scanner.save(scan)
        print(f"{mail.email_id:<22} {scan['scan_status']:<10} overall={scan['overall_risk']:<10} "
              f"({len(scan['results'])} indicators, {scan['duration_sec']}s)")
