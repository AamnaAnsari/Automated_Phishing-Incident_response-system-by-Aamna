"""Central configuration: paths, thresholds and API settings."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    BASE_DIR = Path(__file__).resolve().parent

    # Folders
    EMAIL_DIR = BASE_DIR / "data" / "emails"
    EXTRACTED_DIR = BASE_DIR / "outputs" / "extracted"
    SCANS_DIR = BASE_DIR / "outputs" / "scans"
    LOG_DIR = BASE_DIR / "outputs" / "logs"
    NEEDS_ACTION_DIR = BASE_DIR / "storage" / "Needs_Action"
    APPROVED_DIR = BASE_DIR / "storage" / "Approved"
    REJECTED_DIR = BASE_DIR / "storage" / "Rejected"
    MANUAL_REVIEW_DIR = BASE_DIR / "storage" / "Manual_Review"
    RESOLVED_DIR = BASE_DIR / "storage" / "Resolved"      # manual-review cases a human has closed
    SAFE_LIST_FILE = BASE_DIR / "storage" / "Safe_List.json"
    REPORT_DIR = BASE_DIR / "outputs" / "reports"
    DEMO_DIR = BASE_DIR / "outputs" / "demo_run"      # isolated workspace for run_demo.py
    EVAL_DIR = BASE_DIR / "outputs" / "eval_run"      # isolated workspace for evaluate.py
    TRUTH_FILE = BASE_DIR / "data" / "ground_truth.json"

    # Keys / modes
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq")
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")
    LLM_MODEL = os.getenv("LLM_MODEL", "")   # optional override
    MOCK_MODE = os.getenv("MOCK_MODE", "true").lower() == "true"

    # VirusTotal free tier: 4 requests/minute
    VT_REQUESTS_PER_MIN = 4
    VT_TIMEOUT_SEC = 10
    VT_RETRIES = 1           # extra attempts for timeout / network / 5xx
    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    MOCK_FILE = BASE_DIR / "data" / "mock_vt_responses.json"

    # Risk thresholds
    MALICIOUS_MIN = 3             # >= 3 malicious engines -> Malicious
    SUSPICIOUS_MALICIOUS_MIN = 2  # 2 malicious engines -> Suspicious (a single one is treated as noise)
    SUSPICIOUS_MIN = 3            # >= 3 "suspicious" engines -> Suspicious

    # Simulated notifications (files only, nothing is really sent)
    SECURITY_MAILBOX = "it-security@examplecorp.com"
    IT_TEAM_ADDRESS = "it-team@examplecorp.com"
    REPORTER_PLACEHOLDER = "reporting-employee@examplecorp.com"  # dummy emails do not record who forwarded them

    # Report: manual baseline from the proposal's reference (23-27 min per phishing email)
    MANUAL_MINUTES = (23, 27)
    HUMAN_REVIEW_SEC_ASSUMED = 60   # assumption: admin needs ~1 minute to approve/reject a ready plan

    @classmethod
    def ensure_dirs(cls) -> None:
        for d in (cls.EXTRACTED_DIR, cls.SCANS_DIR, cls.LOG_DIR, cls.NEEDS_ACTION_DIR,
                  cls.APPROVED_DIR, cls.REJECTED_DIR, cls.MANUAL_REVIEW_DIR, cls.RESOLVED_DIR):
            d.mkdir(parents=True, exist_ok=True)
