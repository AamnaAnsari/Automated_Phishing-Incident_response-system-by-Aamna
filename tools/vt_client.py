"""VirusTotal v3 client: mock mode, rate limiting, timeout/retry and clean error types."""
import base64
import json
import sys
import time
from collections import deque
from urllib.parse import urlparse
from pathlib import Path

import requests

from config import Config

STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected")
RETRYABLE = {"TIMEOUT", "NETWORK", "SERVER"}


class VTError(Exception):
    """kind: TIMEOUT | NETWORK | SERVER | RATE_LIMIT | AUTH | BAD_RESPONSE"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind, self.message = kind, message

    def to_dict(self) -> dict:
        return {"type": self.kind, "message": self.message}


class RateLimiter:
    """Sliding window: at most `max_calls` requests per `period` seconds."""

    def __init__(self, max_calls, period=60.0, clock=time.monotonic, sleep=time.sleep):
        self.max_calls, self.period, self.clock, self.sleep = max_calls, period, clock, sleep
        self.calls = deque()

    def _purge(self):
        now = self.clock()
        while self.calls and now - self.calls[0] >= self.period:
            self.calls.popleft()

    def wait(self):
        self._purge()
        if len(self.calls) >= self.max_calls:
            self.sleep(self.period - (self.clock() - self.calls[0]))
            self._purge()
        self.calls.append(self.clock())


class VTClient:
    def __init__(self, mock=None, api_key=None, session=None, limiter=None, mock_file=None, sleep=time.sleep):
        self.mock = Config.MOCK_MODE if mock is None else mock
        self.api_key = Config.VT_API_KEY if api_key is None else api_key
        self.session = session or requests
        self.limiter = limiter or RateLimiter(Config.VT_REQUESTS_PER_MIN)
        self.sleep = sleep
        self.fixtures = self._load_fixtures(mock_file or Config.MOCK_FILE) if self.mock else {}

    @property
    def mode(self) -> str:
        return "MOCK" if self.mock else "LIVE"

    def scan(self, indicator: str, kind: str) -> dict:
        """kind = 'url' | 'domain' | 'ip'. Returns {malicious, suspicious, harmless, undetected}.
        Raises VTError on any API problem (callers decide what to do)."""
        if kind not in ("url", "domain", "ip"):
            raise ValueError(f"Unknown indicator type: {kind}")
        return self._scan_mock(indicator, kind) if self.mock else self._scan_live(indicator, kind)

    # ---------- mock ----------
    @staticmethod
    def _load_fixtures(path) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def _scan_mock(self, indicator, kind) -> dict:
        entries = self.fixtures.get("indicators", {})
        host = urlparse(indicator).hostname if kind == "url" else None
        for key in (indicator, host):
            if key and key in entries:
                entry = entries[key]
                if "error" in entry:
                    raise VTError(entry["error"], f"Simulated {entry['error']} (mock fixture)")
                return self._stats(entry)
        return self._stats(self.fixtures.get("default", {}))

    # ---------- live ----------
    def _scan_live(self, indicator, kind) -> dict:
        if not self.api_key:
            raise VTError("AUTH", "VT_API_KEY is empty. Add it to .env or use MOCK_MODE=true.")
        url, last = self._endpoint(indicator, kind), None

        for attempt in range(Config.VT_RETRIES + 1):
            self.limiter.wait()
            try:
                resp = self.session.get(url, headers={"x-apikey": self.api_key}, timeout=Config.VT_TIMEOUT_SEC)
                return self._parse(resp)
            except requests.exceptions.Timeout:
                last = VTError("TIMEOUT", f"No answer within {Config.VT_TIMEOUT_SEC}s")
            except requests.exceptions.RequestException as exc:
                last = VTError("NETWORK", f"{type(exc).__name__}: {exc}")
            except VTError as err:
                if err.kind not in RETRYABLE:
                    raise  # 401 / 429 / bad response will not fix themselves
                last = err
            if attempt < Config.VT_RETRIES:
                self.sleep(1 + attempt)  # small back-off before retrying
        raise last

    @staticmethod
    def _endpoint(indicator, kind) -> str:
        base = Config.VT_BASE_URL
        if kind == "url":
            ident = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            return f"{base}/urls/{ident}"
        return f"{base}/{'domains' if kind == 'domain' else 'ip_addresses'}/{indicator}"

    def _parse(self, resp) -> dict:
        code = resp.status_code
        if code == 404:
            return self._stats({})  # never seen by VirusTotal -> no detections
        if code in (401, 403):
            raise VTError("AUTH", f"HTTP {code}: invalid or unauthorised API key")
        if code == 429:
            raise VTError("RATE_LIMIT", "HTTP 429: free-tier quota reached")
        if code >= 500:
            raise VTError("SERVER", f"HTTP {code}: VirusTotal server error")
        if code != 200:
            raise VTError("BAD_RESPONSE", f"Unexpected HTTP {code}")
        try:
            return self._stats(resp.json()["data"]["attributes"]["last_analysis_stats"])
        except (ValueError, KeyError, TypeError):
            raise VTError("BAD_RESPONSE", "Response did not contain last_analysis_stats")

    @staticmethod
    def _stats(raw: dict) -> dict:
        return {k: int(raw.get(k, 0)) for k in STAT_KEYS}


if __name__ == "__main__":
    # python -m tools.vt_client domain malicious-phishing-test.com
    kind, value = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ("domain", "malicious-phishing-test.com")
    client = VTClient()
    try:
        print(client.mode, kind, value, "->", client.scan(value, kind))
    except VTError as err:
        print(client.mode, kind, value, "-> API_ERROR", err.to_dict())
