import base64
import unittest

import requests

from tools.vt_client import RateLimiter, VTClient, VTError


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code, self._payload = status, payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def ok(stats):
    return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": stats}}})


class FakeSession:
    """Returns / raises the queued items one by one, like a scripted VirusTotal."""

    def __init__(self, *items):
        self.items, self.calls = list(items), []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers, timeout))
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def live(session):
    return VTClient(mock=False, api_key="k", session=session,
                    limiter=RateLimiter(1000), sleep=lambda s: None)


class TestMockMode(unittest.TestCase):
    def setUp(self):
        self.client = VTClient(mock=True)

    def test_malicious_domain(self):
        self.assertEqual(self.client.scan("malicious-phishing-test.com", "domain")["malicious"], 14)

    def test_url_falls_back_to_its_domain(self):
        r = self.client.scan("http://malicious-phishing-test.com/verify", "url")
        self.assertEqual(r["malicious"], 14)

    def test_unknown_indicator_is_clean(self):
        self.assertEqual(self.client.scan("https://www.python.org/about/", "url")["malicious"], 0)

    def test_simulated_timeout(self):
        with self.assertRaises(VTError) as ctx:
            self.client.scan("timeout-test.com", "domain")
        self.assertEqual(ctx.exception.kind, "TIMEOUT")


class TestLiveMode(unittest.TestCase):
    STATS = {"malicious": 2, "suspicious": 1, "harmless": 50, "undetected": 5, "timeout": 0}

    def test_parses_stats(self):
        r = live(FakeSession(ok(self.STATS))).scan("1.2.3.4", "ip")
        self.assertEqual(r, {"malicious": 2, "suspicious": 1, "harmless": 50, "undetected": 5})

    def test_endpoints_and_api_key_header(self):
        s = FakeSession(ok(self.STATS), ok(self.STATS), ok(self.STATS))
        c = live(s)
        c.scan("http://a.test/x", "url"); c.scan("a.test", "domain"); c.scan("1.2.3.4", "ip")
        ident = base64.urlsafe_b64encode(b"http://a.test/x").decode().rstrip("=")
        self.assertTrue(s.calls[0][0].endswith("/urls/" + ident))
        self.assertTrue(s.calls[1][0].endswith("/domains/a.test"))
        self.assertTrue(s.calls[2][0].endswith("/ip_addresses/1.2.3.4"))
        self.assertEqual(s.calls[0][1], {"x-apikey": "k"})

    def test_404_means_no_detections(self):
        self.assertEqual(live(FakeSession(FakeResponse(404))).scan("new.test", "domain")["malicious"], 0)

    def test_auth_error_no_retry(self):
        s = FakeSession(FakeResponse(401))
        with self.assertRaises(VTError) as ctx:
            live(s).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "AUTH")
        self.assertEqual(len(s.calls), 1)

    def test_rate_limit_error(self):
        with self.assertRaises(VTError) as ctx:
            live(FakeSession(FakeResponse(429))).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "RATE_LIMIT")

    def test_server_error_then_success_retries(self):
        s = FakeSession(FakeResponse(503), ok(self.STATS))
        self.assertEqual(live(s).scan("a.test", "domain")["malicious"], 2)
        self.assertEqual(len(s.calls), 2)

    def test_server_error_twice_fails(self):
        with self.assertRaises(VTError) as ctx:
            live(FakeSession(FakeResponse(500), FakeResponse(500))).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "SERVER")

    def test_timeout_fails_after_retry(self):
        s = FakeSession(requests.exceptions.Timeout(), requests.exceptions.Timeout())
        with self.assertRaises(VTError) as ctx:
            live(s).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "TIMEOUT")
        self.assertEqual(len(s.calls), 2)

    def test_connection_error_is_network(self):
        s = FakeSession(requests.exceptions.ConnectionError("boom"), requests.exceptions.ConnectionError("boom"))
        with self.assertRaises(VTError) as ctx:
            live(s).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "NETWORK")

    def test_bad_json_is_bad_response(self):
        with self.assertRaises(VTError) as ctx:
            live(FakeSession(FakeResponse(200, None))).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "BAD_RESPONSE")

    def test_missing_key(self):
        with self.assertRaises(VTError) as ctx:
            VTClient(mock=False, api_key="", session=FakeSession()).scan("a.test", "domain")
        self.assertEqual(ctx.exception.kind, "AUTH")


class TestRateLimiter(unittest.TestCase):
    def test_fifth_call_waits_for_the_window(self):
        t = {"now": 0.0}
        slept = []

        def fake_sleep(sec):
            slept.append(sec)
            t["now"] += sec

        limiter = RateLimiter(4, 60.0, clock=lambda: t["now"], sleep=fake_sleep)
        for _ in range(4):
            limiter.wait()
        self.assertEqual(slept, [])
        t["now"] = 10.0
        limiter.wait()  # 5th call inside the same minute
        self.assertEqual(slept, [50.0])


if __name__ == "__main__":
    unittest.main()
