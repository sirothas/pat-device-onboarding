"""The pairing client against a scripted portal: the RFC 8628 states, and the host-binding refusals."""
import io
import json
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pat_onboarding.pairing import PairingClient, PairingError  # noqa: E402
from pat_onboarding.trust import TrustError  # noqa: E402

PORTAL = "https://iip.example.test"


class Resp(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(json.dumps(body).encode() if not isinstance(body, str) else body.encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Portal:
    """Answers each request from a script; records what was sent."""
    def __init__(self, script):
        self.script = list(script)
        self.sent = []

    def open(self, req, timeout=None):
        self.sent.append((req.get_method(), req.full_url, json.loads(req.data) if req.data else None))
        status, body = self.script.pop(0)
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(json.dumps(body).encode()))
        return Resp(status, body)


START = {"device_code": "DEV-SECRET", "user_code": "QJRH-KFZC", "verification_uri": PORTAL + "/odj/approve",
         "verification_uri_complete": PORTAL + "/odj/approve?code=QJRH-KFZC", "expires_in": 600, "interval": 5}


class PairingTests(unittest.TestCase):
    def client(self, script):
        p = Portal(script)
        return PairingClient(PORTAL, opener=p.open), p

    def test_http_portal_is_refused(self):
        with self.assertRaises(ValueError):
            PairingClient("http://iip.example.test")

    def test_missing_tenant_document_is_a_trust_error(self):
        c, _ = self.client([(404, {"error": "not found"})])
        with self.assertRaises(TrustError):
            c.get_tenant_envelope()

    def test_start_sends_the_serial_and_parses(self):
        c, p = self.client([(200, START)])
        s = c.start("SER-1")
        self.assertEqual(p.sent[0], ("POST", PORTAL + "/odj/pair", {"serial": "SER-1"}))
        self.assertEqual(s.user_code, "QJRH-KFZC")
        self.assertNotIn("DEV-SECRET", repr(s))

    def test_approval_link_on_another_host_is_refused(self):
        bad = dict(START, verification_uri_complete="https://evil.example.test/approve")
        c, _ = self.client([(200, bad)])
        with self.assertRaises(TrustError):
            c.start("SER-1")

    def test_poll_waits_backs_off_then_returns_the_payload_once(self):
        c, p = self.client([(200, START), (400, {"error": "authorization_pending"}),
                            (400, {"error": "slow_down"}), (200, {"os": "linux"})])
        s = c.start("SER-1")
        slept, waits = [], []
        body = c.poll(s, on_waiting=lambda: waits.append(1), sleep=slept.append, clock=lambda: 0)
        self.assertEqual(json.loads(body), {"os": "linux"})
        self.assertEqual(slept, [5, 5, 10])                      # slow_down added 5 s
        self.assertEqual(waits, [1])
        self.assertEqual(p.sent[1][2], {"device_code": "DEV-SECRET"})
        self.assertEqual(s.device_code, "")                      # dropped once used

    def test_denied_is_a_pairing_error(self):
        c, _ = self.client([(200, START), (400, {"error": "access_denied"})])
        with self.assertRaises(PairingError) as cm:
            c.poll(c.start("S"), sleep=lambda _: None, clock=lambda: 0)
        self.assertIn("ask IT", str(cm.exception))

    def test_expired_is_a_pairing_error(self):
        c, _ = self.client([(200, START), (400, {"error": "expired_token"})])
        with self.assertRaises(PairingError):
            c.poll(c.start("S"), sleep=lambda _: None, clock=lambda: 0)

    def test_deadline_ends_the_poll(self):
        c, _ = self.client([(200, START)] + [(400, {"error": "authorization_pending"})] * 3)
        t = iter([0, 0, 10_000])
        with self.assertRaises(PairingError):
            c.poll(c.start("S"), sleep=lambda _: None, clock=lambda: next(t))


if __name__ == "__main__":
    unittest.main()
