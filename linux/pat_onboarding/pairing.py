"""The helper's half of the device-code pairing (RFC 8628 shape; the portal's /odj/pair and
/odj/pair/token). A port of src/Pat.Onboarding.Core/PairingClient.cs - same endpoints, same error
handling, same rule that the approval page must be on the portal the tenant document vouched for.

The device code is a bearer secret: it lives only in this object and is never logged.
Standard library only (Ubuntu Desktop ships no curl - checked on 24.04 and 26.04).
"""
import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .trust import TrustError


class PairingError(Exception):
    pass


@dataclass
class Started:
    device_code: str = field(repr=False)
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class PairingClient:
    def __init__(self, portal, opener=None, timeout=30):
        if urlsplit(portal).scheme != "https":
            raise ValueError("the portal must be https")
        self.portal = portal
        self.timeout = timeout
        # The system trust store (the portal's certificate is a public one). No verification is ever
        # turned off: the tenant document is the SECOND check, not a replacement for TLS.
        self._open = opener or urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context())).open

    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(urljoin(self.portal, path), data=data, method=method,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self._open(req, timeout=self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def get_tenant_envelope(self):
        status, text = self._req("GET", "/.well-known/pat-onboarding.json")
        if status != 200:
            raise TrustError(f"the portal has no PAT tenant document (HTTP {status}) - it is not an enrolled portal")
        return text

    def start(self, serial):
        status, text = self._req("POST", "/odj/pair", {"serial": serial})
        if status != 200:
            raise PairingError(_error(text) or f"HTTP {status}")
        try:
            e = json.loads(text)
            s = Started(device_code=e["device_code"], user_code=e["user_code"],
                        verification_uri=e["verification_uri"],
                        verification_uri_complete=e["verification_uri_complete"],
                        expires_in=int(e["expires_in"]), interval=max(2, int(e["interval"])))
        except Exception as exc:  # noqa: BLE001
            raise PairingError("the portal's pairing answer is malformed") from exc
        # The approval page must be on the SAME portal the tenant document vouched for - a portal that
        # sent the employee elsewhere to approve is not one to trust.
        host = (urlsplit(self.portal).hostname or "").lower()
        for u in (s.verification_uri, s.verification_uri_complete):
            if (urlsplit(u).hostname or "").lower() != host or urlsplit(u).scheme != "https":
                raise TrustError("the portal's approval link points at a different host")
        return s

    def poll(self, s, on_waiting=None, sleep=time.sleep, clock=time.monotonic):
        """Poll until approved; returns the token response JSON (the payload) once. RFC 8628 3.5:
        authorization_pending keeps waiting, slow_down backs off by 5 s."""
        deadline = clock() + s.expires_in + 30
        interval = s.interval
        while clock() < deadline:
            sleep(interval)
            status, text = self._req("POST", "/odj/pair/token", {"device_code": s.device_code})
            if status == 200:
                s.device_code = ""
                return text
            err = _error(text)
            if err == "authorization_pending":
                if on_waiting:
                    on_waiting()
                continue
            if err == "slow_down":
                interval += 5
                continue
            if err == "expired_token":
                raise PairingError("the code expired before it was approved - start again")
            if err == "access_denied":
                raise PairingError("the portal refused to release this laptop's configuration "
                                   "(already delivered, or not assigned to you) - ask IT")
            raise PairingError(f"unexpected answer from the portal (HTTP {status})")
        raise PairingError("no approval before the code expired - start again")


def _error(text):
    try:
        v = json.loads(text)
        return v.get("error") if isinstance(v, dict) else None
    except ValueError:
        return None
