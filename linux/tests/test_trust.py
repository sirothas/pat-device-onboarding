"""Every trust decision tested BOTH ways: the genuine case is accepted, and each forgery refused.
Mirrors tests/Pat.Onboarding.Core.Tests/TrustTests.cs, plus the Linux-only pins (ADR 0058)."""
import base64
import hashlib
import io
import json
import os
import sys
import unittest
import zipfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from pat_onboarding import keys  # noqa: E402
from pat_onboarding.trust import TrustError, TrustedKey, accept_payload, verify_tenant  # noqa: E402

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)
PORTAL = "https://iip.example.test"
SERIAL = "9639-2453-0768-1493-1196-5648-92"
OTP = "AbCdEfGhJkMnPqRsTuVwXyZ234567892"
REPO = os.path.join(os.path.dirname(__file__), "..", "..")


def self_signed(cn):
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - timedelta(days=1))
         .not_valid_after(NOW + timedelta(days=365)).sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER), c.public_bytes(serialization.Encoding.PEM).decode()


def h(b):
    return hashlib.sha256(b).hexdigest()


class Fx:
    def __init__(self):
        self.pat = ec.generate_private_key(ec.SECP256R1())
        n = self.pat.public_key().public_numbers()
        self.trusted = TrustedKey("pat-tenant-test-1", n.x.to_bytes(32, "big").hex(), n.y.to_bytes(32, "big").hex())
        self.mca_der, self.mca_pem = self_signed("test machine CA")
        self.aca_der, self.aca_pem = self_signed("test AD root CA")

    def doc(self, **over):
        d = dict(v=1, tenant="example-demo", portal=PORTAL, concentrator="odj.example.test",
                 machine_ca_sha256=h(self.mca_der), not_after="2027-09-25T00:00:00Z",
                 ad_domain="demo.example.test", ad_ca_sha256=h(self.aca_der))
        d.update(over)
        return {k: v for k, v in d.items() if v is not None}

    def envelope(self, doc=None, signer=None, kid="pat-tenant-test-1", tamper=None):
        d = json.dumps(doc or self.doc()).encode()
        r, s = decode_dss_signature((signer or self.pat).sign(d, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")        # IEEE P1363, as the portal serves it
        if tamper:
            d = tamper(d)
        return json.dumps({"kid": kid, "doc": base64.b64encode(d).decode(), "sig": base64.b64encode(sig).decode()})

    def tenant(self):
        return verify_tenant(self.envelope(), self.trusted, PORTAL, NOW)

    def bundle(self, mca_pem=None, extra=False, drop=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n, c in (("machine.crt", "CERT"), ("machine.key", "KEY"),
                         ("machine-ca-bundle.pem", mca_pem or self.mca_pem), ("machine-tc.key", "TC")):
                if n != drop:
                    z.writestr(n, c)
            if extra:
                z.writestr("evil.so", "x")
        return buf.getvalue()

    def token(self, bundle=None, corrupt=False, **over):
        b = bundle or self.bundle()
        r = dict(os="linux", serial=SERIAL, name="DMO1L0002", server="odj.example.test", port=1195, tun_mtu=1400,
                 domain="demo.example.test", employee="satishs", otp=OTP, ad_ca_pem=self.aca_pem,
                 bundle_sha256=("0" * 64) if corrupt else h(b).upper(), bundle_b64=base64.b64encode(b).decode())
        r.update(over)
        return json.dumps({k: v for k, v in r.items() if v is not None})


class TenantDocumentTests(unittest.TestCase):
    def setUp(self):
        self.f = Fx()

    def refuses(self, env, portal=PORTAL, now=NOW, match=None):
        with self.assertRaises(TrustError) as cm:
            verify_tenant(env, self.f.trusted, portal, now)
        if match:
            self.assertIn(match, str(cm.exception))

    def test_genuine_document_is_accepted(self):
        t = self.f.tenant()
        self.assertEqual(t.concentrator, "odj.example.test")
        self.assertEqual(t.ad_domain, "demo.example.test")
        self.assertEqual(t.ad_ca_sha256, h(self.f.aca_der))

    def test_tampered_document_is_refused(self):
        def flip(d):
            b = bytearray(d)
            b[10] ^= 1
            return bytes(b)
        self.refuses(self.f.envelope(tamper=flip), match="NOT valid")

    def test_other_key_is_refused(self):
        self.refuses(self.f.envelope(signer=ec.generate_private_key(ec.SECP256R1())), match="NOT valid")

    def test_unknown_kid_is_refused(self):
        self.refuses(self.f.envelope(kid="someone-else"), match="not the one this installer trusts")

    def test_document_for_another_portal_is_refused(self):
        self.refuses(self.f.envelope(), portal="https://evil.example.test", match="not https://evil")

    def test_other_port_is_refused(self):
        self.refuses(self.f.envelope(), portal="https://iip.example.test:8443")

    def test_http_portal_is_refused(self):
        self.refuses(self.f.envelope(self.f.doc(portal="http://iip.example.test")), portal="http://iip.example.test")

    def test_expired_document_is_refused(self):
        self.refuses(self.f.envelope(), now=datetime(2027, 9, 25, tzinfo=timezone.utc), match="expired")

    def test_document_without_ad_domain_is_refused_for_linux(self):
        self.refuses(self.f.envelope(self.f.doc(ad_domain=None)), match="not enrolled for Linux")

    def test_document_without_ad_ca_is_refused_for_linux(self):
        self.refuses(self.f.envelope(self.f.doc(ad_ca_sha256=None)), match="not enrolled for Linux")

    def test_wrong_version_is_refused(self):
        self.refuses(self.f.envelope(self.f.doc(v=2)), match="version")

    def test_garbage_envelope_is_refused(self):
        self.refuses("{not json", match="not a valid envelope")

    def test_short_signature_is_refused(self):
        env = json.loads(self.f.envelope())
        env["sig"] = base64.b64encode(b"\x01" * 63).decode()
        self.refuses(json.dumps(env), match="NOT valid")


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.f = Fx()
        self.t = self.f.tenant()

    def refuses(self, token, serial=SERIAL, match=None):
        with self.assertRaises(TrustError) as cm:
            accept_payload(token, serial, self.t)
        if match:
            self.assertIn(match, str(cm.exception))

    def test_genuine_payload_is_accepted(self):
        p = accept_payload(self.f.token(), SERIAL, self.t)
        self.assertEqual(p.name, "DMO1L0002")
        self.assertEqual(p.otp, OTP)
        self.assertEqual(sorted(p.bundle), sorted(["machine.crt", "machine.key", "machine-ca-bundle.pem", "machine-tc.key"]))
        self.assertNotIn(OTP, repr(p))            # never in a log line by accident

    def test_serial_is_compared_normalised(self):
        accept_payload(self.f.token(), " 9639-2453-0768-1493-1196-5648-92 ".lower(), self.t)

    def test_another_machines_payload_is_refused(self):
        self.refuses(self.f.token(), serial="0000-1111", match="this machine is")

    def test_windows_payload_is_refused(self):
        self.refuses(self.f.token(os="windows"), match="not linux")

    def test_payload_without_os_is_refused(self):
        self.refuses(self.f.token(os=None), match="not linux")

    def test_other_concentrator_is_refused(self):
        self.refuses(self.f.token(server="evil.example.test"), match="signed tenant document says")

    def test_other_domain_is_refused(self):
        self.refuses(self.f.token(domain="evil.example.test"), match="joins evil.example.test")

    def test_bad_name_is_refused(self):
        self.refuses(self.f.token(name="dmo1l0002; rm -rf /"), match="not a valid laptop name")

    def test_bad_employee_is_refused(self):
        self.refuses(self.f.token(employee="satishs\nroot"), match="employee")

    def test_bad_otp_is_refused(self):
        self.refuses(self.f.token(otp="short"), match="one-time password")

    def test_otp_with_ambiguous_characters_is_refused(self):
        self.refuses(self.f.token(otp="O" * 32), match="one-time password")

    def test_out_of_range_mtu_is_refused(self):
        self.refuses(self.f.token(tun_mtu=9000), match="MTU")

    def test_corrupt_bundle_hash_is_refused(self):
        self.refuses(self.f.token(corrupt=True), match="does not match its hash")

    def test_extra_bundle_member_is_refused(self):
        self.refuses(self.f.token(bundle=self.f.bundle(extra=True)), match="unexpected member")

    def test_missing_bundle_member_is_refused(self):
        self.refuses(self.f.token(bundle=self.f.bundle(drop="machine-tc.key")), match="has no machine-tc.key")

    def test_substituted_machine_ca_is_refused(self):
        _, other = self_signed("attacker CA")
        self.refuses(self.f.token(bundle=self.f.bundle(mca_pem=other)), match="machine CA")

    def test_substituted_ad_ca_is_refused(self):
        _, other = self_signed("attacker AD CA")
        self.refuses(self.f.token(ad_ca_pem=other), match="AD CA")

    def test_malformed_payload_is_refused(self):
        self.refuses("[]", match="malformed")


class InteropTests(unittest.TestCase):
    """The envelope tools/sign-tenant-document.py produced for the C# interop test (DEV key, v1, no Linux
    pins) must pass SIGNATURE verification here - it is refused only for lacking ad_domain/ad_ca_sha256.
    A one-bit change must fail the signature instead. Same file the Windows tests read."""
    ENV = os.path.join(REPO, "tests", "Pat.Onboarding.Core.Tests", "Data", "python-signed-envelope.json")

    def test_python_signed_envelope_passes_the_signature_check(self):
        with open(self.ENV) as fh:
            env = fh.read()
        with self.assertRaises(TrustError) as cm:
            verify_tenant(env, keys.CURRENT, PORTAL, NOW)
        self.assertIn("not enrolled for Linux", str(cm.exception))    # got past kid, signature, portal, expiry

    def test_one_bit_flip_fails_the_signature(self):
        with open(self.ENV) as fh:
            env = json.load(fh)
        sig = bytearray(base64.b64decode(env["sig"]))
        sig[5] ^= 1
        env["sig"] = base64.b64encode(bytes(sig)).decode()
        with self.assertRaises(TrustError) as cm:
            verify_tenant(json.dumps(env), keys.CURRENT, PORTAL, NOW)
        self.assertIn("NOT valid", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
