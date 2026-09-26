"""The machine layer without touching this machine: what it would write and run."""
import json
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pat_onboarding import machine  # noqa: E402
from pat_onboarding.machine import MachineError  # noqa: E402

OTP = "AbCdEfGhJkMnPqRsTuVwXyZ234567892"


def payload(**over):
    p = dict(serial="S1", name="DMO1L0002", server="odj.example.test", port=1195, tun_mtu=1400,
             domain="demo.example.test", employee="satishs", otp=OTP, ad_ca_pem="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
             bundle={"machine.crt": b"C", "machine.key": b"K", "machine-ca-bundle.pem": b"CA", "machine-tc.key": b"T"})
    p.update(over)
    return SimpleNamespace(**p)


class FakeRunner:
    def __init__(self, answers=None):
        self.calls, self.answers = [], list(answers or [])

    def run(self, argv, check=True, input_text=None, timeout=600):
        self.calls.append(argv)
        rc, out = self.answers.pop(0) if self.answers else (0, "")
        return SimpleNamespace(returncode=rc, stdout=out, stderr="")


class ProfileTests(unittest.TestCase):
    def test_profile_carries_the_windows_directives_and_the_linux_ones(self):
        t = machine.render_profile("odj.example.test", 1195, 1400).splitlines()
        for line in ("remote odj.example.test 1195", "tls-crypt pat-machine/machine-tc.key",
                     'remote-cert-eku "TLS Web Server Authentication"', "verify-x509-name odj.example.test name",
                     "tun-mtu 1400", 'pull-filter ignore "block-outside-dns"', "dns-updown disable",
                     "script-security 2", "up /usr/lib/pat-onboarding/tunnel-dns"):
            self.assertIn(line, t)
        # the ignore must come BEFORE the option 2.6 does not know
        self.assertLess(t.index("ignore-unknown-option dns-updown"), t.index("dns-updown disable"))

    def test_profile_refuses_a_non_host_server(self):
        with self.assertRaises(MachineError):
            machine.render_profile("odj.example.test\nup /bin/sh", 1195, 1400)


class TunnelInstallTests(unittest.TestCase):
    def test_credentials_and_profile_are_root_only(self):
        with tempfile.TemporaryDirectory() as root:
            r = FakeRunner()
            machine.install_tunnel(payload(), r, root=root)
            cred = os.path.join(root, "etc/openvpn/client/pat-machine")
            self.assertEqual(stat.S_IMODE(os.stat(cred).st_mode), 0o700)
            self.assertEqual(sorted(os.listdir(cred)), ["machine-ca.pem", "machine-client.crt", "machine-client.key", "machine-tc.key"])
            for f in os.listdir(cred):
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(cred, f)).st_mode), 0o600)
            with open(os.path.join(cred, "machine-client.key"), "rb") as fh:
                self.assertEqual(fh.read(), b"K")
            self.assertEqual(r.calls, [])          # a non-/ root never touches systemd


class DomainWaitTests(unittest.TestCase):
    def test_waits_until_the_domain_answers(self):
        r = FakeRunner([(1, ""), (1, ""), (0, "demo.example.test\n")])
        machine.wait_for_domain("demo.example.test", r, sleep=lambda _: None, clock=lambda: 0)
        self.assertEqual(r.calls[-1], ["realm", "discover", "--name-only", "demo.example.test"])

    def test_gives_up_with_the_journal_hint(self):
        r = FakeRunner([(1, "")] * 5)
        t = iter([0, 0, 0, 10_000])
        with self.assertRaises(MachineError) as cm:
            machine.wait_for_domain("demo.example.test", r, timeout=60, sleep=lambda _: None, clock=lambda: next(t))
        self.assertIn("Nothing in the domain was changed", str(cm.exception))

    def test_another_domains_answer_is_not_success(self):
        r = FakeRunner([(0, "evil.example.test\n")] * 3)
        t = iter([0, 0, 0, 10_000])
        with self.assertRaises(MachineError):
            machine.wait_for_domain("demo.example.test", r, timeout=60, sleep=lambda _: None, clock=lambda: next(t))


class HostnameTests(unittest.TestCase):
    def test_hostname_and_hosts_line(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("127.0.0.1\tlocalhost\n127.0.1.1\tLABVL0002\n::1\tip6-localhost\n")
        try:
            r = FakeRunner()
            machine.set_hostname("DMO1L0002", r, hosts=fh.name)
            self.assertEqual(r.calls, [["hostnamectl", "set-hostname", "dmo1l0002"]])
            with open(fh.name) as h:
                lines = h.read().splitlines()
            self.assertIn("127.0.1.1\tdmo1l0002", lines)
            self.assertNotIn("127.0.1.1\tLABVL0002", lines)
            self.assertIn("::1\tip6-localhost", lines)
        finally:
            os.unlink(fh.name)


class JoinVarsTests(unittest.TestCase):
    def test_laptop_inputs(self):
        v = machine.join_vars(payload(), ["labadmin"])
        self.assertEqual(v["pat_identity_ad_join_otp"], OTP)
        self.assertEqual(v["pat_identity_ad_realm"], "DEMO.EXAMPLE.TEST")
        self.assertFalse(v["pat_identity_manage_resolv_conf"])
        self.assertEqual(v["pat_identity_login_access_group"], "")          # not the server default group
        self.assertEqual(v["pat_identity_login_access_users"], ["labadmin", "satishs"])
        self.assertEqual(v["pat_identity_allow_users"], ["labadmin", "satishs"])   # local admin kept in
        self.assertTrue(v["pat_identity_mkhomedir"])
        self.assertIs(v["pat_identity_ad_dyndns_update"], False)             # pooled tunnel address
        json.dumps(v)   # serialisable into the vars file


if __name__ == "__main__":
    unittest.main()
