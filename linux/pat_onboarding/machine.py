"""This machine: its facts (read from the OS, never from the portal or the user), and the three changes
the helper makes, in the proven order (ADR 0056/0058):

  1. TUNNEL - the pre-logon machine tunnel (openvpn-client@pat-machine, enabled at boot), with split
     DNS: only the AD domain resolves over the tunnel, everything else keeps the home resolver.
  2. PROVE the tunnel: `realm discover <domain>` must succeed over it. Linux has no offline join, so
     a tunnel that is merely installed is not enough - the join below is ONLINE.
  3. JOIN - hostname := the IT-assigned name, then pat.identity.{ca_trust, sssd_ad_join, pam_profile}
     run LOCALLY (ansible-playbook -c local): `realm join --one-time-password`, SSSD, PAM.

Every command goes through Runner, so the tests can see exactly what would run.
"""
import grp
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import time

from .trust import BUNDLE_MEMBERS

OPENVPN_CLIENT_DIR = "/etc/openvpn/client"
UNIT_NAME = "pat-machine"                                  # openvpn-client@pat-machine.service
CRED_DIR = os.path.join(OPENVPN_CLIENT_DIR, UNIT_NAME)     # 0700 root; the unit's cwd is OPENVPN_CLIENT_DIR
PROFILE = os.path.join(OPENVPN_CLIENT_DIR, UNIT_NAME + ".conf")
DNS_HOOK = "/usr/lib/pat-onboarding/tunnel-dns"           # shipped by the package
SUPPORTED = {"24.04", "26.04"}
REQUIRED_COMMANDS = ("openvpn", "realm", "adcli", "sssd", "ansible-playbook", "resolvectl", "hostnamectl")

INSTALLED_NAME = {"machine.crt": "machine-client.crt", "machine.key": "machine-client.key",
                  "machine-ca-bundle.pem": "machine-ca.pem", "machine-tc.key": "machine-tc.key"}


class MachineError(Exception):
    pass


class Runner:
    """Runs a command; a non-zero exit is an error unless check=False. Never echoes stdin."""
    def run(self, argv, check=True, input_text=None, timeout=600):
        r = subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise MachineError(f"{argv[0]} failed (exit {r.returncode}): {(r.stderr or r.stdout).strip()[-800:]}")
        return r


# --- facts ----------------------------------------------------------------------------------------

def bios_serial(path="/sys/class/dmi/id/product_serial"):
    try:
        with open(path) as fh:
            s = "".join(fh.read().split()).upper()
    except PermissionError as e:
        raise MachineError("cannot read the BIOS serial - run as root") from e
    if s in ("", "0", "DEFAULTSTRING", "TOBEFILLEDBYO.E.M.", "SYSTEMSERIALNUMBER", "NONE", "N/A"):
        raise MachineError(f"the BIOS serial '{s}' is a placeholder - this machine cannot be identified")
    return s


def os_release(path="/etc/os-release"):
    d = {}
    with open(path) as fh:
        for line in fh:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                d[k] = v.strip('"')
    return d


def local_admins(group_names=("sudo", "admin")):
    """The laptop's LOCAL administrators (uid >= 1000 in sudo/admin). They must stay on the sign-in
    allow-list: pam_access's closing deny-all matches local users too (pat-platform gotchas)."""
    out = set()
    for g in group_names:
        try:
            members = grp.getgrnam(g).gr_mem
        except KeyError:
            continue
        for m in members:
            try:
                if pwd.getpwnam(m).pw_uid >= 1000:
                    out.add(m)
            except KeyError:
                pass
    return sorted(out)


def preflight(runner, which=shutil.which, osr=None):
    """Refuse before anything changes. Returns the Ubuntu version."""
    if os.geteuid() != 0:
        raise MachineError("run as root (sudo)")
    osr = osr or os_release()
    if osr.get("ID") != "ubuntu" or osr.get("VERSION_ID") not in SUPPORTED:
        raise MachineError(f"unsupported OS {osr.get('ID')} {osr.get('VERSION_ID')} - Ubuntu {', '.join(sorted(SUPPORTED))} only")
    missing = [c for c in REQUIRED_COMMANDS if not which(c)]
    if missing:
        raise MachineError(f"missing: {', '.join(missing)} - the package's dependencies are not installed")
    if runner.run(["realm", "list", "--name-only"], check=False).stdout.strip():
        raise MachineError("this laptop is already joined to a domain")
    if runner.run(["systemctl", "is-active", "systemd-resolved"], check=False).stdout.strip() != "active":
        raise MachineError("systemd-resolved is not running - split DNS for the tunnel needs it")
    ntp = runner.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], check=False).stdout.strip()
    if ntp != "yes":
        raise MachineError("the clock is not NTP-synchronised - Kerberos refuses a clock more than 5 minutes off")
    # Any OTHER enabled machine-level OpenVPN profile would start its own tunnel at boot beside ours.
    units = runner.run(["systemctl", "list-unit-files", "--state=enabled", "--no-legend", "openvpn-client@*", "openvpn@*"],
                       check=False).stdout.split()
    foreign = [u for u in units if u.endswith(".service") and u != f"openvpn-client@{UNIT_NAME}.service"]
    if foreign:
        raise MachineError(f"other OpenVPN tunnels are enabled at boot: {', '.join(foreign)} - disable them first")
    if not local_admins():
        raise MachineError("no local administrator (uid >= 1000 in sudo) - there would be no way back in if the join failed")
    return osr["VERSION_ID"]


# --- 1. the tunnel ---------------------------------------------------------------------------------

def render_profile(server, port, tun_mtu):
    """The same directives as the Windows profile (Pat.Onboarding.Core.TunnelProfile), plus what Linux
    needs: the DNS hook, and a filter for the Windows-only push the concentrator sends."""
    if not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", server):
        raise MachineError("server is not a host name")
    d = UNIT_NAME
    return "\n".join([
        "# PAT company laptop machine tunnel - written by pat-onboarding. Starts at boot, before sign-in.",
        "client", "dev tun", "proto udp", f"remote {server} {port}", "resolv-retry infinite", "nobind",
        "persist-key", "persist-tun",
        f"ca {d}/machine-ca.pem", f"cert {d}/machine-client.crt", f"key {d}/machine-client.key",
        f"tls-crypt {d}/machine-tc.key",
        'remote-cert-eku "TLS Web Server Authentication"', f"verify-x509-name {server} name",
        "cipher AES-256-GCM", "data-ciphers AES-256-GCM", f"tun-mtu {tun_mtu}", "verb 3",
        # block-outside-dns is a Windows mechanism; on Linux the split below is the equivalent.
        'pull-filter ignore "block-outside-dns"',
        # ONE DNS mechanism on both releases: OpenVPN 2.6 (24.04) has no DNS hook of its own; 2.7 (26.04)
        # runs its built-in dns-updown unless told not to. 2.6 does not know the option - hence the ignore.
        "ignore-unknown-option dns-updown", "dns-updown disable",
        "script-security 2", f"up {DNS_HOOK}", f"down {DNS_HOOK}", "down-pre",
        "",
    ])


def install_tunnel(payload, runner, root="/"):
    cred = os.path.join(root, CRED_DIR.lstrip("/"))
    profile = os.path.join(root, PROFILE.lstrip("/"))
    os.makedirs(cred, mode=0o700, exist_ok=True)
    os.chmod(cred, 0o700)
    for m in BUNDLE_MEMBERS:
        _write_private(os.path.join(cred, INSTALLED_NAME[m]), payload.bundle[m])
    _write_private(profile, render_profile(payload.server, payload.port, payload.tun_mtu).encode())
    # read back: nothing broader than root, from a fresh stat
    for p in [cred, profile] + [os.path.join(cred, INSTALLED_NAME[m]) for m in BUNDLE_MEMBERS]:
        st = os.stat(p)
        if st.st_uid != 0 and os.geteuid() == 0:
            raise MachineError(f"{p} is not owned by root")
        if st.st_mode & 0o077:
            raise MachineError(f"{p} is readable beyond root (mode {oct(st.st_mode & 0o777)})")
    if root == "/":
        runner.run(["systemctl", "daemon-reload"])
        runner.run(["systemctl", "enable", "--now", f"openvpn-client@{UNIT_NAME}"])


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


# --- 2. prove it ------------------------------------------------------------------------------------

def wait_for_domain(domain, runner, timeout=120, sleep=time.sleep, clock=time.monotonic):
    """The tunnel is proven when the DOMAIN is discoverable through it - DNS SRV over the tunnel link
    and an LDAP answer from a DC. A failed tunnel stops here, before anything touches AD."""
    deadline = clock() + timeout
    last = ""
    while clock() < deadline:
        r = runner.run(["realm", "discover", "--name-only", domain], check=False, timeout=60)
        if r.returncode == 0 and r.stdout.strip().lower() == domain:
            return
        last = (r.stderr or r.stdout).strip()
        sleep(5)
    raise MachineError(f"the domain {domain} is not reachable through the tunnel after {timeout}s ({last[-300:]}). "
                       f"Nothing in the domain was changed. Check: journalctl -u openvpn-client@{UNIT_NAME}")


# --- 3. the join -------------------------------------------------------------------------------------

def set_hostname(name, runner, hosts="/etc/hosts"):
    """adcli names the computer account from the short hostname, so it MUST be the IT-assigned name."""
    host = name.lower()
    runner.run(["hostnamectl", "set-hostname", host])
    with open(hosts) as fh:
        lines = fh.read().splitlines()
    out, done = [], False
    for line in lines:
        if line.startswith("127.0.1.1"):
            if not done:
                out.append(f"127.0.1.1\t{host}")
                done = True
            continue
        out.append(line)
    if not done:
        out.append(f"127.0.1.1\t{host}")
    with open(hosts, "w") as fh:
        fh.write("\n".join(out) + "\n")


def join_vars(payload, admins):
    """The inputs to pat.identity for a laptop (the role README's 'Laptop mode' table)."""
    allow = sorted(set([payload.employee] + list(admins)))
    return {
        "pat_identity_ca_anchors": [{"name": "ad-root", "content": payload.ad_ca_pem}],
        "pat_identity_ad_domain": payload.domain,
        "pat_identity_ad_realm": payload.domain.upper(),
        "pat_identity_ad_join_otp": payload.otp,
        "pat_identity_manage_resolv_conf": False,       # split DNS over the tunnel, not a DC-pinned resolver
        "pat_identity_login_access_group": "",
        "pat_identity_login_access_users": allow,
        "pat_identity_pam_access": "simple_allow_groups",
        "pat_identity_allow_groups": [],
        "pat_identity_allow_users": allow,
        "pat_identity_mkhomedir": True,
    }


PLAYBOOK = """\
# pat-onboarding: the laptop's own join, run locally (ADR 0058). Roles vendored with the package.
- hosts: localhost
  connection: local
  gather_facts: true
  roles:
    - pat.identity.ca_trust
    - pat.identity.sssd_ad_join
    - pat.identity.pam_profile
"""


def run_join(payload, runner, collections, admins, rundir="/run"):
    """Vars (the OTP among them) go to a 0600 file on tmpfs, removed whatever happens."""
    work = tempfile.mkdtemp(prefix="pat-onboarding-", dir=rundir)
    os.chmod(work, 0o700)
    vars_path = os.path.join(work, "vars.json")
    try:
        _write_private(vars_path, json.dumps(join_vars(payload, admins)).encode())
        _write_private(os.path.join(work, "laptop.yml"), PLAYBOOK.encode())
        env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=collections, ANSIBLE_NOCOLOR="1",
                   ANSIBLE_RETRY_FILES_ENABLED="0", ANSIBLE_LOCAL_TEMP=os.path.join(work, "tmp"))
        r = subprocess.run(["ansible-playbook", "-i", "localhost,", "-e", "@" + vars_path,
                            os.path.join(work, "laptop.yml")], capture_output=True, text=True, env=env, timeout=1800)
        if r.returncode != 0:
            # no_log keeps the OTP out of this output; show the tail, where the failed task is
            raise MachineError("the domain join playbook failed:\n" + r.stdout[-3000:])
        return r.stdout
    finally:
        shutil.rmtree(work, ignore_errors=True)
