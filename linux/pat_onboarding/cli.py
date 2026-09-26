"""pat-onboarding - join this Ubuntu laptop to the company domain (pat-platform ADR 0058).

    sudo pat-onboarding --portal https://iip.example.com
    sudo pat-onboarding --portal https://iip.example.com --payload-file payload.json   # IT-delivered

The whole onboarding, in the proven order: verify everything first; TUNNEL before JOIN (a tunnel
without a join is harmless and retryable); PROVE the tunnel reaches the domain before anything touches
AD; then the join. Nothing secret is written anywhere except the tunnel's own credentials (root, 0600)
and, for the seconds the join runs, a 0600 vars file on tmpfs.
"""
import argparse
import os
import sys
from datetime import datetime, timezone

from . import __version__, keys, machine
from .pairing import PairingClient, PairingError
from .trust import TrustError, accept_payload, verify_tenant

DEFAULT_COLLECTIONS = "/usr/share/pat-onboarding/collections"
PORTAL_FILE = "/etc/pat-onboarding/portal"
LOG_DIR = "/var/log/pat-onboarding"


class Log:
    """Plain text under /var/log/pat-onboarding. Never a secret: no device code, payload, key or OTP."""
    def __init__(self):
        os.makedirs(LOG_DIR, mode=0o750, exist_ok=True)
        self.path = os.path.join(LOG_DIR, datetime.now(timezone.utc).strftime("onboarding-%Y%m%dT%H%M%SZ.log"))

    def __call__(self, m, show=True):
        if show:
            print(m, flush=True)
        try:
            with open(self.path, "a") as fh:
                fh.write(f"{datetime.now(timezone.utc).isoformat()} {m}\n")
        except OSError:
            pass


def configured_portal():
    try:
        with open(PORTAL_FILE) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def run(args, runner, say):
    # 1. this machine - read from the OS
    ubuntu = machine.preflight(runner)
    serial = machine.bios_serial()
    admins = machine.local_admins()
    say(f"This laptop's serial number: {serial} (Ubuntu {ubuntu})")

    # 2. the portal - believed only with PAT's signature, and only for itself
    client = PairingClient(args.portal)
    tenant = verify_tenant(client.get_tenant_envelope(), keys.CURRENT, args.portal)
    say(f"Portal verified: {args.portal} (tenant {tenant.tenant}, domain {tenant.ad_domain}, signed by PAT)")

    # 3. pairing - or a payload IT handed over (same checks either way)
    if args.payload_file:
        with open(args.payload_file) as fh:
            token = fh.read()
        say(f"Using the configuration IT provided ({args.payload_file})")
    else:
        started = client.start(serial)
        say("")
        say(f"    Your code:  {started.user_code}")
        say(f"    Open {started.verification_uri_complete}")
        say("    Sign in with your company account, check the laptop name and serial, and approve.")
        say("")
        token = client.poll(started, on_waiting=lambda: print(".", end="", flush=True))
        print()

    # 4. the payload - bound to this machine and this tenant before anything is touched
    payload = accept_payload(token, serial, tenant)
    token = None
    if args.payload_file:
        try:
            os.remove(args.payload_file)       # it held a one-time password
        except OSError:
            pass
    say(f"Approved - configuration for {payload.name}, domain {payload.domain}, for {payload.employee}")
    try:
        # 5. tunnel first
        say("Installing the secure connection that starts before sign-in...")
        machine.install_tunnel(payload, runner)
        # 6. prove it
        say(f"Waiting for the company network ({payload.domain}) through it...")
        machine.wait_for_domain(payload.domain, runner)
        say("Company network reachable.")
        # 7. join
        say(f"Joining this laptop to {payload.domain} as {payload.name}...")
        machine.set_hostname(payload.name, runner)
        machine.run_join(payload, runner, args.collections, admins)
    finally:
        payload.wipe()
    say(f"Joined. Local administrator(s) kept: {', '.join(admins)}")
    say("ONBOARDING-OK", show=False)
    return payload.name


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pat-onboarding", description="Join this Ubuntu laptop to the company domain.")
    ap.add_argument("--portal", default=None, help="the https:// portal address IT gave you")
    ap.add_argument("--payload-file", default=None, help="a configuration file IT delivered (instead of pairing)")
    ap.add_argument("--collections", default=DEFAULT_COLLECTIONS, help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)
    args.portal = args.portal or configured_portal()
    if not args.portal or not args.portal.startswith("https://"):
        ap.error("give the https:// portal address IT gave you (--portal)")

    if keys.IS_DEVELOPMENT_KEY:
        print("[DEVELOPMENT BUILD - trusts the PAT development tenant key]", flush=True)
    say = Log()
    say(f"pat-onboarding {__version__} started", show=False)
    try:
        run(args, machine.Runner(), say)
    except TrustError as e:
        say(f"REFUSED - {e}")
        say(f"Nothing on this laptop was changed. Log: {say.path}")
        return 3
    except (PairingError, machine.MachineError, OSError) as e:
        say(f"FAILED: {e}")
        say(f"Log: {say.path}")
        return 1
    except KeyboardInterrupt:
        say("Stopped.")
        return 130
    print()
    print("Done. Restart, wait a minute at the sign-in screen, choose 'Not listed?',")
    print("and sign in with your company account name and password.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
