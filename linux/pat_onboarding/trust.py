"""Every trust decision the Linux helper makes, before anything touches the operating system.

The same rules as the Windows core (src/Pat.Onboarding.Core/TenantDocument.cs, Payload.cs), because a
laptop is only as safe as the weaker of the two installers:

  * A portal is believed only if it serves a tenant document SIGNED BY PAT, and only for the portal
    named inside it. Otherwise anyone who can point the installer at their own portal can have the
    laptop joined to THEIR domain.
  * The payload is accepted only if it is bound to THIS machine's serial, points the tunnel at the
    concentrator the signed document names, and carries the CAs the signed document names.

Linux adds two pins the Windows join does not need, because the laptop joins ONLINE and trusts the
domain's LDAPS certificate itself (pat-platform ADR 0058): the signed document names the AD domain
(`ad_domain`) and the AD CA (`ad_ca_sha256`). A v1 document without them is valid for Windows and
refused here - there is no "warn and continue" path.

Standard library plus python3-cryptography (in the base archive of Ubuntu 24.04 and 26.04).
"""
import base64
import binascii
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class TrustError(Exception):
    """Any doubt about the portal or the payload. The helper stops; nothing has been changed."""


# --- small checks, identical in meaning to Pat.Onboarding.Core.Checks ------------------------------

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HOST = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
# [SITE]L<1-10 of A-Z 0-9 -> (naming.yaml workstations), within NetBIOS's 15 characters
_LAPTOP = re.compile(r"^[A-Z0-9]{4}L[A-Z0-9-]{1,10}$")
# the broker's one-time-password alphabet (Invoke-OdjProvision.ps1): 32 unambiguous characters
_OTP = re.compile(r"^[A-HJ-NP-Za-km-z2-9]{32}$")
# an AD sAMAccountName an employee signs in with
_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$")


def is_host(s):
    return isinstance(s, str) and 0 < len(s) <= 253 and bool(_HOST.match(s))


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def normalise_serial(s):
    """BIOS serials compare upper-case with all whitespace removed (as the portal stores them)."""
    return "".join((s or "").split()).upper()


def first_pem_der(pem, kind="CERTIFICATE"):
    m = re.search(r"-----BEGIN %s-----(.+?)-----END %s-----" % (kind, kind), pem or "", re.S)
    if not m:
        return None
    try:
        return base64.b64decode("".join(m.group(1).split()), validate=True)
    except (binascii.Error, ValueError):
        return None


# --- the PAT tenant-signing key -------------------------------------------------------------------

class TrustedKey:
    """A PAT tenant-signing PUBLIC key (ECDSA P-256), compiled into the package."""

    def __init__(self, key_id, x_hex, y_hex):
        x, y = bytes.fromhex(x_hex), bytes.fromhex(y_hex)
        if not key_id or len(x) != 32 or len(y) != 32:
            raise ValueError("a P-256 key needs a key id and 32-byte X and Y")
        self.key_id = key_id
        self._pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()

    def verify(self, data, p1363_sig):
        """The envelope carries IEEE P1363 r||s (what .NET emits and checks); cryptography wants DER."""
        if not isinstance(p1363_sig, (bytes, bytearray)) or len(p1363_sig) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(p1363_sig[:32], "big"), int.from_bytes(p1363_sig[32:], "big"))
        try:
            self._pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


# --- the tenant document --------------------------------------------------------------------------

@dataclass
class Tenant:
    tenant: str
    portal: str
    concentrator: str
    machine_ca_sha256: str
    not_after: datetime
    ad_domain: str
    ad_ca_sha256: str


def _origin(url):
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else None)
    return (u.scheme, (u.hostname or "").lower(), port)


def verify_tenant(envelope_json, key, portal_asked, now=None):
    """Verify and parse /.well-known/pat-onboarding.json. Raises TrustError on ANY doubt."""
    now = now or datetime.now(timezone.utc)
    try:
        env = json.loads(envelope_json)
        kid, doc_b64, sig_b64 = env["kid"], env["doc"], env["sig"]
        if not all(isinstance(v, str) for v in (kid, doc_b64, sig_b64)):
            raise TypeError
    except (ValueError, KeyError, TypeError) as e:
        raise TrustError("the portal's tenant document is not a valid envelope") from e
    if kid != key.key_id:
        raise TrustError(f"the tenant document is signed with key '{kid}', not the one this installer trusts ('{key.key_id}')")
    try:
        doc = base64.b64decode(doc_b64, validate=True)
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise TrustError("the tenant document is not base64") from e
    if not key.verify(doc, sig):
        raise TrustError("the tenant document's signature is NOT valid - this portal is not one PAT has enrolled")

    try:
        d = json.loads(doc)
        if d["v"] != 1:
            raise TrustError("unsupported tenant document version")
        t = Tenant(tenant=d["tenant"], portal=d["portal"], concentrator=d["concentrator"],
                   machine_ca_sha256=str(d["machine_ca_sha256"]).lower(),
                   not_after=datetime.fromisoformat(d["not_after"].replace("Z", "+00:00")),
                   ad_domain=str(d.get("ad_domain") or "").lower(),
                   ad_ca_sha256=str(d.get("ad_ca_sha256") or "").lower())
    except TrustError:
        raise
    except Exception as e:  # noqa: BLE001 - any malformation is a refusal
        raise TrustError("the signed tenant document is malformed") from e

    # The portal we are TALKING to must be the one the document names: otherwise a copied, genuinely
    # signed document for another portal would vouch for an attacker's host.
    if _origin(t.portal)[0] != "https" or _origin(t.portal) != _origin(portal_asked):
        raise TrustError(f"the tenant document is for {t.portal}, not {portal_asked}")
    if t.not_after.tzinfo is None or now >= t.not_after:
        raise TrustError(f"the tenant document expired {t.not_after.isoformat()}")
    if not is_host(t.concentrator) or not _HEX64.match(t.machine_ca_sha256) or not (t.tenant or "").strip():
        raise TrustError("the signed tenant document carries an invalid field")
    # Linux-only requirements (ADR 0058): the domain to join and its CA, both signed by PAT.
    if not is_host(t.ad_domain) or not _HEX64.match(t.ad_ca_sha256):
        raise TrustError("the signed tenant document does not name the AD domain and its CA "
                         "(ad_domain, ad_ca_sha256) - this portal is not enrolled for Linux laptops")
    return t


# --- the payload ----------------------------------------------------------------------------------

BUNDLE_MEMBERS = ("machine.crt", "machine.key", "machine-ca-bundle.pem", "machine-tc.key")


@dataclass
class Payload:
    serial: str
    name: str
    server: str
    port: int
    tun_mtu: int
    domain: str
    employee: str
    otp: str = field(repr=False)            # a computer-account password until adcli rotates it
    ad_ca_pem: str = field(repr=False)
    bundle: dict = field(repr=False)        # member name -> bytes

    def wipe(self):
        self.otp = ""
        self.bundle = {}


def _read_bundle(zbytes):
    out = {}
    try:
        with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
            for info in z.infolist():
                if info.filename not in BUNDLE_MEMBERS:
                    raise TrustError(f"the certificate bundle holds an unexpected member '{info.filename}'")
                if info.file_size > 64 * 1024:
                    raise TrustError(f"bundle member {info.filename} is implausibly large")
                out[info.filename] = z.read(info)
    except zipfile.BadZipFile as e:
        raise TrustError("the certificate bundle is not a zip") from e
    for m in BUNDLE_MEMBERS:
        if m not in out:
            raise TrustError(f"the certificate bundle has no {m}")
    return out


def accept_payload(token_json, this_serial, tenant):
    """The one-time payload from POST /odj/pair/token, accepted only if it is bound to THIS machine,
    THIS tenant and its own hash. Raises TrustError; nothing on the machine has changed yet."""
    try:
        r = json.loads(token_json)
        if r.get("os") != "linux":
            raise TrustError(f"the payload is for os '{r.get('os') or 'windows'}', not linux - "
                             "IT prepared this laptop as the wrong kind of device")
        p = Payload(serial=r["serial"], name=r["name"], server=r["server"], port=int(r["port"]),
                    tun_mtu=int(r["tun_mtu"]), domain=str(r["domain"]).lower(), employee=r["employee"],
                    otp=r["otp"], ad_ca_pem=r["ad_ca_pem"], bundle={})
        bundle_b64, bundle_sha = r["bundle_b64"], str(r["bundle_sha256"]).lower()
    except TrustError:
        raise
    except Exception as e:  # noqa: BLE001
        raise TrustError("the portal's payload is malformed") from e

    if normalise_serial(p.serial) != normalise_serial(this_serial):
        raise TrustError(f"the payload is for serial {p.serial}, this machine is {this_serial}")
    if p.server.lower() != tenant.concentrator.lower():
        raise TrustError(f"the payload points the tunnel at {p.server}, the signed tenant document says {tenant.concentrator}")
    if not (1 <= p.port <= 65535) or not (576 <= p.tun_mtu <= 1500):
        raise TrustError("the payload's port or MTU is out of range")
    if not isinstance(p.name, str) or not _LAPTOP.match(p.name):
        raise TrustError(f"the payload's computer name '{p.name}' is not a valid laptop name")
    if p.domain != tenant.ad_domain:
        raise TrustError(f"the payload joins {p.domain}, the signed tenant document says {tenant.ad_domain}")
    if not isinstance(p.employee, str) or not _ACCOUNT.match(p.employee):
        raise TrustError("the payload's employee account name is not valid")
    if not isinstance(p.otp, str) or not _OTP.match(p.otp):
        raise TrustError("the payload's one-time password is not in the broker's form")

    try:
        bundle = base64.b64decode(bundle_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise TrustError("the certificate bundle is not base64") from e
    if sha256_hex(bundle) != bundle_sha:
        raise TrustError("the certificate bundle does not match its hash")
    p.bundle = _read_bundle(bundle)

    # The CAs this laptop will trust must be the ones the SIGNED document names: a portal that could
    # substitute its own could stand up its own concentrator, or its own "domain controller".
    mca = first_pem_der(p.bundle["machine-ca-bundle.pem"].decode("ascii", "replace"))
    if mca is None or sha256_hex(mca) != tenant.machine_ca_sha256:
        raise TrustError("the payload's machine CA is not the one the signed tenant document names")
    aca = first_pem_der(p.ad_ca_pem)
    if aca is None or sha256_hex(aca) != tenant.ad_ca_sha256:
        raise TrustError("the payload's AD CA is not the one the signed tenant document names")
    return p
