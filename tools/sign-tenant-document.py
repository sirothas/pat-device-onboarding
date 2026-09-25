#!/usr/bin/env python3
"""sign-tenant-document.py - PAT-side: enrol a client portal by signing its tenant document.

    tools/sign-tenant-document.py --tenant example-demo --portal https://iip.example.test \
        --concentrator odj.example.test --machine-ca machine-ca.pem --days 365 \
        --kid pat-tenant-dev-2026-09 --key-file ~/pat-keys/pat-tenant-dev-2026-09.key.pem   > envelope.json
    # production: --kms-key-id <AWS KMS key> instead of --key-file (the private key never leaves KMS)

The output envelope is what the portal serves at /.well-known/pat-onboarding.json. The installer
verifies it with PAT's public key (compiled in), for exactly the portal named here.

Signature: ECDSA P-256 over SHA-256 of the exact document bytes, emitted as IEEE P1363 (r||s) - the
form .NET's ECDsa.VerifyData checks. openssl and KMS both return DER; it is converted here.
Standard library + openssl/aws on PATH only.
"""
import argparse, base64, datetime, hashlib, json, re, subprocess, sys, tempfile, os


def der_to_p1363(der: bytes) -> bytes:
    # SEQUENCE { INTEGER r, INTEGER s }
    if der[0] != 0x30:
        raise ValueError("not a DER ECDSA signature")
    i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    out = b""
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("bad INTEGER in signature")
        n = der[i + 1]
        v = der[i + 2:i + 2 + n].lstrip(b"\x00")
        if len(v) > 32:
            raise ValueError("integer too long for P-256")
        out += v.rjust(32, b"\x00")
        i += 2 + n
    return out


def cert_der(pem_path: str) -> bytes:
    pem = open(pem_path).read()
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S)
    if not m:
        raise SystemExit(f"no certificate in {pem_path}")
    return base64.b64decode("".join(m.group(1).split()))


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--tenant", required=True)
    a.add_argument("--portal", required=True)
    a.add_argument("--concentrator", required=True)
    a.add_argument("--machine-ca", required=True, help="PEM of the machine CA the tunnel must trust")
    a.add_argument("--days", type=int, default=365)
    a.add_argument("--kid", required=True)
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--key-file")
    g.add_argument("--kms-key-id")
    x = a.parse_args()

    if not x.portal.startswith("https://") or x.portal.rstrip("/") != x.portal.rstrip("/").split("?")[0]:
        raise SystemExit("--portal must be an https:// origin")
    not_after = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=x.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = json.dumps({
        "v": 1, "tenant": x.tenant, "portal": x.portal.rstrip("/"), "concentrator": x.concentrator,
        "machine_ca_sha256": hashlib.sha256(cert_der(x.machine_ca)).hexdigest(), "not_after": not_after,
    }, separators=(",", ":")).encode()

    if x.key_file:
        with tempfile.NamedTemporaryFile(delete=False) as t:
            t.write(doc)
        try:
            der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", os.path.expanduser(x.key_file), t.name],
                                 check=True, capture_output=True).stdout
        finally:
            os.unlink(t.name)
    else:
        r = subprocess.run(["aws", "kms", "sign", "--key-id", x.kms_key_id, "--message-type", "RAW",
                            "--signing-algorithm", "ECDSA_SHA_256", "--message", "fileb:///dev/stdin",
                            "--query", "Signature", "--output", "text"], input=doc, check=True, capture_output=True)
        der = base64.b64decode(r.stdout.strip())

    env = {"kid": x.kid, "doc": base64.b64encode(doc).decode(), "sig": base64.b64encode(der_to_p1363(der)).decode()}
    json.dump(env, sys.stdout)
    print()
    print(f"signed tenant document for {x.portal} (kid {x.kid}), valid until {not_after}", file=sys.stderr)


if __name__ == "__main__":
    main()
