# PAT company laptop onboarding (Windows)

The installer an employee runs on a new or re-imaged company laptop, at home, to join it to the
company's Active Directory with **no IT visit**: one download, one UAC prompt, one reboot.

```
PAT-Onboarding-Setup.exe  ->  OpenVPN community MSI (unmodified) + the PAT helper
the helper:  reads the BIOS serial -> fetches the portal's PAT-signed tenant document
             -> shows a short code -> employee approves it in the company portal (password + MFA)
             -> receives this laptop's one-time payload straight into memory
             -> installs the pre-logon machine tunnel -> offline domain join -> "restart now"
```

## Why a portal is trusted

A portal decides which domain a laptop joins, so the installer does not trust a portal because of
its address or its TLS certificate. It trusts a portal only if it serves
`/.well-known/pat-onboarding.json` **signed by PAT** (key compiled into the installer), naming that
exact portal, its concentrator and its machine CA. A payload whose CA or concentrator differs from
the signed document is refused before anything touches the operating system.

## Verify a release

```
sha256sum -c SHA256SUMS
gh attestation verify PAT-Onboarding-Setup.exe --repo sirothas/pat-device-onboarding
```

Every release carries a CycloneDX SBOM and a build-provenance attestation. Releases are
Authenticode-signed by Parvati Axis Technologies Pvt Ltd (from phase 3; earlier builds are unsigned
and say **[DEVELOPMENT BUILD]** in the window title).

## Layout

| Path | What |
|---|---|
| `src/Pat.Onboarding.Core` | every trust decision, platform-neutral, unit-tested (`tests/`) |
| `src/PatOnboarding` | the Windows helper (.NET Framework 4.8): WMI, ACLs, the join API |
| `installer/` | WiX v5: `Package.wxs` (the helper MSI), `Bundle.wxs` (the setup exe), `openvpn.lock.json` |
| `tools/sign-tenant-document.py` | PAT-side: sign a client portal's tenant document |

Design of record: pat-platform ADR 0056 (brokered offline domain join + pre-logon machine tunnel)
and ADR 0057 (this installer and its device-code pairing).
