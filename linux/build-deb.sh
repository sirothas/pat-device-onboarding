#!/usr/bin/env bash
# build-deb.sh - build the Ubuntu package: pat-onboarding_<version>_all.deb
#
#   linux/build-deb.sh <version> [outdir]        e.g. linux/build-deb.sh 0.2.0 out
#
# Installs exactly what linux/dev-install.sh put in place by hand - the helper, the tunnel DNS hook, the
# vendored pat.identity collection (linux/vendor, at the commit in VENDORED) and /usr/sbin/pat-onboarding
# - so the package is the proven layout, not a new one. dev-install.sh retires with this.
#
# DEPENDS lists only what the helper's own preflight needs and the tools it calls. krb5-user is NOT a
# dependency on purpose: installing it asks an interactive question (the default Kerberos realm), which
# would stop an employee's `apt install` at a prompt they cannot answer. The sssd_ad_join role installs it
# non-interactively during the join, as it does on every server.
set -euo pipefail
ver="${1:?version}"; out="${2:-out}"
here="$(cd "$(dirname "$0")" && pwd)"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$ ]] || { echo "bad version '$ver'" >&2; exit 2; }
[ -f "$here/vendor/VENDORED" ] || { echo "linux/vendor is empty - run tools/vendor-pat-identity.sh" >&2; exit 2; }

root="$(mktemp -d)"; trap 'rm -rf "$root"' EXIT
install -d -m 0755 "$root/DEBIAN" "$root/usr/lib/pat-onboarding" "$root/usr/sbin" \
    "$root/usr/share/pat-onboarding/collections" "$root/usr/share/doc/pat-onboarding"
cp -r "$here/pat_onboarding" "$root/usr/lib/pat-onboarding/"
find "$root/usr/lib/pat-onboarding" -name __pycache__ -prune -exec rm -rf {} +
install -m 0755 "$here/tunnel-dns" "$root/usr/lib/pat-onboarding/tunnel-dns"
cp -r "$here/vendor/ansible_collections" "$root/usr/share/pat-onboarding/collections/"
install -m 0644 "$here/vendor/VENDORED" "$root/usr/share/doc/pat-onboarding/VENDORED"
cat > "$root/usr/sbin/pat-onboarding" <<'EOF'
#!/bin/sh
exec env PYTHONPATH=/usr/lib/pat-onboarding python3 -m pat_onboarding "$@"
EOF
chmod 0755 "$root/usr/sbin/pat-onboarding"
# the version the helper reports is the package's
sed -i "s/^__version__ = .*/__version__ = \"$ver\"/" "$root/usr/lib/pat-onboarding/pat_onboarding/__init__.py"
find "$root/usr" -type d -exec chmod 0755 {} + ; find "$root/usr" -type f ! -perm -u+x -exec chmod 0644 {} +

cat > "$root/usr/share/doc/pat-onboarding/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: pat-onboarding
Source: https://github.com/sirothas/pat-device-onboarding
Files: *
Copyright: Parvati Axis Technologies
License: see LICENSE in the source repository
EOF

size=$(du -sk "$root/usr" | cut -f1)
cat > "$root/DEBIAN/control" <<EOF
Package: pat-onboarding
Version: $ver
Architecture: all
Maintainer: Parvati Axis Technologies <noreply@parvatiat.com>
Installed-Size: $size
Depends: python3 (>= 3.12), python3-cryptography, openvpn, realmd, adcli, sssd, sssd-ad, sssd-tools,
 libnss-sss, libpam-sss, oddjob, oddjob-mkhomedir, samba-common-bin, ansible-core (>= 2.16), systemd-resolved
Section: admin
Priority: optional
Homepage: https://github.com/sirothas/pat-device-onboarding
Description: PAT company laptop onboarding (Ubuntu)
 Joins a company Ubuntu laptop to the domain from anywhere: verifies the PAT-signed company portal,
 pairs with a short code the employee approves, installs a pre-logon machine tunnel with split DNS,
 and joins online with a one-time password. Run: sudo pat-onboarding --portal https://<portal>
EOF

mkdir -p "$out"
deb="$out/pat-onboarding_${ver}_all.deb"
dpkg-deb --root-owner-group --build "$root" "$deb" >/dev/null
echo "built $deb"
dpkg-deb --info "$deb" | sed -n '/Package:/,/Homepage:/p'
echo "files: $(dpkg-deb --contents "$deb" | grep -vc '/$')"
