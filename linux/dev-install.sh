#!/bin/sh
# dev-install.sh - install the Ubuntu helper from a development bundle, BEFORE the .deb exists.
#
#   sudo sh dev-install.sh          (from the unpacked bundle directory)
#
# Does what the package will do, and nothing more: the dependencies from Ubuntu's OWN archive (every one
# is there on 24.04 and 26.04 - pat-platform ADR 0058), the helper and its tunnel DNS hook at the paths
# the helper expects, and the pat.identity collection it runs locally. Retire this script when the .deb
# ships (its expiry condition): the package's Depends and file list replace it line for line.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$here/MANIFEST" ] && cat "$here/MANIFEST"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openvpn realmd adcli sssd sssd-ad sssd-tools samba-common-bin krb5-user \
    oddjob oddjob-mkhomedir libnss-sss libpam-sss ansible-core python3-cryptography >/dev/null

install -d -m 0755 /usr/lib/pat-onboarding /usr/share/pat-onboarding/collections
rm -rf /usr/lib/pat-onboarding/pat_onboarding /usr/share/pat-onboarding/collections/ansible_collections
cp -r "$here/pat_onboarding" /usr/lib/pat-onboarding/
install -m 0755 "$here/tunnel-dns" /usr/lib/pat-onboarding/tunnel-dns
cp -r "$here/collections/ansible_collections" /usr/share/pat-onboarding/collections/
find /usr/lib/pat-onboarding /usr/share/pat-onboarding -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} +
chmod 0755 /usr/lib/pat-onboarding/tunnel-dns
cat > /usr/local/sbin/pat-onboarding <<'EOF'
#!/bin/sh
exec env PYTHONPATH=/usr/lib/pat-onboarding python3 -m pat_onboarding "$@"
EOF
chmod 0755 /usr/local/sbin/pat-onboarding

echo "installed: $(/usr/local/sbin/pat-onboarding --version)"
for c in openvpn realm adcli sssd ansible-playbook resolvectl; do
    printf '  %-17s %s\n' "$c" "$(command -v "$c" || echo MISSING)"
done
echo "DEV-INSTALL-OK"
