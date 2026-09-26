#!/usr/bin/env bash
# vendor-pat-identity.sh - copy the pat.identity Ansible collection into linux/vendor/ at ONE commit.
#
#   tools/vendor-pat-identity.sh <path to a pat-ansible checkout> <commit>
#
# The Ubuntu package runs these roles on the employee's laptop, so it ships exactly the reviewed
# version, recorded - never "whatever was checked out when someone built it". `git archive` takes the
# COMMITTED tree at <commit>, not the working copy: an uncommitted edit in the checkout cannot leak in.
# Molecule scenarios (test-only) are dropped. linux/vendor/VENDORED records the source and commit.
set -euo pipefail
src="${1:?pat-ansible checkout}"; ref="${2:?commit}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dest="$here/linux/vendor"
sha="$(git -C "$src" rev-parse --verify "$ref^{commit}")"
url="$(git -C "$src" remote get-url origin 2>/dev/null || echo unknown)"

rm -rf "$dest"; mkdir -p "$dest"
git -C "$src" archive --format=tar "$sha" collections/ansible_collections/pat/identity | tar -x -C "$dest"
mv "$dest/collections/ansible_collections" "$dest/ansible_collections"; rmdir "$dest/collections"
rm -rf "$dest"/ansible_collections/pat/identity/roles/*/molecule
printf 'pat.identity vendored from %s\ncommit %s\nvendored %s\n' "$url" "$sha" "$(date -u +%FT%TZ)" > "$dest/VENDORED"
cat "$dest/VENDORED"
echo "files: $(find "$dest" -type f | wc -l)"
