# pat.identity.ca_trust

Install and refresh CA trust anchors in the OS trust store, so TLS the host
*initiates* validates against the client's PKI. Concretely: so SSSD can talk
**LDAPS** to a domain controller.

## Why this runs first

`pat.identity.sssd_ldap_idonly` (and `sssd_ad_join`) set
`ldap_tls_reqcert = demand` — they **fail closed** on an untrusted chain. If
the DC's issuing CA is not already in the system trust store, SSSD cannot
establish TLS and the node comes up with **no identity at all**. That is the
safe failure (better than trusting an unverified directory), but it means this
role is a hard prerequisite. Sequence it *before* the SSSD role in the play;
it flushes handlers at the end so the refreshed bundle is in place by the time
the SSSD role runs.

It is **not** declared as a Molecule/meta dependency of the SSSD roles — those
stay independently testable in a container with no directory. The ordering is
enforced by the playbook, and named in both roles' comments.

## What it does

1. Resolves the per-family anchor directory + refresh command (`vars/`).
2. Asserts at least one anchor was supplied, and that each is well-formed
   (safe filename slug + looks like a PEM certificate).
3. Ensures `ca-certificates` (which provides the refresh command) is present.
4. Writes each anchor to `<dir>/pat-ca-<name>.crt`.
5. Removes any `pat-ca-*.crt` it previously managed that is no longer declared.
6. Refreshes the consolidated bundle (`update-ca-trust` / `update-ca-certificates`)
   once, only if something changed.

## The `pat-ca-` prefix and the closed set

The role manages files named `pat-ca-*.crt` as a **closed set**: declared
anchors are present, and a managed anchor dropped from the list is removed on
the next run — a rotated-out CA must actually stop being trusted, not linger.
Files that do **not** match that prefix (OS-shipped roots, anchors another
tool placed) are never touched.

## Variables

| Variable | Meaning |
|---|---|
| `pat_identity_ca_anchors` | List of `{ name, content }`. `name` is a slug (`[A-Za-z0-9._-]`); `content` is a PEM certificate. **No default** — client PKI material, set in `inventories/<env>/group_vars`. |

The role is **source-agnostic**: `content` is a PEM string and the inventory
decides where it comes from, e.g.

```yaml
pat_identity_ca_anchors:
  - name: "[ORG]-root-ca"
    content: "{{ lookup('pat.base.secret', 'ad/ca_root_pem') }}"
  - name: "[ORG]-issuing-ca"
    content: "{{ lookup('file', 'files/issuing-ca.pem') }}"
```

This mirrors how `sssd_ldap_idonly` takes a *logical* secret name rather than
welding a backend into the role (see `pat.base.secret`). A CA certificate is
public, so it need not go through the secret backend — but it may.

## Debian gotcha

On the Debian family `update-ca-certificates` only picks up files ending in
`.crt`; a `.pem` in the same directory is silently ignored. The role always
writes `.crt`, which is why it is safe on both families.

## Scope of the Molecule test

The container scenario installs a throwaway self-signed CA, refreshes the
store, and proves with `openssl verify` that the anchor is now trusted, that
the pre-existing OS roots still verify (the refresh added, it did not replace),
and that a second converge is idempotent. It proves the install-and-trust
mechanism end to end on both families. It does **not** prove the closed-set
*removal* path (straightforward `find`/`difference`/`absent`), nor LDAPS
against a real DC — the latter is the ADR 0004 acceptance test on a real node.
