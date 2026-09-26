# pat.identity.sssd_ldap_idonly

Identity-**only** SSSD for ephemeral compute nodes. This is the ADR 0004
proof: a node that **resolves** identity but never **authenticates** anyone.

`id_provider = ldap`, `auth_provider = none`. No computer object, no Kerberos,
no realm join. A running job must survive a directory outage, so identity is
served from a generous offline cache and `su`/interactive password auth is
deliberately impossible on this domain.

Use this on `compute_nodes`. Its counterpart for interactive hosts is
`pat.identity.sssd_ad_join` (a full directory join), selected by inventory
group membership — never by a conditional in a play.

## Supported platforms

| Family | Distributions |
|---|---|
| RedHat | RHEL 9, Rocky 9, AlmaLinux 9 |
| Debian | Debian 12/13, Ubuntu 22.04/24.04 |

## Sequence — read this

This role **must run after `pat.identity.ca_trust`**. SSSD connects with
`ldap_tls_reqcert = demand`, so the DC's CA chain has to be in the system
trust store first. If it is not, SSSD **fails closed**: the node comes up with
no identity at all. That is the correct outcome — a compute node with an
unverifiable directory should resolve nobody, not trust an impostor.

It also expects to be paired with `pat.identity.pam_profile` (`slurm_adopt`
mode), which wires NSS and PAM (via authselect on RHEL). This role owns
`/etc/sssd/sssd.conf` and the SSSD service only; it does not touch
`nsswitch.conf` or `/etc/pam.d`.

## Key inputs (from inventory, compute host class)

| Variable | Meaning |
|---|---|
| `pat_identity_ldap_uri` | `ldaps://…` — **LDAPS is mandatory**; `ldap://` is refused |
| `pat_identity_ldap_bind_dn_secret` | logical secret name of the read-only bind DN |
| `pat_identity_ldap_bind_pw_secret` | logical secret name of the bind password |
| `pat_identity_ldap_user_search_base` | user OU — **not** the forest root |
| `pat_identity_ldap_group_search_base` | group OU — **not** the forest root |

The bind DN and password are fetched with `lookup('pat.base.secret', …)` and
handled `no_log`. `/etc/sssd/sssd.conf` is written `0600 root:root`. The
credential never appears in user-data, on a command line, or in a log.

Tunables (offline cache timeouts, `enumerate`, TLS reqcert, schema) are in
`defaults/main.yml`, documented inline.

## What Molecule proves here — and what it cannot

Molecule (Rocky 9, Ubuntu 24.04, Debian 12, with the idempotence step) proves
that the packages resolve per family, that `sssd.conf` **templates correctly**
with the right directives and file mode, and that the role is **idempotent**.

Molecule **cannot** prove this role actually works. That needs a live
directory: whether `id <user>` returns the correct numeric UID/GID, whether
group membership is complete, whether `su` fails as intended, and whether
identity still resolves with the directory unreachable are all provable only
on a real node. That proof is the acceptance test in
`docs/testing/adr0004-acceptance.md`, run on `aps2dvcn01`.
