# pat.identity.sssd_ad_join

Full Active Directory domain join for **interactive and infrastructure** hosts
(login/submit hosts, the Slurm controller, the DBD host). Creates a computer
object, obtains a Kerberos keytab, and configures SSSD for both **identity and
authentication** (`id_provider = ad`, `auth_provider = ad`).

## The asymmetry with `sssd_ldap_idonly` (read this)

These two roles are split **deliberately** so a compute node cannot be
accidentally configured to authenticate. They are opposite by design:

| | `sssd_ad_join` (this) | `sssd_ldap_idonly` |
|---|---|---|
| Hosts | login, controller, DBD | ephemeral compute nodes |
| `id_provider` | `ad` | `ldap` |
| `auth_provider` | **`ad`** | **`none`** |
| Computer object / keytab | yes | no |
| Credential caching | **`cache_credentials = true`** | omitted (nothing to cache) |
| `offline_credentials_expiration` | set, in **`[pam]`** | absent |
| Secret in `sssd.conf` | **none** (machine keytab) | the reader bind password |

**Why the caching asymmetry is correct, not an oversight:** a login host caches
credentials so an engineer can still sign in during a brief DC outage — a real,
wanted capability. A compute node sets `auth_provider = none`; nothing
authenticates there (access is `pam_slurm_adopt` while a job runs, ADR 0004), so
there is nothing to cache and the option would be meaningless. Same directory,
opposite requirements. Do not "reconcile" the two roles by giving the compute
node credential caching, or the login host `auth_provider = none`.

**`offline_credentials_expiration` goes in `[pam]`, never `[domain]`** —
`sssctl config-check` rejects it in `[domain]` (a defect found live on the
id-only role). This role's template puts it in `[pam]`.

## Sequence

Runs **after `pat.identity.ca_trust`** (wired in `site.yml`; a fail-loud assert
enforces the anchor is present). Deploys its own canonical `sssd.conf` rather
than sed-editing realmd's output, so the config is deterministic.

## Join account and OU

The computer object is created in `pat_identity_ad_computer_ou` — the
**delegated Linux OU** (`ou-structure.md`: the join account's create/reset-
computer rights are scoped there and inherit), never the default Computers
container. The join runs as `pat_identity_ad_join_account`
(`sa-unixadintegration`), whose password is read via `pat.base.secret` on the
controller (`no_log`). That account needs delegated create/reset-computer
rights on that OU only — never Domain Admin.

## Rebuild / orphan handling

On a host recreate the old computer object is orphaned in AD. `realm join`
(via `adcli`) **reuses/resets** an existing same-named computer account when the
join account has rights, so a same-hostname rebuild reclaims the orphan rather
than erroring. This is exercised by the reproducibility test, not assumed.

## How this release runs SSSD (read from the host, not assumed)

SSSD 2.10+ can run as an unprivileged `sssd` user with socket-activated
responders. Ubuntu 26.04 (SSSD 2.12) ships exactly that: `User=sssd`,
`sssd-nss.socket` / `sssd-pam.socket` enabled. Ubuntu 24.04 (SSSD 2.9.4) runs as
root **and also enables those sockets**, so the release number predicts neither
fact. Upstream's 2.10.0 notes require `sssd.conf`'s owner to **match the user the
service runs as**. The role therefore reads two facts before deploying the file:

| Fact | Read from | Effect |
|---|---|---|
| service user | `sssd.service` `User=` (empty = root) | `sssd.conf` owner and group; mode stays `0600` |
| socket activation | `sssd-nss.socket` enabled | the `services = nss, pam` line is omitted |

**Failure mode it prevents.** A hard-coded `root:root 0600` file cannot be read by
an `sssd`-user SSSD, and a `services` line alongside enabled sockets makes the
monitor and systemd fight over the responder sockets. Both were latent until
the role met a 26.04 host.

**This changes existing hosts.** A 24.04 server with the sockets enabled loses its
`services` line on the next converge, and its responders become socket-activated.
Upstream recommends that form, but it is still a change. Converge one such host
first and check `sssctl config-check`, `systemctl --failed` and `id <ad user>`
(pat-platform finding #203).

## Laptop mode: one-time-password join (pat-platform ADR 0058)

A remote Ubuntu company laptop runs this role **locally**
(`ansible-playbook -c local`), over its machine tunnel, with a different join:

| | Server (default) | Laptop |
|---|---|---|
| Computer object | created by `realm join` in `_ad_computer_ou` | **pre-created** by the onboarding broker |
| Credential | join account password (`pat.base.secret`) | `pat_identity_ad_join_otp`: a one-time password the broker set on that object |
| `realm join` | `-U <account> --computer-ou=...` | `--one-time-password=...`; no account, no OU |
| `pat_identity_manage_resolv_conf` | `true` (pin to DCs) | **`false`**: split DNS scopes only the AD domain to the tunnel |
| Access | `pat_identity_login_access_group` | `pat_identity_login_access_users` (the employee) and/or a support group |

With `pat_identity_ad_join_otp` set, the OU, join account and password-secret
inputs are no longer required. The OTP is passed at run time, never in
inventory, and is single-use: `adcli` rotates the machine password as it claims
the object. It appears in `realm`'s argv (there is no stdin form) for the
seconds the join takes; `no_log` keeps it out of every log.

Pair it with `pat.identity.pam_profile` using `pat_identity_allow_users` for the
employee **and the laptop's local admin account**. The pam_access list ends in
deny-all, which matches local users too.
