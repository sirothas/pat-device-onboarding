# pat.identity.pam_profile

The PAM login policy for a host, in two modes chosen by inventory:

| `pat_identity_pam_access` | For | Effect |
|---|---|---|
| `simple_allow_groups` | login / interactive hosts | only members of `pat_identity_allow_groups` may open a session (`pam_access`) |
| `slurm_adopt` | compute nodes | a user may open a session only while a job of theirs runs on the node; the session is adopted into the job cgroup, so it is accounted and dies with the job (`pam_slurm_adopt`) |

`pat_identity_mkhomedir: true` additionally creates the home directory on
first login.

`pat_identity_allow_users` admits named users alongside the groups (either list
may be empty, not both). It exists for hosts that belong to a person - a company
laptop admits its assigned employee **and its local admin account**. The
allow-list ends in `- : ALL : ALL`, which matches *local* users too; only
`root` from the console is exempted. A laptop gated on groups alone therefore
locks out the account created at OS install, and a laptop with no local
account that can sign in is recoverable only from recovery mode.

## Why this role dispatches on OS family

This is the **one** role where `when: ansible_os_family` is legitimate:
authselect (RedHat) and pam-auth-update (Debian) are different *mechanisms*,
not different names for the same tool. The dispatch is a single
`include_tasks` in `tasks/main.yml`; everything below it is family-specific by
necessity.

## RedHat — never edit `/etc/pam.d/*`

authselect owns `/etc/pam.d/*` and `/etc/nsswitch.conf` and **silently
reverts** any hand edit on its next run. The symptom is `pam_slurm_adopt`
working today and gone next week with nothing in the commit log to blame. So
this role creates a **custom authselect profile** (`custom/pat-hpc`, based on
the stock `sssd` profile), edits the profile *templates*, and selects it. All
PAM changes flow through authselect.

## Debian — pam-auth-update fragments

Policy is expressed as fragments in `/usr/share/pam-configs/`; `pam-auth-update
--package` composes them into the `common-*` stacks. The `common-*` files are
never edited directly.

## Depends on PrologFlags=Contain

`pam_slurm_adopt` does **nothing** without `PrologFlags=Contain` in
`slurm.conf` (set by `pat.hpc.slurm_common`), and the failure is silent. The
compute node must also have the Slurm PAM module installed (from the Slurm
build) for the session line to resolve at login time.

## What Molecule proves — and what it cannot

Molecule (Rocky 9, Ubuntu 24.04, Debian 12, idempotence) proves that the
authselect custom profile is created and selected, that the mode-specific PAM
line is present in the generated stack, that `with-mkhomedir` wires the home
module, and that the role is idempotent. It **cannot** prove the runtime
behaviour — that a non-allowed user is actually refused, or that
`pam_slurm_adopt` places a session in the right cgroup — because that needs a
real login, a real directory and a running Slurm job. That is proven on the
test node (`docs/testing/adr0004-acceptance.md`).
