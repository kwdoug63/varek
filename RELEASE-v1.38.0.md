# VAREK v1.38.0 — Hardening: Git's Settings, the VM's Agent User and Network

Three of v1.37.0's known limits, closed. The checks on an EC2 Mac (`tests/mac_check.sh --sweep`) passed on this code, November 12, 2026. Security operations, planned as v1.38.0, moves to v1.39.0, so this hardening does not wait on the integrations. The Warden decides nothing differently, and the policy grammar stays 1.35.

> Not reviewed by a human or a third party, or by a separate review pass:
> the changes were tested as below.

MIT · github.com/kwdoug63/varek

## Summary

- **The baseline never writes the working directory's git settings and
  hooks** (#175). Git runs what they name (a hook, `core.fsmonitor`, a
  filter). On a Mac the project is shared with the VM, so the Mac's own git
  ran them too, outside the Warden. The baseline now opens with a deny of
  every write (`access=wo`, `access=rw`, `+O_CREAT`, `+O_TRUNC`; a removal
  or a rename is decided as a write) to:
  - `.git/config` (with `config.worktree` and git's `config.lock`) and
    `.git/hooks`, as prefixes;
  - a linked worktree's and a submodule's: `.git/worktrees/*/config*`,
    `.git/modules/*/config*`, `.git/modules/*/hooks` and
    `.git/modules/*/hooks/*`.

  Reads fall through to the rules after them, the credential denies
  first. The Warden renames no directory and the baseline admits no link,
  so `.git` is not moved or linked around them. The git directory stays in
  the VM's share, so git works in the VM.
- **On a Mac, the agent runs in the VM as a user of its own, without
  sudo** (#176). It ran as the VM's user, `varek`, who has sudo without a
  password; only `no_new_privs` and the Warden kept sudo from the agent.
  Before each run `varek vm run` makes or checks the user `agent`:
  - its own group and no other, a locked password and no ssh key;
  - the run refused if sudo would let it run anything.

  Then it runs `sudo varek run --run-as agent`. A VM made by v1.37.0 gets
  the user at its next run. `varek vm run` takes no `--run-as`; `varek`
  stays the Mac's way in (`varek vm ssh`).
- **On a Mac, a packet filter keeps the VM from the Mac and its networks**
  (#176). vmnet's NAT made the Mac the guest's gateway, so root in the VM
  (not under the Warden) reached the Mac's services, its networks and, on
  an EC2 Mac, the instance metadata service. `varek vm start` and `init`
  now load pf rules into an anchor of their own, `com.apple/varek-vm`
  (the user's own rules are not touched), with sudo, after the VM has its
  address and before the project is mounted; `varek vm stop` flushes them.
  - **Passes:** the Mac's own connections to the VM (ssh) and their
    replies, the VM's DNS and DHCP, and the Internet.
  - **Dropped:** anything else from the VM to the Mac's addresses,
    link-local addresses (the metadata service), the private ranges and
    shared address space; IPv6 coming in on vmnet's bridge.
  - A start whose rules do not load, or are not read back, is refused.
    `VAREK_VM_FIREWALL=off` starts the VM without them, and says so.

### What changes for a user

| | Before | v1.38.0 |
|---|---|---|
| Under the baseline: commits, branches, merges, fetches, a clone inside the project | work | work |
| Under the baseline: `git init` at the working directory's root, `git config`, `git remote add`, `git push -u` | work | refused (they write `.git/config`); a run that needs them takes `--policy` |
| `varek vm start` and `varek vm run` on a Mac | no sudo on the Mac | sudo on the Mac, for `pfctl` (it asks for the Mac's password if sudo does) |
| `varek vm run --run-as USER` | taken | refused |

## Tested

- **CI** on every PR (#174 to #176): every job, x86-64 and arm64,
  including the container image's sweep and the soak harness's six-minute
  trial.
- **The baseline's rules**:
  - `vdp_check`, on two working directories (one with `* ? [ ]` in its
    name): reads of config and hooks allowed; every kind of write to
    them, a worktree's and a submodule's refused; git's other files, a
    nested clone's config and source files written as before.
  - Live (`varek run --profile python --run-as nobody`): commit, branch,
    merge and a clone inside the project work; `git config
    core.fsmonitor`, a hook written, `.git/config` removed and `git remote
    add` are refused.
  - The solver cross-check on the claude profile's baseline (test-v1290,
    with z3): 250 s, every rule agreeing (main's baseline before: 231 s).
    An earlier shape of the rules (an `allow ... readonly` and a `deny` of
    each, with `**` globs) ran its search out; it never shipped.
- **On an EC2 Mac** (`mac2.metal`, us-east-2, a RHEL 9 aarch64 guest),
  November 12, 2026, on 141f054 (#176's head, as merged):
  `mac_check.sh --sweep`: `mac_check.sh: PASS`, 33 checks and every suite
  inside the VM. Among them:
  - the agent runs as `agent`, without sudo, no group but its own and a
    locked password, and reads and writes the project over virtio-fs, the
    Mac seeing what it wrote;
  - the filter loaded on the Mac; root in the VM reaches neither the Mac's
    ports 22 and 5000 nor 169.254.169.254; DNS and the Internet work.

  Its summaries are in
  `s3://varek-mac-results-982471468969/pr176-us-east-2-20261113T0242Z/`.
- **No 24-hour soak was run on this code.** The soak harness's six-minute
  trial passed in CI on each PR; the last 24-hour soak was v1.37.0's, on
  the Mac, November 10 and 11.

## Known limits

- **The baseline's git rules:**
  - a nested submodule's settings (`.git/modules/a/modules/b/...`) are not
    covered: a glob crossing directories made the solver's cross-check
    run out;
  - an IDE's task files and `.envrc` in the project are still the
    policy's to keep from the agent;
  - `mv .git` by the agent falls back to copying (the Warden renames no
    directory), which moves what it may and leaves `config` and `hooks`.
- **The packet filter:**
  - its rules name the Mac's addresses when they are loaded; an address
    the Mac gets later, from another network, is not among them until the
    next start (the private ranges still are);
  - its IPv6 rule is the bridge's, so other vmnet VMs on it lose IPv6
    while this VM runs;
  - on a VM's first boot there are a few seconds before the rules load,
    with no project mounted.
- From v1.37.0, unchanged: the VM persists between runs and stays up after
  `varek vm run` until `varek vm stop`; the guest can fill the Mac's disk
  through its serial log; a statically linked musl agent records
  `O_LARGEFILE` on arm64 and not on x86-64.
- **test_v1340's `nosha` container** once hung the sweep's host run
  (#173). It now fails its own check within 70 s (#174); why it hung is
  not known.
