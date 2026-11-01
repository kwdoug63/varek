# Installing VAREK on Red Hat Enterprise Linux 9

This installs the Warden, its helpers and the `varek` command on a RHEL 9
host, from the source of a release. The Warden runs as root and supervises
an AI agent's process from outside it: each call the agent makes that its
policy covers is decided against the policy, in the kernel (seccomp), and
recorded in a signed stream.

For Kubernetes and OpenShift, install the Helm charts instead
(`packaging/helm/varek/README.md`); for a container, the image
(`packaging/container/README.md`).

## What it needs

- RHEL 9 (kernel 5.14 or later, cgroup v2: RHEL 9's defaults), x86_64.
  CI runs every host suite on RHEL 9 in a VM, tested on Rocky Linux 9
  (the repository README's platform table).
- Root, or `sudo`. The Warden needs CAP_SYS_ADMIN and refuses to start
  without it; the agent it runs holds none of its rights.
- Two package repositories besides RHEL's own:
  - **EPEL 9**, for libsodium, which RHEL 9 does not ship. EPEL is the
    Fedora project's repository for Enterprise Linux, not Red Hat's.
  - **CodeReady Builder**, a Red Hat repository, for the development
    packages the build needs (`libseccomp-devel`).
- SELinux stays enforcing: nothing here asks you to change it.

## 1. The repositories

EPEL 9, from the Fedora project (its package is signed with EPEL 9's key,
fingerprint `FF8A D134 4597 106E CE81 3B91 8A38 72BF 3228 467C`, which dnf
asks you to accept on first use):

```sh
sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
```

CodeReady Builder, with the `crb` command the EPEL package installs (it
finds the repository's name on a subscribed host and on a cloud image alike):

```sh
sudo crb enable
```

## 2. The build's packages

```sh
sudo dnf install -y gcc make git python3 libseccomp-devel libsodium-devel openssl-devel
```

At run time the Warden needs `libseccomp`, `libsodium`, `openssl-libs` and
`python3`; the `-devel` packages bring them.

## 3. Build and install a release

The release's tag, here v1.36.1 (the list:
https://github.com/kwdoug63/varek/releases):

```sh
git clone --branch v1.36.1 --depth 1 https://github.com/kwdoug63/varek.git && cd varek/varek/v1_4
make
sudo make install BINDIR=/usr/bin
```

`make install` puts the Warden, its helpers, the policy packs and the tools
in `/opt/varek`, and the `varek` command in `BINDIR`. `/usr/bin` because
RHEL's `sudo` finds commands only in `/usr/sbin`, `/usr/bin` and the like
(its `secure_path`), not `/usr/local/bin`, the default.

## 4. Check the host

```sh
sudo varek version
sudo varek doctor
```

`varek version` names the Warden's version (`VAREK Warden  1.36.1`).
`varek doctor` checks the kernel, the build and the host's settings, and
names the fix for any it finds missing.

## 5. A first run

With nothing set up, an agent runs under VAREK's baseline policy and the
profile its command's name chooses:

```sh
sudo varek run -- python3 agent.py
varek refusals
```

`varek refusals` shows what the run refused, and why. For a policy pack of
your sector, signing and the log directory, set it up once and try it:

```sh
sudo varek init --pack healthcare
sudo varek preflight --run
```

The packs are `cybersecurity`, `finance`, `healthcare`, `national-defense`
and `utility`; `--pack /path/to/policy.txt` takes your own. Then:

- `sudo varek audit`: re-checks the run's certificates, chain and signatures;
- `sudo varek export`: signed CycloneDX evidence of the run, which anyone can
  check with `varek export --verify <file>`.

The full command reference is `varek/v1_4/README.md`.

## Upgrading and removing

To upgrade, build and install the next release's tag the same way. To
remove VAREK, from the same directory:

```sh
sudo make uninstall BINDIR=/usr/bin
```

That removes `/opt/varek` and the `varek` command, and keeps the settings in
`/etc/varek` and the logs in `/var/log/varek`.

## Support

Security issues: `SECURITY.md`. Everything else: an issue at
https://github.com/kwdoug63/varek/issues.
