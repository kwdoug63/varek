# Installing VAREK on Red Hat Enterprise Linux 9

This installs the Warden, its helpers and the `varek` command on a RHEL 9
host, from the source of a release. The Warden runs as root and supervises
an AI agent's process from outside it: each call the agent makes that its
policy covers is decided against the policy, in the kernel (seccomp), and
recorded in a signed stream.

For Kubernetes and OpenShift, install the Helm charts instead
(`packaging/helm/varek/README.md`); for a container, the image
(`packaging/container/README.md`).

Run end to end on RHEL 9.8 (an Amazon EC2 image, kernel
5.14.0-687.45.1.el9_8, SELinux enforcing) on November 1, 2026, from the
v1.36.1 tag: every step below, as written, with no SELinux denial. This
guide lives on the repository's main branch; it applies to v1.36.1 and
later.

## What it needs

- RHEL 9 (kernel 5.14 or later, cgroup v2: RHEL 9's defaults), x86_64.
  CI also runs every host suite on RHEL 9 in a VM, tested on Rocky Linux 9
  (the repository README's platform table).
- Root, or `sudo`. The Warden needs CAP_SYS_ADMIN and refuses to start
  without it; the agent it runs holds none of its rights.
- **EPEL 9**, for libsodium, which RHEL 9 does not ship. EPEL is the Fedora
  project's repository for Enterprise Linux, not Red Hat's. Everything else
  comes from RHEL's own BaseOS and AppStream.
- SELinux stays enforcing: nothing here asks you to change it.

## 1. EPEL 9

```sh
sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
```

With `-y`, dnf imports EPEL 9's signing key the first time it installs a
package from EPEL. To check that the key is EPEL 9's (fingerprint
`FF8A D134 4597 106E CE81 3B91 8A38 72BF 3228 467C`) after step 2:

```sh
rpm -q gpg-pubkey-3228467c
```

## 2. The build's packages

```sh
sudo dnf install -y gcc make git python3 libseccomp-devel libsodium-devel openssl-devel
```

`libsodium-devel` comes from EPEL, the rest from BaseOS and AppStream. dnf
may also update `openssl`, `openssl-libs` and `python3` to the latest RHEL 9
packages they need. At run time the Warden needs `libseccomp`, `libsodium`,
`openssl-libs` and `python3`; the `-devel` packages bring them.

No other repository is needed. CodeReady Builder only gives `glibc-static`,
for a static `tools/bench_workload` (the workload of `varek bench`); without
it `make` builds that one dynamically and says so, and the bench adds the
loader's files to its policy. To have it static, enable CodeReady Builder
and install `glibc-static` before step 3: on a cloud image whose
repositories come from Red Hat's update infrastructure (RHUI, as on Amazon
EC2), `sudo dnf config-manager --set-enabled codeready-builder-for-rhel-9-rhui-rpms`;
on a host registered with Red Hat, `sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms`.
(EPEL's `crb enable` does nothing on an RHUI image, which leaves its
repositories to dnf, though it exits 0.)

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

`varek version` names the `varek` command's version and the Warden's, the
second line `VAREK Warden  1.36.1  (/opt/varek)`. `varek doctor` checks the
kernel, the build and the host's settings, and names the fix for any it
finds missing. Until step 6 it reports one FAIL, `no configuration at
/etc/varek/varek.conf`, and exits 1: a run needs no configuration (step 5),
so on a fresh host every other check is the one to read.

## 5. A first run

With nothing set up, a command runs under VAREK's baseline policy and the
profile its name chooses:

```sh
sudo varek run -- /bin/echo hello-from-the-warden
sudo varek refusals
```

It prints `hello-from-the-warden`, and `varek refusals` (root's: the verdict
streams are root's alone) shows what the run refused, and why: here
nothing. The first run makes what a run needs: the log directory
`/var/log/varek` (mode 750), where each run's verdict stream is kept, and
the key that signs the streams, `/etc/varek/log.key` (mode 600), with its
public key beside it. Your agent runs the same way, for example
`sudo varek run -- python3 agent.py` from the agent's directory.

## 6. A policy pack, signing and the settings

For a policy pack of your sector, set it up once and try it:

```sh
sudo varek init --pack healthcare
sudo varek preflight --run
```

`varek init` writes the settings, `/etc/varek/varek.conf` (the check
`varek doctor` failed in step 4 then passes), with the pack, the signing key and the log
directory. The packs are `cybersecurity`, `finance`, `healthcare`,
`national-defense` and `utility`; `--pack /path/to/policy.txt` takes your
own. Then:

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

That removes `/opt/varek` and the `varek` command, and keeps the settings
and the signing key in `/etc/varek` and the logs in `/var/log/varek`.

## Support

Security issues: `SECURITY.md`. Everything else: an issue at
https://github.com/kwdoug63/varek/issues.
