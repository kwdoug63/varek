#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# vm_cell.sh — v1.36 step 2, its second part (docs/security/v1.36-kubernetes-
# parity.md, D11): the matrix's cells that need a host other than the
# runner's Ubuntu, each a cloud image booted under KVM on a GitHub hosted
# runner (M4c: /dev/kvm is usable there), reached by ssh:
#   --cell chart  a one-node CRI-O cluster in the VM (tests/node_cluster.sh)
#                 with SELinux enforcing, VAREK's chart checked on it by
#                 tests/v1340_kind.sh --host, and SELinux's denials counted;
#   --cell sweep  every host suite in the VM (tests/arm64_sweep.sh --deps).
# Images (--os): rocky9 (Rocky Linux 9's GenericCloud image: RHEL 9's
# rebuild, its kernel and SELinux policy built from RHEL's sources; RHEL's
# own images need a subscription) and al2023 (Amazon Linux 2023's KVM
# image, the OS of EKS's nodes). Each is its project's newest, checked
# against the project's published SHA-256.
#
#   vm_cell.sh resolve --os OS
#       prints file=, sha= and base= (for $GITHUB_OUTPUT: the cache's key)
#   sudo -E vm_cell.sh run --os OS --cell chart|sweep [--cache DIR] [--out DIR]
#       [--archive FILE] [--crio X.Y] [--oci runc|crun]
#       on the runner, as root: the image (from DIR if there and matching),
#       the VM, the cell, its logs back in OUT (OUT/cell/summary.txt)
#   vm_cell.sh inside ...   what run starts in the VM, as root
#
# The VM's ssh key is made for the run (OUT/vm/key), and the VM is reached
# on 127.0.0.1 only. CI: .github/workflows/matrix-vm.yml.
set -uo pipefail

CMD="${1:-}"; shift || true
OS="" CELL="" CACHE=/var/tmp/varek-vm-cache OUT=/var/tmp/varek-vm ARCHIVE="" CRIO=1.35 OCI=runc
FILE="" SHA="" BASE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --os) OS="$2"; shift 2 ;;
        --cell) CELL="$2"; shift 2 ;;
        --cache) CACHE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --archive) ARCHIVE="$2"; shift 2 ;;
        --crio) CRIO="$2"; shift 2 ;;
        --oci) OCI="$2"; shift 2 ;;
        --file) FILE="$2"; shift 2 ;;
        --sha) SHA="$2"; shift 2 ;;
        --base) BASE="$2"; shift 2 ;;
        *) echo "vm_cell.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
get() { curl -fsSL --retry 3 --retry-delay 5 "$@"; }
measure() {
    echo "MEASURE $1: $2" | tee -a "$OUT/measure.txt"
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`$1\`: $2" >> "$GITHUB_STEP_SUMMARY"
    return 0
}

# --- the image: the newest of the project's index, and its SHA-256 from the
# project's checksum file (BSD's "SHA256 (FILE) = HEX" or GNU's "HEX  FILE")
image_def() {
    case "$OS" in
        rocky9) INDEX=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/
                PATTERN='Rocky-9-GenericCloud-Base-9\.[0-9]+-[0-9]+\.[0-9]+\.x86_64\.qcow2'
                SUMS="CHECKSUM" ;;
        al2023) INDEX=https://cdn.amazonlinux.com/al2023/os-images/latest/kvm/
                PATTERN='al2023-kvm-2023\.[0-9.]+-kernel-[0-9.]+-x86_64\.xfs\.gpt\.qcow2'
                SUMS="SHA256SUMS" ;;
        *) echo "vm_cell.sh: --os rocky9|al2023" >&2; exit 2 ;;
    esac
}
sum_of() {   # FILE CHECKSUM-FILE
    sed -n -e "s/^SHA256 ($1) = \([0-9a-f]\{64\}\)$/\1/p" -e "s/^\([0-9a-f]\{64\}\) [ *]$1$/\1/p" "$2" | head -1
}
resolve() {
    image_def
    local t listing
    t="$(mktemp -d)"
    # the index's own address after redirects: its links are relative to it
    BASE="$(curl -fsSL --retry 3 --retry-delay 5 -o "$t/index" -w '%{url_effective}' "$INDEX")" ||
        { echo "vm_cell.sh: no index at $INDEX" >&2; rm -rf "$t"; return 1; }
    listing="$(cat "$t/index")"
    FILE="$(grep -oE "$PATTERN" <<< "$listing" | sort -uV | tail -1)"
    [ -n "$FILE" ] || { echo "vm_cell.sh: no image matching $PATTERN at $BASE" >&2; rm -rf "$t"; return 1; }
    get -o "$t/sums" "$BASE$SUMS" || { echo "vm_cell.sh: no $SUMS at $BASE" >&2; rm -rf "$t"; return 1; }
    SHA="$(sum_of "$FILE" "$t/sums")"
    rm -rf "$t"
    [ -n "$SHA" ] || { echo "vm_cell.sh: $FILE is not in $BASE$SUMS" >&2; return 1; }
}

if [ "$CMD" = resolve ]; then
    resolve || exit 1
    printf 'file=%s\nsha=%s\nbase=%s\n' "$FILE" "$SHA" "$BASE"
    exit 0
fi

# --- in the VM, as root
if [ "$CMD" = inside ]; then
    mkdir -p "$OUT"
    . /etc/os-release
    measure "vm" "$PRETTY_NAME, $(uname -r), SELinux $(getenforce 2>/dev/null || echo none), $(nproc) CPUs, $(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo) MB"
    # RHEL 9's rebuilds: libsodium is EPEL's, glibc-static CodeReady
    # Builder's (the image's own build does the same, packaging/container/deps.sh)
    case "$ID" in
        rocky|almalinux|centos)
            dnf -y -q install epel-release dnf-plugins-core > "$OUT/repos.log" 2>&1 &&
                dnf config-manager --set-enabled crb >> "$OUT/repos.log" 2>&1 ||
                { cat "$OUT/repos.log"; echo "vm_cell.sh: EPEL and CRB"; exit 1; } ;;
    esac
    cd "$ROOT" || exit 1
    case "$CELL" in
    sweep)
        # every host suite: the Kubernetes ones need a cluster, Go or kind,
        # and run in the chart cells and kubernetes.yml
        mapfile -t SUITES < <(sed -n 's/^\.PHONY:\(.*\)$/\1/p' "$HERE/Makefile" | tr ' ' '\n' | grep -E '^test-' |
            grep -vxE 'test-cli|test-varek-k8s|test-varek-chart|test-v1340-kind|test-v1340-apiserver')
        SUITES+=(test-cli crosscheck)
        "$HERE/tests/arm64_sweep.sh" --deps --out "$OUT/sweep" "${SUITES[@]}"
        rc=$?
        cp "$OUT/sweep/summary.txt" "$OUT/summary.txt" 2>/dev/null
        # v1.36 step 11 (review): a skipped check fails the cell, unless it is
        # one these hosts are expected to skip (each a SKIP line's reason):
        EXPECTED_SKIPS=(
            'no apparmor_parser here'       # RHEL 9 and Amazon Linux 2023 have SELinux, not AppArmor
            'node \(not installed\)|node (is )?not installed|Node\.js \(not installed\)'   # --deps brings no Node.js
            'go \(not installed\)'          # nor Go, on a dnf host; Ubuntu's sweep (warden-build.yml) runs both
            '^musl \('                      # no musl-gcc in Amazon Linux 2023's repositories (arm64_sweep.sh notes it)
            'no git or no v1\.13\.0 tag'     # the checkout is shallow, without tags
        )
        allowed="$(IFS='|'; echo "${EXPECTED_SKIPS[*]}")"
        for f in "$OUT"/sweep/test-*.log "$OUT"/sweep/crosscheck.log; do
            [ -f "$f" ] || continue
            sed -nE 's/^[[:space:]]*SKIP[[:space:]]+(.*)$/\1/p; s/^[A-Za-z0-9_]+: SKIP[[:space:]]+(.*)$/\1/p' "$f" |
                grep -vE "$allowed" | sed "s|^|$(basename "$f" .log): |"
        done > "$OUT/skips.txt"
        if [ -s "$OUT/skips.txt" ]; then
            echo "== checks skipped that this host should run (each fails the cell)"; cat "$OUT/skips.txt"
            measure "sweep.skips" "$(wc -l < "$OUT/skips.txt") not expected (skips.txt)"
            [ "$rc" = 0 ] && rc=1
        fi
        # each failed suite's whole log in the job's log (its first 1500
        # lines): the artifact holds it too, but where it cannot be read the
        # failing checks' excerpts alone did not say why (run 5's network
        # checks)
        for s in $(awk '$2 == "FAILED" {print $1}' "$OUT/sweep/summary.txt" 2>/dev/null); do
            echo "== $s: its log"
            cut -c1-300 "$OUT/sweep/$s.log" | head -1500
        done
        exit $rc ;;
    chart)
        [ "$(getenforce 2>/dev/null)" = Enforcing ] || { measure "selinux" "not enforcing: the cell's point is missing"; exit 1; }
        # what the chart test needs: its two tools built here, skopeo for
        # the image, helm (its newest 3.x release, checked by its SHA-256)
        dnf -y -q --allowerasing install gcc make git libseccomp-devel libsodium-devel openssl-devel python3 \
            skopeo tar curl audit > "$OUT/deps.log" 2>&1 || { tail -30 "$OUT/deps.log"; echo "vm_cell.sh: dnf failed"; exit 1; }
        make -C "$HERE" tools/varek_keygen tools/vdp_cert_check > "$OUT/build.log" 2>&1 ||
            { tail -30 "$OUT/build.log"; echo "vm_cell.sh: the tools did not build"; exit 1; }
        hv="$(git ls-remote --tags --refs https://github.com/helm/helm 2>/dev/null |
            sed -n 's|.*refs/tags/v\(3\.[0-9]*\.[0-9]*\)$|\1|p' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
        [ -n "$hv" ] || { echo "vm_cell.sh: no helm release found"; exit 1; }
        tgz="helm-v$hv-linux-amd64.tar.gz"
        get -o "/var/tmp/$tgz" "https://get.helm.sh/$tgz" &&
            [ "$(sha256sum "/var/tmp/$tgz" | awk '{print $1}')" = "$(get "https://get.helm.sh/$tgz.sha256sum" | awk '{print $1}')" ] &&
            tar -C /usr/local/bin --strip-components=1 -xzf "/var/tmp/$tgz" linux-amd64/helm ||
            { echo "vm_cell.sh: helm $hv did not install"; exit 1; }
        export PATH="/usr/local/bin:$PATH"
        measure "helm" "$(helm version --short)"
        bash "$HERE/tests/node_cluster.sh" --runtime crio --version "$CRIO" --oci "$OCI" --out "$OUT/cluster" ||
            { echo "vm_cell.sh: the cluster did not come up"; exit 1; }
        export KUBECONFIG=/etc/kubernetes/admin.conf
        "$HERE/tests/v1340_kind.sh" --host --image varek-node:ci --archive "$ARCHIVE" --out "$OUT/chart"
        rc=$?
        cp "$OUT/chart/summary.txt" "$OUT/summary.txt" 2>/dev/null
        # SELinux's denials since the VM booted, by what was denied what:
        # each is a finding, though the checks above decide the cell
        ausearch -m AVC,USER_AVC -i > "$OUT/avc.log" 2>/dev/null
        n="$(grep -c 'type=AVC\|type=USER_AVC' "$OUT/avc.log")"
        measure "selinux.denials" "$n since boot; SELinux $(getenforce) at the end"
        grep -oE 'scontext=[^ ]+ tcontext=[^ ]+ tclass=[^ ]+' "$OUT/avc.log" | sed 's/:c[0-9,.c]*//g' |
            sort | uniq -c | sort -rn | head -15 | tee "$OUT/avc-summary.txt"
        # v1.36 step 11 (review): still enforcing at the end, or the checks
        # above may not have run under it
        if [ "$(getenforce 2>/dev/null)" != Enforcing ]; then
            measure "selinux.end" "not enforcing at the end ($(getenforce 2>/dev/null || echo none)): the cell fails"
            rc=1
        fi
        exit $rc ;;
    *) echo "vm_cell.sh: --cell chart|sweep" >&2; exit 2 ;;
    esac
fi

[ "$CMD" = run ] || { echo "usage: vm_cell.sh resolve|run|inside --os OS --cell CELL ..." >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "vm_cell.sh: run as root" >&2; exit 2; }
case "$CELL" in chart) [ -s "$ARCHIVE" ] || { echo "vm_cell.sh: --cell chart needs --archive FILE (docker save of the node image)" >&2; exit 2; } ;;
    sweep) ;; *) echo "vm_cell.sh: --cell chart|sweep" >&2; exit 2 ;; esac
image_def
mkdir -p "$OUT/vm" "$CACHE"
VM="$OUT/vm" LOG="$OUT/vm/vm.log"
START=$(date +%s)

# --- the runner: qemu, and /dev/kvm opened to its user (GitHub's udev rule)
apt-get update -q >> "$LOG" 2>&1
apt-get install -y -q qemu-system-x86 qemu-utils cloud-image-utils >> "$LOG" 2>&1 || { tail -20 "$LOG"; echo "vm_cell.sh: qemu did not install"; exit 1; }
measure "runner.qemu" "$(qemu-system-x86_64 --version | head -1), installed in $(( $(date +%s) - START )) s"
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' > /etc/udev/rules.d/99-kvm4all.rules
udevadm control --reload-rules >> "$LOG" 2>&1; udevadm trigger --name-match=kvm >> "$LOG" 2>&1
[ -w /dev/kvm ] || { echo "vm_cell.sh: no /dev/kvm on this runner"; exit 1; }

# --- the image, from the cache if it is there and matches
[ -n "$FILE" ] && [ -n "$SHA" ] && [ -n "$BASE" ] || resolve || exit 1
img="$CACHE/$FILE"
if [ -s "$img" ] && [ "$(sha256sum "$img" | awk '{print $1}')" = "$SHA" ]; then
    measure "image" "$FILE (cached)"
else
    t0=$(date +%s)
    get -o "$img.part" "$BASE$FILE" || { echo "vm_cell.sh: $BASE$FILE did not download"; exit 1; }
    [ "$(sha256sum "$img.part" | awk '{print $1}')" = "$SHA" ] || { rm -f "$img.part"; echo "vm_cell.sh: $FILE does not match its SHA-256"; exit 1; }
    mv "$img.part" "$img"
    measure "image" "$FILE (downloaded in $(( $(date +%s) - t0 )) s)"
fi
chmod a+r "$img"

# --- the VM: a disk over the image, a seed for cloud-init (a user with the
# run's key, the root file system grown to the disk), the runner's CPUs and
# all but 3 GB of its memory, ssh forwarded from 127.0.0.1:2222
qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$VM/disk.qcow2" 60G >> "$LOG" 2>&1 || { echo "vm_cell.sh: qemu-img"; exit 1; }
rm -f "$VM/key" "$VM/key.pub"
ssh-keygen -q -t ed25519 -N '' -C varek-vm-cell -f "$VM/key" || exit 1
cat > "$VM/user-data" <<EOF
#cloud-config
users:
  - name: varek
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys: ["$(cat "$VM/key.pub")"]
growpart: {mode: auto, devices: ["/"]}
resize_rootfs: true
EOF
printf 'instance-id: varek-%s\nlocal-hostname: varek-%s\n' "$OS" "$OS" > "$VM/meta-data"
cloud-localds "$VM/seed.iso" "$VM/user-data" "$VM/meta-data" >> "$LOG" 2>&1 || { echo "vm_cell.sh: cloud-localds"; exit 1; }
MEM=$(( $(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo) - 3072 ))
CPUS=$(nproc)
qemu-system-x86_64 -enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
    -drive file="$VM/disk.qcow2",if=virtio -drive file="$VM/seed.iso",if=virtio,format=raw \
    -nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22 \
    -display none -monitor none -serial file:"$VM/serial.log" \
    -daemonize -pidfile "$VM/qemu.pid" >> "$LOG" 2>&1 || { tail -20 "$LOG"; echo "vm_cell.sh: qemu did not start"; exit 1; }
stop_vm() { [ -s "$VM/qemu.pid" ] && kill "$(cat "$VM/qemu.pid")" 2>/dev/null; return 0; }
trap stop_vm EXIT
SSH=(ssh -i "$VM/key" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
     -o ConnectTimeout=5 -o ServerAliveInterval=30 -o ServerAliveCountMax=10 varek@127.0.0.1)
up=0
for _ in $(seq 120); do "${SSH[@]}" true 2>/dev/null && { up=1; break; }; sleep 5; done
if [ "$up" = 0 ]; then
    echo "vm_cell.sh: the VM did not answer on ssh in 10 minutes; the serial console's end:"
    tail -c 3000 "$VM/serial.log" | tr -d '\r'; exit 1
fi
"${SSH[@]}" 'sudo cloud-init status --wait' >> "$LOG" 2>&1
measure "vm.up" "$(( $(date +%s) - START )) s from the start; $MEM MB, $CPUS CPUs"

# --- the checkout (and the node image) into the VM, where the user nobody
# can read it (the suites run tools as nobody), then the cell
# (the run's own files and the image cache left out, if they are in it: the
# first run copied the VM's disk as the VM wrote it, and failed)
ex=()
for d in "$OUT" "$CACHE"; do case "$(realpath -m "$d")" in "$ROOT"/*) ex+=("--exclude=./$(realpath -m --relative-to="$ROOT" "$d")") ;; esac; done
tar -C "$ROOT" "${ex[@]}" -cf - . | "${SSH[@]}" 'sudo rm -rf /opt/varek && sudo mkdir -p /opt/varek && sudo tar -C /opt/varek -xf - --no-same-owner' ||
    { echo "vm_cell.sh: the checkout did not copy"; exit 1; }
args=(--cell "$CELL" --crio "$CRIO" --oci "$OCI" --out /var/tmp/vm-cell)
if [ "$CELL" = chart ]; then
    "${SSH[@]}" 'cat > /var/tmp/varek-node.tar' < "$ARCHIVE" || { echo "vm_cell.sh: the node image did not copy"; exit 1; }
    args+=(--archive /var/tmp/varek-node.tar)
fi
"${SSH[@]}" sudo bash /opt/varek/varek/v1_4/tests/vm_cell.sh inside "${args[@]}"
rc=$?

# --- the cell's logs back, and the VM's journal
mkdir -p "$OUT/cell"
"${SSH[@]}" "sudo sh -c 'journalctl -b --no-pager > /var/tmp/vm-cell/journal.log 2>&1'; sudo tar -C /var/tmp/vm-cell -cf - ." |
    tar -C "$OUT/cell" -xf - 2>> "$LOG"
cat "$OUT/cell/measure.txt" >> "$OUT/measure.txt" 2>/dev/null
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -s "$OUT/cell/summary.txt" ] &&
    { echo '```'; cat "$OUT/cell/summary.txt"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
measure "cell" "$CELL on $OS: exit $rc, $(( $(date +%s) - START )) s from the start"
exit $rc
