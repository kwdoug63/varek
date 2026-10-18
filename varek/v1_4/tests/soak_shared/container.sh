#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# container.sh — v1.32 step 9 (docs/security/v1.32-containers.md): the shared
# soak (soak.sh, README.md) inside VAREK's test image, under the settings the
# image documents (packaging/container/README.md): --cap-drop ALL and the ten
# capabilities, --cgroupns=private, the runtime's default seccomp profile,
# and VAREK's AppArmor profile as shipped (--apparmor) or the SELinux type
# and module (--selinux). Nothing more: no MKNOD, no test copy of the
# profile. The container runs detached; its directory is on the host.
#
#   sudo varek/v1_4/tests/soak_shared/container.sh [--runtime docker|podman]
#        [--build] [--image NAME] [--apparmor|--selinux] [--name NAME]
#        [--out DIR] [--check-only] [-- soak.sh options, e.g. --hours 0.1 --interval 3]
#
# --build     build the test image first (packaging/container/Containerfile,
#             --target test) from this checkout
# --image     the test image (default varek-test:<this checkout's commit>)
# --name      the container's name (default varek-soak)
# --out       the soak's directory on the host (default
#             /var/tmp/varek-soak-container-<time>), mounted at /soak
# --check-only  the steps after the runs again (soak.sh --check-only), on the
#             stopped container NAME's soak in DIR, when they were cut short:
#             its tokens and agents' files are in that container only, so it
#             is committed to an image and the steps run in a container of it
#
# A stopped container of that name is never removed here (it holds the
# soak's tokens): remove it yourself once its soak is judged.
#
# Follow it with `docker logs -f NAME`; it ends with soak_check's verdict, and
# DIR/report.txt holds it. While it runs, run nothing else under the Warden
# on the host (README.md).
set -u
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RT="" BUILD=0 IMAGE="" NAME=varek-soak OUT="" LSM="" SOAK=() CHECK_ONLY=0
CAPS="SYS_ADMIN SYS_PTRACE SETPCAP SETUID SETGID DAC_OVERRIDE KILL NET_ADMIN NET_BIND_SERVICE CHOWN"
while [ $# -gt 0 ]; do
    case "$1" in
        --runtime) RT="$2"; shift 2 ;;
        --build) BUILD=1; shift ;;
        --image) IMAGE="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --apparmor) LSM=apparmor; shift ;;
        --selinux) LSM=selinux; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        -h|--help) sed -n '3,/^set -u$/{/^#/p}' "$0"; exit 0 ;;
        --) shift; SOAK=("$@"); break ;;
        *) echo "container.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "container.sh: run as root" >&2; exit 2; }
for a in "${SOAK[@]}"; do
    case "$a" in --out|--out=*|--check-only)
        echo "container.sh: give $a to container.sh, not to soak.sh (the soak's directory is /soak/run, on the host)" >&2; exit 2 ;;
    esac
done
if [ -z "$RT" ]; then
    if command -v docker > /dev/null 2>&1; then RT=docker; elif command -v podman > /dev/null 2>&1; then RT=podman
    else echo "container.sh: neither docker nor podman is installed" >&2; exit 2; fi
fi
IMAGE="${IMAGE:-varek-test:$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo local)}"
if [ "$CHECK_ONLY" = 1 ] && [ -z "$OUT" ]; then
    echo "container.sh: --check-only needs --out DIR, the soak's directory" >&2; exit 2
fi
OUT="$(realpath -m "${OUT:-/var/tmp/varek-soak-container-$(date -u +%Y%m%dT%H%M%SZ)}")"   # a bind mount, not a volume name
state="$("$RT" inspect --format '{{.State.Running}}' "$NAME" 2>/dev/null)"
if [ "$CHECK_ONLY" = 1 ]; then
    if [ "$state" != false ] || [ ! -d "$OUT/run" ]; then
        echo "container.sh: --check-only needs the stopped container $NAME and its soak in $OUT/run" >&2; exit 2
    fi
# a soak of its own: never one on top of another's files, in place of a
# running one, nor removing a stopped one (its tokens are in it)
elif [ -e "$OUT/run" ]; then
    echo "container.sh: $OUT/run exists: give this soak a directory of its own (--out)" >&2; exit 2
elif [ "$state" = true ]; then
    echo "container.sh: a container $NAME is running (a soak?); stop it first or give --name" >&2; exit 2
elif [ -n "$state" ]; then
    echo "container.sh: a stopped container $NAME exists; if its soak is judged, remove it ($RT rm $NAME), else give --name" >&2; exit 2
fi
mkdir -p "$OUT"
args=(--cap-drop ALL --cgroupns=private)
for c in $CAPS; do args+=(--cap-add "$c"); done
vol="$OUT:/soak"
case "$LSM" in
    apparmor)
        apparmor_parser -r -W "$ROOT/packaging/container/apparmor/varek-container" ||
            { echo "container.sh: the AppArmor profile did not load" >&2; exit 1; }
        args+=(--security-opt apparmor=varek-container) ;;
    selinux)
        semodule -i "$ROOT/packaging/container/selinux/varek_container.cil" ||
            { echo "container.sh: the SELinux module did not load" >&2; exit 1; }
        args+=(--security-opt label=type:container_init_t); vol="$OUT:/soak:Z" ;;
esac
args+=(-v "$vol")
if [ "$BUILD" = 1 ]; then
    echo "== build the test image"
    "$RT" build -f "$ROOT/packaging/container/Containerfile" --target test -t "$IMAGE" "$ROOT" > "$OUT/build.log" 2>&1 ||
        { tail -20 "$OUT/build.log"; echo "container.sh: the build failed ($OUT/build.log)" >&2; exit 1; }
fi
if [ "$CHECK_ONLY" = 1 ]; then
    img="varek-soak-check:$NAME"
    echo "== $NAME committed to $img; the steps after the runs, again"
    "$RT" commit "$NAME" "$img" > /dev/null || { echo "container.sh: cannot commit $NAME" >&2; exit 1; }
    "$RT" run --rm "${args[@]}" "$img" tests/soak_shared/soak.sh --out /soak/run --check-only "${SOAK[@]}"
    rc=$?
    echo "container.sh: done (exit $rc; the result in $OUT/run/report.txt); remove $img and $NAME once judged"
    exit "$rc"
fi
"$RT" image inspect "$IMAGE" > /dev/null 2>&1 || { echo "container.sh: no image $IMAGE (--build makes it)" >&2; exit 2; }
{
    echo "host: $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
    echo "runtime: $($RT --version 2>/dev/null | head -1)"
    echo "image: $IMAGE $("$RT" image inspect --format '{{.Id}}' "$IMAGE")"
    echo "settings: ${args[*]}"
    echo "soak: ${SOAK[*]:-(24 hours)}"
    echo "started: $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z')"
} | tee "$OUT/container.txt"
"$RT" run -d --name "$NAME" "${args[@]}" "$IMAGE" tests/soak_shared/soak.sh --out /soak/run "${SOAK[@]}" > /dev/null ||
    { echo "container.sh: the container did not start" >&2; exit 1; }
# soak.sh refuses bad options at once: running after a few seconds, or said
sleep 5
if [ "$("$RT" inspect --format '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]; then
    "$RT" logs "$NAME" 2>&1 | tail -20
    echo "container.sh: $NAME stopped at once (above); remove it ($RT rm $NAME) and start again" >&2; exit 1
fi
echo "container.sh: running as $NAME; follow it with: $RT logs -f $NAME (the result in $OUT/run/report.txt)"
