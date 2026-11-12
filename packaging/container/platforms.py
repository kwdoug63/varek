#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# platforms.py — v1.36 step 3 (docs/security/v1.36-kubernetes-parity.md, D8):
# an image index (`docker buildx imagetools inspect --raw`) checked to name
# exactly the platforms given, each once. A build's attestations, listed as
# unknown/unknown, are not platforms. The release (container-release.yml)
# runs it on the node image before signing it.
#
#   platforms.py INDEX.json linux/amd64 linux/arm64
#
# platforms.py --image MANIFEST.json PLATFORM: the digest of that platform's
# image when MANIFEST is an index of one platform's image (with a build's
# attestation, as Docker's containerd image store pushes a single-platform
# image); nothing when MANIFEST is an image itself, whose digest the caller
# already has. The release takes the image's own digest this way, since the
# index for both platforms lists the image and not that one platform's index,
# and so `cosign sign --recursive` signs the image and not that index.
import json
import sys


def platforms(index):
    if index.get("mediaType") not in ("application/vnd.oci.image.index.v1+json",
                                      "application/vnd.docker.distribution.manifest.list.v2+json"):
        raise ValueError(f"not an image index: {index.get('mediaType')}")
    out = []
    for m in index.get("manifests", []):
        p = m.get("platform") or {}
        if p.get("os") == "unknown":
            continue
        # arm64's only variant (v8), which Docker on arm64 writes, is arm64
        v = p.get("variant")
        if p.get("architecture") == "arm64" and v == "v8":
            v = None
        out.append("/".join(x for x in (p.get("os"), p.get("architecture"), v) if x))
    return sorted(out)


INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")


def image_digest(manifest, platform):
    """The digest of PLATFORM's image in an index; None for an image itself."""
    if manifest.get("mediaType") not in INDEX_TYPES:
        return None
    found = []
    for m in manifest.get("manifests", []):
        p = m.get("platform") or {}
        v = p.get("variant")
        if p.get("architecture") == "arm64" and v == "v8":
            v = None
        if "/".join(x for x in (p.get("os"), p.get("architecture"), v) if x) == platform:
            found.append(m["digest"])
    if len(found) != 1:
        raise ValueError(f"the index names {platform} {len(found)} times, not once")
    return found[0]


def main(argv):
    if len(argv) == 4 and argv[1] == "--image":
        try:
            with open(argv[2]) as f:
                d = image_digest(json.load(f), argv[3])
        except (OSError, ValueError, KeyError) as e:
            print(f"platforms.py: {e}", file=sys.stderr)
            return 1
        if d:
            print(d)
        return 0
    if len(argv) < 3:
        print("usage: platforms.py INDEX.json PLATFORM... | platforms.py --image MANIFEST.json PLATFORM", file=sys.stderr)
        return 2
    try:
        with open(argv[1]) as f:
            got = platforms(json.load(f))
    except (OSError, ValueError) as e:
        print(f"platforms.py: {e}", file=sys.stderr)
        return 1
    want = sorted(argv[2:])
    print("platforms:", " ".join(got))
    if got != want:
        print(f"platforms.py: the index names {got}, not {want}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
