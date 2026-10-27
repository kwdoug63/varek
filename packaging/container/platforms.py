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


def main(argv):
    if len(argv) < 3:
        print("usage: platforms.py INDEX.json PLATFORM...", file=sys.stderr)
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
