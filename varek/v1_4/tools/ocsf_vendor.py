#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ocsf_vendor.py — v1.31 (docs/security/v1.31-standards.md, section 1):
make schemas/ocsf-1.9.0/schema.json, the part of the OCSF 1.9.0 schema the
OCSF export writes, from the OCSF project's own repository and compiler.

    git clone --depth 1 --branch 1.9.0 https://github.com/ocsf/ocsf-schema.git SRC
    pip install ocsf-lib==0.10.4
    python3 tools/ocsf_vendor.py SRC > schemas/ocsf-1.9.0/schema.json

The schema is compiled by ocsf-lib (`ocsf.compile`) with exactly the profiles
the export declares (security_control, ai_operation, host) and no
extensions, then cut down to the event classes the export writes and every
object and type they reach. Nothing in it is changed; the result is sorted
so the file is the same each time. Run once, by hand, when the vendored
version changes; the tests read the file and need neither the network nor
ocsf-lib.
"""
import json
import subprocess
import sys

PROFILES = ["security_control", "ai_operation", "host"]
CLASSES = ["file_activity", "process_activity", "network_activity", "http_activity", "dns_activity",
           "application_lifecycle", "api_activity"]


def main(src):
    out = subprocess.run([sys.executable, "-m", "ocsf.compile", src, "--profile", *PROFILES,
                          "--ignore-extension", "linux", "windows", "macos"],
                         capture_output=True, text=True, check=True).stdout
    s = json.loads(out)
    keep_obj, todo = set(), []
    classes = {n: s["classes"][n] for n in CLASSES}

    def reach(attrs):
        for a in attrs.values():
            t = a.get("type")
            if t in s["objects"] and t not in keep_obj:
                keep_obj.add(t)
                todo.append(t)

    for c in classes.values():
        reach(c["attributes"])
    while todo:
        reach(s["objects"][todo.pop()]["attributes"])
    res = {"version": s["version"], "profiles": PROFILES,
           "source": "https://github.com/ocsf/ocsf-schema tag 1.9.0 (856d462), compiled by ocsf-lib 0.10.4",
           "types": s["types"], "categories": s["categories"], "classes": classes,
           "objects": {k: s["objects"][k] for k in sorted(keep_obj)}}
    json.dump(res, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
