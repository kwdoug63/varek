# SPDX-License-Identifier: MIT
"""The example agent (packaging/container/example): what an agent does at
its start, under the Warden in the container. It prints one JSON line:
what it could do, and what it was refused."""
import json
import os

r = {}


def t(name, f):
    try:
        f()
        r[name] = "ok"
    except OSError as e:
        r[name] = e.strerror
    except Exception as e:                                          # noqa: BLE001  (an import)
        r[name] = type(e).__name__


t("read_own_file", lambda: open("/work/agent.py").read())        # its project: readable
t("import_requests", lambda: __import__("requests"))               # its packages, as the profile lets it
t("read_shadow", lambda: open("/etc/shadow").read())               # never the agent's
t("write_etc", lambda: open("/etc/varek-example", "w").write("x"))  # the system is read-only to it
r["user"] = os.getuid()
print(json.dumps(r))
