#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1240_listen53.py — test_v1240.sh: a stand-in resolver on 127.0.0.1:53
(TCP and UDP) that counts what reaches it for <seconds>, then writes the
count to <out> ("busy" if the port is taken).

  v1240_listen53.py <out> <seconds>
"""
import select
import socket
import sys
import time

out, secs = sys.argv[1], float(sys.argv[2])
try:
    t = socket.socket()
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("127.0.0.1", 53))
    t.listen(5)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 53))
except OSError:
    open(out, "w").write("busy")
    sys.exit(0)
n = 0
end = time.time() + secs
while time.time() < end:
    r, _, _ = select.select([t, u], [], [], max(0, end - time.time()))
    for s in r:
        if s is t:
            s.accept()
        else:
            s.recvfrom(4096)
        n += 1
open(out, "w").write(str(n))
