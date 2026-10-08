#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1250_stall.py — the v1.25 review's stall: a TCP connect to the stub that
never completes (TCP_MD5SIG with a key the stub's listener lacks, so it drops
every SYN) must not hold up the Warden.

  v1250_stall.py <file to open>

One thread connects to 127.53.53.53:53 with TCP_SYNCNT=1; another opens the
file three times meanwhile. Prints "OPEN <seconds>" for each open and
"CONNECT <errno name> <seconds> blocking=<0|1>" when the connect ends.
"""
import errno
import fcntl
import os
import socket
import struct
import sys
import threading
import time


def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sa = struct.pack("=HH4s", socket.AF_INET, 0, socket.inet_aton("127.53.53.53")).ljust(128, b"\0")
    key = b"k" * 8
    s.setsockopt(socket.IPPROTO_TCP, 14, sa + struct.pack("=BBHI", 0, 0, len(key), 0) + key.ljust(80, b"\0"))
    s.setsockopt(socket.IPPROTO_TCP, 7, 1)                 # TCP_SYNCNT: give up after about 3 s
    t = time.time()
    try:
        s.connect(("127.53.53.53", 53))
        e = 0
    except OSError as x:
        e = x.errno
    blocking = 0 if fcntl.fcntl(s, fcntl.F_GETFL) & os.O_NONBLOCK else 1
    print(f"CONNECT {errno.errorcode.get(e, 'OK')} {time.time() - t:.2f} blocking={blocking}", flush=True)


th = threading.Thread(target=connect)
th.start()
time.sleep(0.5)
for _ in range(3):
    t = time.time()
    open(sys.argv[1]).read()
    print(f"OPEN {time.time() - t:.3f}", flush=True)
    time.sleep(0.2)
th.join()
