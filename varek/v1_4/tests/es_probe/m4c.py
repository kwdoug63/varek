# SPDX-License-Identifier: MIT
"""m4c.py: M4c's opens (README, step 4), one Python process each.

  m4c.py open FILE          one read-write open of FILE, closed unwritten
                            (the file not changed, so its cached answers
                            are not dropped by a write); prints its result
  m4c.py loop FILE          one process: three appends to FILE, then
                            SIGUSR1 to its parent (the probe, under
                            --rules-on-usr1), then three more; prints each
"""
import os
import signal
import sys
import time


def attempt(f):
    try:
        f()
        return "ok"
    except OSError as e:
        return f"{e.strerror} (errno {e.errno})"


def rdwr_open(path):
    os.close(os.open(path, os.O_RDWR))


def append(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, text.encode() + b"\n")
    finally:
        os.close(fd)


def main():
    mode, path = sys.argv[1], sys.argv[2]
    who = f"pid {os.getpid()} (parent {os.getppid()})"
    if mode == "open":
        print(f"m4c open {path}, {who}: {attempt(lambda: rdwr_open(path))}", flush=True)
    elif mode == "loop":
        before = [attempt(lambda i=i: append(path, f"p{i}")) for i in (1, 2, 3)]
        os.kill(os.getppid(), signal.SIGUSR1)
        time.sleep(1)
        after = [attempt(lambda i=i: append(path, f"q{i}")) for i in (1, 2, 3)]
        print(f"m4c loop {who}: before the rule {before}; after {after}", flush=True)
    else:
        sys.exit("usage: m4c.py open|loop FILE")


if __name__ == "__main__":
    main()
