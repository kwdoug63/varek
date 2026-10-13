# SPDX-License-Identifier: MIT
"""v1271_probe.py — run as the agent under the Warden by test_v1271.sh
section 3: what a process sees once the policy's writable directories are
mounted noexec. Each line is `NAME result`. Only copies of files already on
the host are used.

  v1271_probe.py WRITABLE_DIR
"""
import ctypes
import importlib.util
import mmap
import os
import shutil
import sys

W = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)
libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)


def say(name, result):
    print(name, result, flush=True)


def err(e):
    return "refused " + (os.strerror(e.errno) if getattr(e, "errno", None) else type(e).__name__)


# a system library, at its own path and as a copy in the writable directory
lib = "libm.so.6"                                      # a library every glibc host has
src = next(os.path.join(d, lib) for d in ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
                                          "/lib64", "/usr/lib64", "/lib", "/usr/lib")
           if os.path.exists(os.path.join(d, lib)))
dst = os.path.join(W, "copy-" + lib)
shutil.copyfile(src, dst)
try:
    ctypes.CDLL(src)
    say("LIB_ORIGINAL", "loaded")
except OSError as e:
    say("LIB_ORIGINAL", err(e))
try:
    ctypes.CDLL(dst)
    say("LIB_COPY", "loaded")
except OSError as e:
    say("LIB_COPY", "refused")

# a Python extension module, at its own path and as a copy
ext = importlib.util.find_spec("_json")
if ext and ext.origin and ext.origin.endswith(".so"):
    cp = os.path.join(W, os.path.basename(ext.origin))
    shutil.copyfile(ext.origin, cp)
    try:
        spec = importlib.util.spec_from_file_location("_json", cp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        say("EXT_COPY", "imported")
    except ImportError:
        say("EXT_COPY", "refused")
else:
    say("EXT_COPY", "skipped")
with open(os.path.join(W, "puremod.py"), "w") as f:
    f.write("X = 42\n")
spec = importlib.util.spec_from_file_location("puremod", os.path.join(W, "puremod.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
say("PURE_PY", "imported" if mod.X == 42 else "wrong")

# mmap of a file in the writable directory, executable
fd = os.open(dst, os.O_RDONLY)
try:
    mmap.mmap(fd, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC, flags=mmap.MAP_PRIVATE)
    say("MMAP_EXEC", "mapped")
except OSError as e:
    say("MMAP_EXEC", err(e))

# mprotect adding PROT_EXEC to a mapping of it
m = mmap.mmap(fd, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE, flags=mmap.MAP_PRIVATE)
addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
r = libc.mprotect(addr, 4096, mmap.PROT_READ | mmap.PROT_EXEC)
say("MPROTECT_EXEC", "allowed" if r == 0 else "refused " + os.strerror(ctypes.get_errno()))
os.close(fd)

# anonymous memory may still be made executable (a JIT's)
try:
    a = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    say("ANON_EXEC", "mapped")
except OSError as e:
    say("ANON_EXEC", err(e))

# a ctypes callback (libffi's closures)
CMP = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
arr = (ctypes.c_int * 5)(5, 1, 4, 2, 3)
libc.qsort(arr, 5, ctypes.sizeof(ctypes.c_int), CMP(lambda a, b: a[0] - b[0]))
say("CALLBACK", "ok" if list(arr) == [1, 2, 3, 4, 5] else "wrong")

# v1.27.1 review: from a working directory inside the writable directory, by
# a relative name (the working directory must not lead around the mount)
if os.path.realpath(os.getcwd()) == os.path.realpath(W):
    try:
        shutil.copyfile(src, "rel-" + lib)
        try:
            ctypes.CDLL("./rel-" + lib)
            say("REL_LIB_COPY", "loaded")
        except OSError:
            say("REL_LIB_COPY", "refused")
        fd = os.open("rel-" + lib, os.O_RDONLY)
        try:
            mmap.mmap(fd, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC, flags=mmap.MAP_PRIVATE)
            say("REL_MMAP_EXEC", "mapped")
        except OSError as e:
            say("REL_MMAP_EXEC", err(e))
    except OSError as e:
        say("REL_OPEN", err(e))
