# SPDX-License-Identifier: MIT
"""v1340_bpf_compare.py — v1.34 step 1: the Warden's filter and the one
built from its OCI form (tests/v1340_oci_filter.c), compared call by call.

Each filter is classic BPF over struct seccomp_data; both are run here by a
small interpreter on every system call number of the native architecture,
those with x32's bit set, and an i386 call, each with arguments drawn from
every value and mask the rules compare against (and their neighbours).

  v1340_bpf_compare.py DIR     (DIR holds warden.bpf, oci.bpf and oci.json)
Prints each difference and a summary; exit 0 when the two decide the same
everywhere but where the summary says why they cannot."""
import json
import struct
import sys

AUDIT_ARCH_X86_64, AUDIT_ARCH_I386, AUDIT_ARCH_AARCH64 = 0xC000003E, 0x40000003, 0xC00000B7
X32_BIT = 0x40000000
RET = {0x80000000: "KILL_PROCESS", 0x00000000: "KILL_THREAD", 0x7ff00000: "LOG", 0x7fc00000: "NOTIFY",
       0x7fff0000: "ALLOW", 0x00030000: "TRAP"}


def name(v):
    if (v & 0xffff0000) == 0x00050000:
        return f"ERRNO({v & 0xffff})"
    return RET.get(v & 0xffff0000 if (v & 0xffff0000) != 0x80000000 else 0x80000000, hex(v))


def load(path):
    b = open(path, "rb").read()
    return [struct.unpack("<HBBI", b[i:i + 8]) for i in range(0, len(b), 8)]


def run(prog, data):
    A = X = 0
    M = [0] * 16
    pc = 0
    while True:
        code, jt, jf, k = prog[pc]
        cls = code & 0x07
        if cls == 0x00:                                   # LD
            mode = code & 0xe0
            if mode == 0x20:                              # ABS
                A = struct.unpack_from("<I", data, k)[0]
            elif mode == 0x60:                            # MEM
                A = M[k]
            elif mode == 0x00:                            # IMM
                A = k
            else:
                raise ValueError(f"LD mode {code:#x}")
        elif cls == 0x01:                                 # LDX
            mode = code & 0xe0
            X = M[k] if mode == 0x60 else k
        elif cls == 0x02:                                 # ST
            M[k] = A
        elif cls == 0x03:                                 # STX
            M[k] = X
        elif cls == 0x04:                                 # ALU
            op, src = code & 0xf0, (X if code & 0x08 else k)
            if op == 0x00: A = A + src
            elif op == 0x10: A = A - src
            elif op == 0x20: A = A * src
            elif op == 0x40: A = A | src
            elif op == 0x50: A = A & src
            elif op == 0x60: A = (A << src) if src < 32 else 0
            elif op == 0x70: A = A >> src
            elif op == 0x80: A = -A
            elif op == 0xa0: A = A ^ src
            else: raise ValueError(f"ALU op {code:#x}")
            A &= 0xffffffff
        elif cls == 0x05:                                 # JMP
            op, src = code & 0xf0, (X if code & 0x08 else k)
            if op == 0x00:
                pc += k + 1
                continue
            c = {0x10: A == src, 0x20: A > src, 0x30: A >= src, 0x40: (A & src) != 0}[op]
            pc += 1 + (jt if c else jf)
            continue
        elif cls == 0x06:                                 # RET
            return A if code & 0x10 else k
        elif cls == 0x07:                                 # MISC
            if code & 0xf8 == 0x00:
                X = A
            else:
                A = X
        pc += 1


def data(nr, arch, args):
    return struct.pack("<iIQ6Q", nr, arch, 0, *[a & 0xffffffffffffffff for a in args])


def main(d):
    w, o = load(f"{d}/warden.bpf"), load(f"{d}/oci.bpf")
    prof = json.load(open(f"{d}/oci.json"))
    native = AUDIT_ARCH_AARCH64 if any(s["names"] == ["linkat"] for s in prof["syscalls"]) and \
        not any(s["names"] == ["open"] for s in prof["syscalls"]) else AUDIT_ARCH_X86_64
    # argument values: every value and mask compared, their neighbours, and 0
    vals = {0, 1, 0xffffffff, 0xffffffffffffffff}
    per = {}
    for s in prof["syscalls"]:
        for a in s["args"]:
            for v in (a["value"], a["valueTwo"], a["value"] | a["valueTwo"], a["value"] ^ a["valueTwo"]):
                for x in (v, v + 1, v - 1, v | 0x100000000):
                    per.setdefault((s["nr"], a["index"]), set()).add(x & 0xffffffffffffffff)
    nrs = range(0, 600)
    cases = diffs = 0
    seen = {}
    for nr in nrs:
        argsets = [[0] * 6, [1] * 6, [0xffffffff] * 6]
        for (snr, i), vs in per.items():
            if snr == nr:
                for v in vs:
                    for base in ([0] * 6, [1] * 6):
                        a = list(base)
                        a[i] = v
                        argsets.append(a)
        # combinations of two compared arguments (the rules with two)
        idx = sorted({i for (snr, i) in per if snr == nr})
        if len(idx) >= 2:
            for v1 in per[(nr, idx[0])]:
                for v2 in per[(nr, idx[1])]:
                    a = [0] * 6
                    a[idx[0]], a[idx[1]] = v1, v2
                    argsets.append(a)
        for args in argsets:
            for arch, n in ((native, nr), (native, nr | X32_BIT), (AUDIT_ARCH_I386, nr)):
                if native == AUDIT_ARCH_AARCH64 and n != nr:
                    continue
                dd = data(n, arch, args)
                rw, ro = run(w, dd), run(o, dd)
                cases += 1
                if rw != ro:
                    key = ("x32" if n & X32_BIT else "i386" if arch == AUDIT_ARCH_I386 else "native", name(rw), name(ro))
                    seen[key] = seen.get(key, 0) + 1
                    diffs += 1
    print(f"{cases} calls compared, {diffs} decided differently")
    for (where, a, b), n in sorted(seen.items()):
        print(f"  {where}: the Warden's filter {a}, the OCI form's {b} ({n} calls)")
    native_diffs = sum(n for (where, _, _), n in seen.items() if where == "native")
    return 0 if native_diffs == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
