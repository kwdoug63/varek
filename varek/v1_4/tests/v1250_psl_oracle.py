#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1250_psl_oracle.py — an independent statement of which wildcard suffixes
v1.25 refuses (docs/security/v1.25-wildcard-host-names.md, section 2), for
test_v1250.sh to compare shared_domains.c against.

  v1250_psl_oracle.py <public_suffix_list.dat> <varek_shared_domains.txt> cases
      prints, for each line on stdin (a suffix), "refused" or "ok"
  v1250_psl_oracle.py <psl> <varek> private-cases
      prints suffixes to test: every private-section entry, a name under it,
      and the ICANN rules' public suffixes, one per line
"""
import sys


def alabel(dom):
    out = []
    for lab in dom.split("."):
        out.append(lab.lower() if lab.isascii() else "xn--" + lab.encode("punycode").decode())
    return ".".join(out)


def load(psl, varek):
    icann, icann_wild, icann_exc, shared = set(), set(), set(), set()
    section = None
    for line in open(psl, encoding="utf-8"):
        if "===BEGIN ICANN DOMAINS===" in line:
            section = "icann"
            continue
        if "===BEGIN PRIVATE DOMAINS===" in line:
            section = "private"
            continue
        line = line.strip().split()[0] if line.strip() else ""
        if not line or line.startswith("//") or section is None:
            continue
        if line.startswith("!"):
            if section == "icann":
                icann_exc.add(alabel(line[1:]))
            continue
        wild = line.startswith("*.")
        dom = alabel(line[2:] if wild else line)
        if section == "private":
            shared.add(dom)
        elif wild:
            icann_wild.add(dom)
        else:
            icann.add(dom)
    for line in open(varek, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            shared.add(line)
    return icann, icann_wild, icann_exc, shared


def refused(s, icann, icann_wild, icann_exc, shared):
    if s not in icann_exc:
        if s in icann:
            return True
        if "." in s and s.split(".", 1)[1] in icann_wild:
            return True
    labels = s.split(".")
    return any(".".join(labels[i:]) in shared for i in range(len(labels)))


def main():
    lists = load(sys.argv[1], sys.argv[2])
    if sys.argv[3] == "cases":
        for line in sys.stdin:
            s = line.strip()
            if s:
                print("refused" if refused(s, *lists) else "ok")
    else:
        icann, icann_wild, icann_exc, shared = lists
        out = set()
        for d in shared:
            out.add(d)
            out.add("tenant." + d)
        for d in icann:
            if "." in d:
                out.add(d)
                out.add("example." + d)
        for d in icann_wild:
            out.add("x." + d)
            out.add("y.x." + d)
        for d in icann_exc:
            out.add(d)
        for s in sorted(out):
            if all(c.isalnum() or c in "-." for c in s) and s.isascii():
                print(s)


if __name__ == "__main__":
    main()
