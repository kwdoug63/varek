#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ocsf_validate.py — v1.31 (docs/security/v1.31-standards.md, section 1):
check OCSF events against the OCSF 1.9.0 schema vendored in
schemas/ocsf-1.9.0/schema.json (the OCSF project's own schema files,
compiled by its own compiler: schemas/ocsf-1.9.0/README.md). No network,
no OCSF software.

    python3 tests/ocsf_validate.py EVENTS.jsonl [more ...]

One event per line. Each event is checked as OCSF defines one:
  - class_uid names a class of the schema; category_uid is its category;
    activity_id is one of the class's activities; type_uid is
    class_uid * 100 + activity_id;
  - metadata.profiles names only profiles the schema has; an attribute a
    profile adds is allowed only when the event declares that profile;
  - every attribute is one the class (or the object) defines, every
    required one is there, and each at_least_one / just_one constraint
    holds;
  - every value has its attribute's type (objects checked the same way,
    recursively; arrays as arrays), every enumerated value is one of its
    enum's, and a caption sibling (activity_name, ...) is its enum's caption
    unless the value is 99 (Other);
  - unmapped, and json_t values, are free-form.
Exit 0 if every event is valid, 1 if one is not (each problem printed).
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "..", "schemas", "ocsf-1.9.0", "schema.json")

BASE = {"string_t": str, "integer_t": int, "long_t": int, "float_t": (int, float), "boolean_t": bool}


class Checker:
    def __init__(self, path=SCHEMA):
        self.s = json.load(open(path))
        self.by_uid = {c["uid"]: c for c in self.s["classes"].values()}

    def base(self, t):
        seen = set()
        while t in self.s["types"] and t not in BASE and t != "json_t" and t not in seen:
            seen.add(t)
            nt = self.s["types"][t].get("type")
            if not nt:
                break
            t = nt
        return t

    def attrs(self, defs, profiles):
        return {k: a for k, a in defs.items() if a.get("profile") is None or a.get("profile") in profiles}

    def obj(self, v, defs, constraints, path, profiles, out):
        if not isinstance(v, dict):
            out.append(f"{path}: not an object")
            return
        attrs = self.attrs(defs, profiles)
        for k in v:
            if k not in attrs:
                out.append(f"{path}.{k}: not an attribute of this {'class' if path == '' else 'object'}"
                           f"{' (or its profile is not declared)' if k in defs else ''}")
        for k, a in attrs.items():
            if a.get("requirement") == "required" and k not in v:
                out.append(f"{path}.{k}: required, and missing")
        for kind, names in (constraints or {}).items():
            n = sum(1 for x in names if x in v)
            if kind == "at_least_one" and n < 1:
                out.append(f"{path}: needs at least one of {names}")
            elif kind == "just_one" and n != 1:
                out.append(f"{path}: needs exactly one of {names}")
        for k, x in v.items():
            a = attrs.get(k)
            if a is None:
                continue
            self.value(x, a, f"{path}.{k}", profiles, out)
            sib = a.get("sibling")
            en = a.get("enum")
            if sib and en and sib in v and not isinstance(x, bool) and isinstance(x, int) and x != 99 \
                    and str(x) in en and v[sib] != en[str(x)].get("caption"):
                out.append(f"{path}.{sib}: {v[sib]!r} is not the caption of {k} {x} ({en[str(x)].get('caption')!r})")

    def value(self, x, a, path, profiles, out):
        if a.get("is_array"):
            if not isinstance(x, list):
                out.append(f"{path}: not an array")
                return
            for i, y in enumerate(x):
                self.scalar(y, a, f"{path}[{i}]", profiles, out)
        else:
            self.scalar(x, a, path, profiles, out)

    def scalar(self, x, a, path, profiles, out):
        t = a.get("type")
        if t == "object":                      # free-form (unmapped, xattributes)
            if not isinstance(x, dict):
                out.append(f"{path}: not an object")
            return
        if t in self.s["objects"]:
            o = self.s["objects"][t]
            self.obj(x, o["attributes"], o.get("constraints"), path, profiles, out)
            return
        b = self.base(t)
        if b == "json_t":
            return
        py = BASE.get(b)
        if py is None:
            out.append(f"{path}: type {t} is not in the schema")
            return
        if isinstance(x, bool) and b != "boolean_t" or not isinstance(x, py):
            out.append(f"{path}: {x!r} is not a {t}")
            return
        en = a.get("enum")
        if en and str(x) not in en:
            out.append(f"{path}: {x!r} is not one of its enum's values")
        td = self.s["types"].get(t) or {}
        mx, rx, rg = td.get("max_len"), td.get("regex"), td.get("range")
        if mx and isinstance(x, str) and len(x) > mx:
            out.append(f"{path}: longer than {mx}")
        if rx and isinstance(x, str) and not re.search(rx, x):
            out.append(f"{path}: {x!r} is not in {t}'s form")
        if rg and isinstance(x, int) and not rg[0] <= x <= rg[1]:
            out.append(f"{path}: {x} is outside {t}'s range {rg}")

    def event(self, ev):
        out = []
        if not isinstance(ev, dict):
            return ["the event is not an object"]
        c = self.by_uid.get(ev.get("class_uid"))
        if c is None:
            return [f"class_uid {ev.get('class_uid')!r} is not a class of the vendored schema"]
        md = ev.get("metadata") if isinstance(ev.get("metadata"), dict) else {}
        profiles = md.get("profiles", [])
        if not isinstance(profiles, list) or any(p not in self.s["profiles"] for p in profiles):
            out.append(f"metadata.profiles {profiles!r}: only {self.s['profiles']} are in the vendored schema")
            profiles = [p for p in profiles if p in self.s["profiles"]] if isinstance(profiles, list) else []
        if md.get("version") != self.s["version"]:
            out.append(f"metadata.version {md.get('version')!r} is not {self.s['version']}")
        self.obj(ev, c["attributes"], c.get("constraints"), "", set(profiles), out)
        cat = self.s["categories"].get(c.get("category"), {})
        if ev.get("category_uid") != cat.get("uid"):
            out.append(f"category_uid {ev.get('category_uid')!r} is not {c['name']}'s ({cat.get('uid')})")
        act = ev.get("activity_id")
        if isinstance(act, int) and ev.get("type_uid") != c["uid"] * 100 + act:
            out.append(f"type_uid {ev.get('type_uid')!r} is not class_uid * 100 + activity_id")
        return out


def main(paths):
    ck = Checker()
    bad = n = 0
    for p in paths:
        for i, line in enumerate(open(p, encoding="utf-8"), 1):
            if not line.strip():
                continue
            n += 1
            try:
                ev = json.loads(line)
            except ValueError as e:
                print(f"{p}:{i}: not JSON ({e})")
                bad += 1
                continue
            probs = ck.event(ev)
            if probs:
                bad += 1
                for x in probs[:20]:
                    print(f"{p}:{i}: {x}")
    print(f"ocsf_validate: {n} events, {bad} invalid ({'FAIL' if bad else 'valid OCSF 1.9.0'})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
