"""
varek/packager.py
────────────────────
VAREK package format and manifest parser.

Package manifest: varek.toml

  [package]
  name    = "my-pipeline"
  version = "1.0.0"
  authors = ["Kenneth Wayne Douglas, MD"]
  license = "MIT"
  description = "An AI/ML pipeline package"
  homepage = "https://github.com/author/my-pipeline"
  keywords = ["ai", "ml", "pipeline"]
  varek = ">=1.0.0"

  [dependencies]
  "core-utils" = "^1.2.0"
  "tensor-ext" = { version = ">=0.9", registry = "https://packages.varek-lang.org" }

  [dev-dependencies]
  "test-helpers" = "^1.0.0"

  [build]
  target    = "native"   # or "interpret"
  opt_level = 2
  emit      = ["ir", "obj"]

  [scripts]
  main  = "src/main.syn"
  test  = "tests/run_all.syn"
  bench = "benchmarks/bench.syn"

Lockfile: varek.lock  (JSON, auto-generated, not hand-edited)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import io
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# SEMVER
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int
    pre:   str = ""   # e.g. "alpha.1", "beta.2", "rc.1"

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.pre}" if self.pre else base

    @classmethod
    def parse(cls, s: str) -> "Version":
        s = s.strip().lstrip("v")
        pre = ""
        if "-" in s:
            s, pre = s.split("-", 1)
        parts = s.split(".")
        try:
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return cls(major, minor, patch, pre)
        except (ValueError, IndexError):
            return cls(0, 0, 0, s)

    def is_stable(self) -> bool:
        return self.pre == ""

    def bump_patch(self) -> "Version":
        return Version(self.major, self.minor, self.patch + 1)

    def bump_minor(self) -> "Version":
        return Version(self.major, self.minor + 1, 0)

    def bump_major(self) -> "Version":
        return Version(self.major + 1, 0, 0)


class VersionReq:
    """
    A version requirement expression.
    Supports: ^1.2.3  >=1.0  >1.0  <2.0  =1.0.0  *  ~1.2
    """
    def __init__(self, spec: str):
        self._spec = spec.strip()

    def matches(self, version: Version) -> bool:
        s = self._spec
        if s == "*":
            return True
        if s.startswith("^"):
            req = Version.parse(s[1:])
            # Compatible: same major, >= minor
            return (version.major == req.major and
                    version >= req)
        if s.startswith("~"):
            req = Version.parse(s[1:])
            return (version.major == req.major and
                    version.minor == req.minor and
                    version >= req)
        if s.startswith(">="):
            return version >= Version.parse(s[2:])
        if s.startswith(">"):
            return version > Version.parse(s[1:])
        if s.startswith("<="):
            return version <= Version.parse(s[2:])
        if s.startswith("<"):
            return version < Version.parse(s[1:])
        if s.startswith("="):
            return version == Version.parse(s[1:])
        # Bare version = exact match
        return version == Version.parse(s)

    def __str__(self) -> str:
        return self._spec


# ══════════════════════════════════════════════════════════════════
# MANIFEST (varek.toml)
# ══════════════════════════════════════════════════════════════════

@dataclass
class PackageMeta:
    name:        str
    version:     Version
    authors:     List[str]       = field(default_factory=list)
    license:     str             = "MIT"
    description: str             = ""
    homepage:    str             = ""
    repository:  str             = ""
    keywords:    List[str]       = field(default_factory=list)
    varek_req: str             = ">=1.0.0"
    readme:      str             = "README.md"


@dataclass
class BuildConfig:
    target:    str   = "interpret"   # "interpret" | "native"
    opt_level: int   = 2
    emit:      List[str] = field(default_factory=lambda: ["ir"])


@dataclass
class Manifest:
    package:      PackageMeta
    dependencies: Dict[str, str]      = field(default_factory=dict)  # name → req
    dev_deps:     Dict[str, str]      = field(default_factory=dict)
    build:        BuildConfig         = field(default_factory=BuildConfig)
    scripts:      Dict[str, str]      = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "package": {
                "name":        self.package.name,
                "version":     str(self.package.version),
                "authors":     self.package.authors,
                "license":     self.package.license,
                "description": self.package.description,
                "homepage":    self.package.homepage,
                "keywords":    self.package.keywords,
                "varek":     self.package.varek_req,
            },
            "dependencies":     self.dependencies,
            "dev-dependencies": self.dev_deps,
            "build": {
                "target":    self.build.target,
                "opt_level": self.build.opt_level,
                "emit":      self.build.emit,
            },
            "scripts": self.scripts,
        }


class ManifestParser:
    """
    Minimal TOML-compatible manifest parser.
    Parses the varek.toml format without requiring the toml package.
    """

    @classmethod
    def parse_file(cls, path: str) -> Manifest:
        with open(path, "r", encoding="utf-8") as f:
            return cls.parse(f.read())

    @classmethod
    def parse(cls, text: str) -> Manifest:
        sections: Dict[str, Dict] = {"package": {}, "dependencies": {},
                                      "dev-dependencies": {}, "build": {},
                                      "scripts": {}}
        current = None

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                if current not in sections:
                    sections[current] = {}
                continue

            # Key = value
            if "=" in line and current is not None:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                sections[current][key] = cls._parse_value(val)

        p = sections.get("package", {})
        meta = PackageMeta(
            name        = p.get("name", "unnamed"),
            version     = Version.parse(str(p.get("version", "0.1.0"))),
            authors     = cls._to_list(p.get("authors", [])),
            license     = str(p.get("license", "MIT")),
            description = str(p.get("description", "")),
            homepage    = str(p.get("homepage", "")),
            repository  = str(p.get("repository", "")),
            keywords    = cls._to_list(p.get("keywords", [])),
            varek_req = str(p.get("varek", ">=1.0.0")),
            readme      = str(p.get("readme", "README.md")),
        )

        b = sections.get("build", {})
        build = BuildConfig(
            target    = str(b.get("target", "interpret")),
            opt_level = int(b.get("opt_level", 2)),
            emit      = cls._to_list(b.get("emit", ["ir"])),
        )

        def _strip_key(k): return k.strip().strip('"').strip("'")

        return Manifest(
            package      = meta,
            dependencies = {_strip_key(k): str(v) for k, v in sections.get("dependencies", {}).items()},
            dev_deps     = {_strip_key(k): str(v) for k, v in sections.get("dev-dependencies", {}).items()},
            build        = build,
            scripts      = {k: str(v) for k, v in sections.get("scripts", {}).items()},
        )

    @classmethod
    def write(cls, manifest: Manifest, path: str) -> None:
        lines = []
        p = manifest.package

        lines.append("[package]")
        lines.append(f'name        = "{p.name}"')
        lines.append(f'version     = "{p.version}"')
        if p.authors:
            authors_str = ", ".join(f'"{a}"' for a in p.authors)
            lines.append(f"authors     = [{authors_str}]")
        lines.append(f'license     = "{p.license}"')
        if p.description:
            lines.append(f'description = "{p.description}"')
        if p.homepage:
            lines.append(f'homepage    = "{p.homepage}"')
        if p.keywords:
            kw_str = ", ".join(f'"{k}"' for k in p.keywords)
            lines.append(f"keywords    = [{kw_str}]")
        lines.append(f'varek     = "{p.varek_req}"')
        lines.append("")

        if manifest.dependencies:
            lines.append("[dependencies]")
            for name, req in manifest.dependencies.items():
                lines.append(f'"{name}" = "{req}"')
            lines.append("")

        if manifest.dev_deps:
            lines.append("[dev-dependencies]")
            for name, req in manifest.dev_deps.items():
                lines.append(f'"{name}" = "{req}"')
            lines.append("")

        lines.append("[build]")
        lines.append(f'target    = "{manifest.build.target}"')
        lines.append(f"opt_level = {manifest.build.opt_level}")
        emit_str = ", ".join(f'"{e}"' for e in manifest.build.emit)
        lines.append(f"emit      = [{emit_str}]")
        lines.append("")

        if manifest.scripts:
            lines.append("[scripts]")
            for name, path_ in manifest.scripts.items():
                lines.append(f'{name} = "{path_}"')
            lines.append("")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    @staticmethod
    def _parse_value(s: str):
        s = s.strip()
        # Array
        if s.startswith("[") and s.endswith("]"):
            inner = s[1:-1].strip()
            if not inner:
                return []
            parts = [p.strip().strip('"').strip("'") for p in inner.split(",")]
            return [p for p in parts if p]
        # String
        if (s.startswith('"') and s.endswith('"')) or \
           (s.startswith("'") and s.endswith("'")):
            return s[1:-1]
        # Integer
        try:
            return int(s)
        except ValueError:
            pass
        # Float
        try:
            return float(s)
        except ValueError:
            pass
        # Bool
        if s.lower() == "true":  return True
        if s.lower() == "false": return False
        return s

    @staticmethod
    def _to_list(v) -> list:
        if isinstance(v, list):  return v
        if isinstance(v, str):   return [v] if v else []
        return []


# ══════════════════════════════════════════════════════════════════
# LOCKFILE
# ══════════════════════════════════════════════════════════════════

@dataclass
class LockedPackage:
    name:     str
    version:  str
    checksum: str
    source:   str   # "registry" | "path" | "git"
    resolved: str   # exact URL or path

@dataclass
class Lockfile:
    varek_version: str = "1.0.0"
    packages: List[LockedPackage] = field(default_factory=list)

    def save(self, path: str) -> None:
        data = {
            "varek-version": self.varek_version,
            "packages": [
                {"name": p.name, "version": p.version,
                 "checksum": p.checksum, "source": p.source,
                 "resolved": p.resolved}
                for p in self.packages
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "Lockfile":
        try:
            with open(path) as f:
                data = json.load(f)
            pkgs = [
                LockedPackage(
                    name=p["name"], version=p["version"],
                    checksum=p.get("checksum",""),
                    source=p.get("source","registry"),
                    resolved=p.get("resolved","")
                )
                for p in data.get("packages", [])
            ]
            return cls(
                varek_version=data.get("varek-version","1.0.0"),
                packages=pkgs
            )
        except (FileNotFoundError, json.JSONDecodeError):
            return cls()


# ══════════════════════════════════════════════════════════════════
# PACKAGE ARCHIVE
# ══════════════════════════════════════════════════════════════════

PACKAGE_INCLUDE = {".syn", ".toml", ".md", ".txt", ".json", ".ebnf"}
PACKAGE_EXCLUDE = {"__pycache__", ".git", ".varek_cache", "target", "node_modules"}

def package_checksum(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def create_package(project_dir: str, output_path: Optional[str] = None) -> str:
    """
    Create a .varekpkg archive from a project directory.
    Returns the path to the created archive.
    """
    manifest_path = os.path.join(project_dir, "varek.toml")
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"varek.toml not found in {project_dir}")

    manifest = ManifestParser.parse_file(manifest_path)
    pkg_name  = f"{manifest.package.name}-{manifest.package.version}.varekpkg"
    out_path  = output_path or os.path.join(project_dir, "target", pkg_name)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(project_dir):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in PACKAGE_EXCLUDE]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext   = os.path.splitext(fname)[1]
                if ext in PACKAGE_INCLUDE or fname in ("varek.toml", "README.md", "LICENSE"):
                    arcname = os.path.relpath(fpath, project_dir)
                    tar.add(fpath, arcname=arcname)

    data = buf.getvalue()
    with open(out_path, "wb") as f:
        f.write(data)

    return out_path


def extract_package(pkg_path: str, target_dir: str) -> Manifest:
    """Extract a .varekpkg archive and return its manifest."""
    with tarfile.open(pkg_path, "r:gz") as tar:
        tar.extractall(target_dir)

    manifest_path = os.path.join(target_dir, "varek.toml")
    if not os.path.exists(manifest_path):
        raise FileNotFoundError("Package missing varek.toml")
    return ManifestParser.parse_file(manifest_path)
