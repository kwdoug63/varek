"""
varek/registry/__init__.py
──────────────────────────────
VAREK Package Registry v1.0

The registry resolves package names to downloadable archives.
In v1.0, three registry backends are supported:

  1. LOCAL  — packages/ directory in the project or ~/.syn/packages/
  2. FILE   — a local registry index (packages/index.json)
  3. REMOTE — https://packages.varek-lang.org (future)

Registry index format (packages/index.json):
  {
    "packages": {
      "core-utils": {
        "1.0.0": { "url": "...", "checksum": "sha256:...", "deps": {...} },
        "1.1.0": { ... }
      }
    }
  }

Package cache: ~/.syn/cache/<name>-<version>/
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from varek.packager import (
    Version, VersionReq, Manifest, LockedPackage, Lockfile,
    ManifestParser, extract_package, package_checksum,
)


# ── Paths ─────────────────────────────────────────────────────────

def _syn_home() -> Path:
    h = os.environ.get("SYN_HOME") or os.path.join(Path.home(), ".syn")
    p = Path(h)
    p.mkdir(parents=True, exist_ok=True)
    return p

def _cache_dir() -> Path:
    d = _syn_home() / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _registry_dir() -> Path:
    d = _syn_home() / "registry"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ══════════════════════════════════════════════════════════════════
# REGISTRY INDEX
# ══════════════════════════════════════════════════════════════════

class RegistryIndex:
    """
    In-memory view of the package registry index.
    Backed by a JSON file that can be on disk or fetched from remote.
    """

    def __init__(self, data: dict):
        self._packages: Dict[str, Dict[str, dict]] = data.get("packages", {})
        self._meta: dict = data.get("meta", {})

    @classmethod
    def empty(cls) -> "RegistryIndex":
        return cls({"packages": {}, "meta": {"version": "1.0.0"}})

    @classmethod
    def from_file(cls, path: str) -> "RegistryIndex":
        try:
            with open(path) as f:
                return cls(json.load(f))
        except (FileNotFoundError, json.JSONDecodeError):
            return cls.empty()

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"packages": self._packages,
                       "meta": self._meta}, f, indent=2)

    # ── Query ─────────────────────────────────────────────────────

    def list_packages(self) -> List[str]:
        return sorted(self._packages.keys())

    def list_versions(self, name: str) -> List[Version]:
        if name not in self._packages:
            return []
        return sorted([Version.parse(v) for v in self._packages[name].keys()])

    def latest(self, name: str) -> Optional[Version]:
        versions = [v for v in self.list_versions(name) if v.is_stable()]
        return max(versions) if versions else None

    def resolve(self, name: str, req: str) -> Optional[Tuple[Version, dict]]:
        """Find the newest version matching req."""
        vreq = VersionReq(req)
        candidates = [v for v in self.list_versions(name) if vreq.matches(v)]
        if not candidates:
            return None
        best = max(candidates)
        return best, self._packages[name][str(best)]

    def get_info(self, name: str, version: str) -> Optional[dict]:
        return self._packages.get(name, {}).get(version)

    # ── Publish ───────────────────────────────────────────────────

    def register(self, name: str, version: str, info: dict) -> None:
        if name not in self._packages:
            self._packages[name] = {}
        self._packages[name][version] = info

    def yank(self, name: str, version: str) -> bool:
        if name in self._packages and version in self._packages[name]:
            self._packages[name][version]["yanked"] = True
            return True
        return False

    def search(self, query: str) -> List[dict]:
        results = []
        q = query.lower()
        for pkg_name, versions in self._packages.items():
            if q in pkg_name.lower():
                latest = self.latest(pkg_name)
                if latest:
                    info = versions.get(str(latest), {})
                    results.append({
                        "name":        pkg_name,
                        "version":     str(latest),
                        "description": info.get("description", ""),
                        "keywords":    info.get("keywords", []),
                    })
        return sorted(results, key=lambda x: x["name"])


# ══════════════════════════════════════════════════════════════════
# REGISTRY CLIENT
# ══════════════════════════════════════════════════════════════════

OFFICIAL_REGISTRY = "https://packages.varek-lang.org"
LOCAL_INDEX_NAME  = "index.json"

class Registry:
    """
    Registry client — resolves, downloads, and caches packages.
    """

    def __init__(self, url: str = "local"):
        self.url         = url
        self._index_path = str(_registry_dir() / LOCAL_INDEX_NAME)
        self._index      = RegistryIndex.from_file(self._index_path)
        self._cache      = _cache_dir()

    # ── Index management ──────────────────────────────────────────

    def update(self) -> None:
        """Refresh the registry index from remote (if configured)."""
        if self.url == "local":
            print("  Using local registry — no update needed.")
            return
        try:
            print(f"  Fetching index from {self.url}...")
            req  = urllib.request.Request(
                f"{self.url}/index.json",
                headers={"User-Agent": "syn/1.0.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            self._index = RegistryIndex(data)
            self._index.save(self._index_path)
            print(f"  Updated: {len(self._index.list_packages())} packages.")
        except Exception as e:
            print(f"  Warning: registry update failed: {e}")

    def save_index(self) -> None:
        self._index.save(self._index_path)

    # ── Resolution ────────────────────────────────────────────────

    def resolve(self, name: str, req: str = "*") -> Optional[Tuple[Version, dict]]:
        return self._index.resolve(name, req)

    def search(self, query: str) -> List[dict]:
        return self._index.search(query)

    def info(self, name: str) -> Optional[dict]:
        latest = self._index.latest(name)
        if latest is None:
            return None
        return self._index.get_info(name, str(latest))

    # ── Installation ──────────────────────────────────────────────

    def install(
        self,
        name: str,
        req:  str = "*",
        target_dir: Optional[str] = None,
    ) -> Optional[LockedPackage]:
        """
        Resolve and install a package. Returns a LockedPackage on success.
        """
        result = self.resolve(name, req)
        if result is None:
            return None

        version, info = result
        cache_key = f"{name}-{version}"
        cache_path = self._cache / cache_key

        if cache_path.exists():
            # Already cached
            pkg_path = str(cache_path / f"{cache_key}.varekpkg")
        else:
            # Download
            pkg_url = info.get("url", "")
            if not pkg_url:
                # Local package — look in packages/ directory
                local_path = Path("packages") / f"{cache_key}.varekpkg"
                if local_path.exists():
                    cache_path.mkdir(parents=True, exist_ok=True)
                    pkg_path = str(local_path)
                else:
                    return None
            else:
                try:
                    cache_path.mkdir(parents=True, exist_ok=True)
                    pkg_path = str(cache_path / f"{cache_key}.varekpkg")
                    urllib.request.urlretrieve(pkg_url, pkg_path)
                except Exception as e:
                    print(f"  Download failed: {e}")
                    return None

        # Verify checksum
        with open(pkg_path, "rb") as f:
            data     = f.read()
            checksum = package_checksum(data)
            expected = info.get("checksum", "")
            if expected and checksum != expected:
                print(f"  Checksum mismatch for {name}!")
                return None

        # Extract to target
        if target_dir:
            extract_path = os.path.join(target_dir, name)
            os.makedirs(extract_path, exist_ok=True)
            try:
                extract_package(pkg_path, extract_path)
            except Exception as e:
                print(f"  Extraction failed: {e}")
                return None

        return LockedPackage(
            name=name, version=str(version),
            checksum=checksum, source="registry",
            resolved=pkg_path,
        )

    def install_from_manifest(
        self,
        manifest: Manifest,
        project_dir: str,
        include_dev: bool = False,
    ) -> Lockfile:
        """Install all dependencies from a manifest. Returns a lockfile."""
        lockfile   = Lockfile(varek_version="1.0.0")
        deps_dir   = os.path.join(project_dir, ".syn", "deps")
        os.makedirs(deps_dir, exist_ok=True)

        all_deps = dict(manifest.dependencies)
        if include_dev:
            all_deps.update(manifest.dev_deps)

        for name, req in all_deps.items():
            print(f"  Installing {name} {req}...")
            locked = self.install(name, req, target_dir=deps_dir)
            if locked:
                lockfile.packages.append(locked)
                print(f"  ✓ {name} {locked.version}")
            else:
                print(f"  ✗ {name} not found in registry")

        lockfile_path = os.path.join(project_dir, "varek.lock")
        lockfile.save(lockfile_path)
        return lockfile

    # ── Publishing ────────────────────────────────────────────────

    def publish_local(self, pkg_path: str) -> bool:
        """
        Publish a package to the local registry.
        Used for development and testing.
        """
        if not os.path.exists(pkg_path):
            print(f"Package not found: {pkg_path}")
            return False

        try:
            # Extract manifest from archive
            with tempfile.TemporaryDirectory() as tmp:
                manifest = extract_package(pkg_path, tmp)
                name     = manifest.package.name
                version  = str(manifest.package.version)

            # Copy to packages/ directory
            os.makedirs("packages", exist_ok=True)
            dest = f"packages/{name}-{version}.varekpkg"
            shutil.copy2(pkg_path, dest)

            # Compute checksum
            with open(dest, "rb") as f:
                checksum = package_checksum(f.read())

            # Register in index
            self._index.register(name, version, {
                "url":         "",   # local
                "checksum":    checksum,
                "description": manifest.package.description,
                "keywords":    manifest.package.keywords,
                "deps":        manifest.dependencies,
            })
            self.save_index()
            print(f"  ✓ Published {name} {version} to local registry")
            return True
        except Exception as e:
            print(f"  ✗ Publish failed: {e}")
            return False

    def yank(self, name: str, version: str) -> bool:
        ok = self._index.yank(name, version)
        if ok:
            self.save_index()
        return ok
