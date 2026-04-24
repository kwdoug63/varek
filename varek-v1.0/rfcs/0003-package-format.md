# RFC 0003 — Package Format and Registry Protocol

| Field       | Value |
|-------------|-------|
| RFC Number  | 0003 |
| Title       | VAREK Package Format (.varekpkg) and Registry Protocol |
| Author(s)   | Kenneth Wayne Douglas, MD |
| Status      | Implemented |
| Created     | 2026-01-01 |
| Discussion  | https://github.com/varek-lang/varek/discussions/3 |

---

## Summary

Define the canonical VAREK package format (.varekpkg), the project manifest
(varek.toml), the lockfile (varek.lock), and the registry index protocol that
together form the VAREK package ecosystem.

---

## Motivation

A package manager without a stable format cannot build a reliable ecosystem.
This RFC locks down the formats so that packages created today will be
installable by future versions of `varek`.

---

## Detailed Design

### Package archive (.varekpkg)

A `.varekpkg` file is a gzip-compressed tar archive containing:

```
my-package-1.0.0/
├── varek.toml          (required)
├── README.md         (recommended)
├── LICENSE           (recommended)
├── src/
│   └── *.syn
└── tests/
    └── *.syn
```

The archive MUST NOT include:
- Build artifacts (`target/`, `*.ll`, `*.o`, `*.s`)
- Dependency directories (`.syn/deps/`)
- Version control directories (`.git/`)

### Manifest (varek.toml)

```toml
[package]
name        = "my-package"
version     = "1.0.0"
authors     = ["Author Name"]
license     = "MIT"
description = "A VAREK package"
varek     = ">=1.0.0"

[dependencies]
"core-utils" = "^1.0.0"

[build]
target    = "interpret"
opt_level = 2

[scripts]
main  = "src/main.syn"
test  = "tests/run.syn"
```

### Lockfile (varek.lock)

```json
{
  "varek-version": "1.0.0",
  "packages": [
    {
      "name":     "core-utils",
      "version":  "1.2.3",
      "checksum": "sha256:abcdef...",
      "source":   "registry",
      "resolved": "https://packages.varek-lang.org/core-utils-1.2.3.varekpkg"
    }
  ]
}
```

The lockfile is committed to version control for applications, not for libraries.

### Registry index format

```json
{
  "meta": { "version": "1.0.0" },
  "packages": {
    "my-package": {
      "1.0.0": {
        "url":         "https://...",
        "checksum":    "sha256:...",
        "description": "...",
        "keywords":    ["ai", "ml"],
        "deps":        { "core-utils": "^1.0.0" }
      }
    }
  }
}
```

### Version requirement syntax

| Syntax    | Meaning |
|-----------|---------|
| `^1.2.3`  | Compatible: same major, ≥ minor.patch |
| `~1.2.3`  | Patch-level: same major.minor, ≥ patch |
| `>=1.0`   | Greater than or equal |
| `>1.0`    | Strictly greater than |
| `=1.0.0`  | Exact match |
| `*`       | Any version |

### Checksum format

`sha256:<64 hex digits>` of the raw archive bytes.

### Breaking changes

None — this is a new feature.

---

## Implementation

Implemented in:
- `varek/packager.py` — Version, VersionReq, Manifest, ManifestParser, Lockfile
- `varek/registry/__init__.py` — RegistryIndex, Registry
- `varek_cli.py` — `varek new`, `varek install`, `varek publish`, `varek search`

Status: ✅ Implemented in v1.0
