#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cdx_schema_check.py — validate BOM files against the CycloneDX 1.6 JSON
schema (v1.18.0 regression tests).

Uses the OWASP CycloneDX project's own schema files and validator, from the
cyclonedx-python-lib package, with format checking on: the JSF signature
schema's `algorithm` is "one of" a list of names or a URI, which only format
checking can tell apart (without it every signed BOM is reported invalid).

    python3 tests/cdx_schema_check.py bom.json [more.json ...]

Exit 0 if every file is valid, 1 if one is not, 2 if the validator is not
installed (pip install -r tools/requirements-test.txt).
"""
import sys


def main(paths):
    try:
        import rfc3986_validator  # noqa: F401  (enables "uri" format checking in jsonschema)
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError as e:
        print(f"cdx_schema_check: {e}; install with: pip install -r tools/requirements-test.txt",
              file=sys.stderr)
        return 2
    v = JsonStrictValidator(SchemaVersion.V1_6)
    bad = 0
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            err = v.validate_str(fh.read())
        if err:
            bad += 1
            print(f"{p}: INVALID: {str(err).splitlines()[0][:300]}")
        else:
            print(f"{p}: valid CycloneDX 1.6")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
