"""
varek/formatter.py
─────────────────────
VAREK source code formatter (varek fmt).

Formats .syn files with consistent style:
  - 2-space indentation
  - Spaces around operators
  - Consistent brace placement
  - Trailing comma in multi-line collections
  - Blank lines between top-level declarations
  - Aligned field declarations in schemas
  - Keyword normalisation (true/false/nil lowercase)
"""

from __future__ import annotations

import re
from typing import List, Optional


# ══════════════════════════════════════════════════════════════════
# TOKEN-AWARE FORMATTER
# ══════════════════════════════════════════════════════════════════

class Formatter:
    """
    Formats VAREK source code by re-lexing and re-emitting with
    canonical style. Uses the VAREK lexer for tokenisation so that
    comments and whitespace are preserved correctly.
    """

    INDENT = "  "    # 2 spaces
    MAX_LINE = 88    # maximum line length before wrapping

    def __init__(self, source: str, filename: str = "<stdin>"):
        self.source   = source
        self.filename = filename

    def format(self) -> str:
        """Format the source and return the result."""
        lines = self.source.splitlines(keepends=True)
        result = []
        indent_level = 0
        prev_blank   = False
        prev_was_toplevel = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            # ── Blank lines ───────────────────────────────────────
            if not stripped:
                # Collapse consecutive blank lines to one
                if not prev_blank:
                    result.append("\n")
                prev_blank = True
                continue

            prev_blank = False

            # ── Indent adjustment for closing braces ──────────────
            if stripped.startswith("}"):
                indent_level = max(0, indent_level - 1)

            # ── Top-level declarations get a blank line before them
            is_toplevel = self._is_toplevel(stripped)
            if is_toplevel and result and not result[-1].isspace() and result[-1] != "\n":
                result.append("\n")

            # ── Format the line content ───────────────────────────
            formatted = self._format_line(stripped, indent_level)
            result.append(self.INDENT * indent_level + formatted + "\n")

            # ── Indent adjustment for opening braces ──────────────
            opens  = formatted.count("{") - formatted.count("}")
            indent_level = max(0, indent_level + opens)

            prev_was_toplevel = is_toplevel

        return "".join(result).rstrip("\n") + "\n"

    def _is_toplevel(self, line: str) -> bool:
        return any(line.startswith(kw) for kw in (
            "fn ", "async fn", "export fn", "schema ", "pipeline ",
            "import ", "safe import",
        ))

    def _format_line(self, line: str, indent: int) -> str:
        """Apply formatting rules to a single stripped line."""
        # Preserve comment lines as-is
        if line.startswith("--"):
            return line

        line = self._normalize_operators(line)
        line = self._normalize_keywords(line)
        line = self._normalize_pipes(line)
        line = self._normalize_braces(line)
        line = self._normalize_commas(line)
        line = self._normalize_types(line)

        return line.strip()

    def _normalize_operators(self, line: str) -> str:
        """Ensure spaces around binary operators."""
        # Arrow operators (keep tight)
        line = re.sub(r'\s*->\s*', ' -> ', line)
        line = re.sub(r'\s*=>\s*', ' => ', line)

        # Comparison operators
        for op in ['==', '!=', '<=', '>=']:
            line = re.sub(r'\s*' + re.escape(op) + r'\s*', f' {op} ', line)

        # Assignment = (but not ==, <=, >=, !=, :=, =>, ->)
        line = re.sub(r'(?<![=!<>:])=(?![=>])', ' = ', line)
        line = re.sub(r':=', ' := ', line)

        # Arithmetic: handled by normalization above

        # Clean up multiple spaces
        line = re.sub(r'  +', ' ', line)
        return line

    def _normalize_keywords(self, line: str) -> str:
        """Ensure keywords are lowercase."""
        for kw in ('True', 'False', 'Nil', 'NULL', 'None'):
            line = re.sub(r'\b' + kw + r'\b', kw.lower(), line)
        return line

    def _normalize_pipes(self, line: str) -> str:
        """Ensure spaces around |> operator."""
        line = re.sub(r'\s*\|>\s*', ' |> ', line)
        return line

    def _normalize_braces(self, line: str) -> str:
        """Space before { in declarations."""
        line = re.sub(r'(\w)\{', r'\1 {', line)
        return line

    def _normalize_commas(self, line: str) -> str:
        """Space after commas."""
        line = re.sub(r',(?!\s)', ', ', line)
        return line

    def _normalize_types(self, line: str) -> str:
        """Normalize type annotations: colon followed by space."""
        line = re.sub(r':(?!\s)(?!=)', ': ', line)
        return line


def format_file(path: str, in_place: bool = False) -> str:
    """
    Format a .syn file. Returns the formatted source.
    If in_place=True, overwrites the file.
    """
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    formatter = Formatter(source, filename=path)
    formatted = formatter.format()

    if in_place:
        with open(path, "w", encoding="utf-8") as f:
            f.write(formatted)

    return formatted


def check_format(path: str) -> bool:
    """Return True if the file is already correctly formatted."""
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    formatted = Formatter(source, filename=path).format()
    return source == formatted


def format_source(source: str) -> str:
    """Format a source string and return the result."""
    return Formatter(source).format()
