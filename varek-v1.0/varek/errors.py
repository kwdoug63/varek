"""
varek/errors.py
─────────────────
Structured error types for the VAREK compiler front-end.
All errors carry source location (file, line, column) and
a human-readable message with optional hint text.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List


# ── Source Location ────────────────────────────────────────────

@dataclass(frozen=True)
class Span:
    """Half-open [start, end) byte range within a source file."""
    file:   str
    line:   int
    col:    int
    end_line: int = 0
    end_col:  int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"

    @classmethod
    def unknown(cls) -> "Span":
        return cls(file="<unknown>", line=0, col=0)


# ── Base Error ─────────────────────────────────────────────────

@dataclass
class VarekError(Exception):
    """Base class for all VAREK compiler errors."""
    message: str
    span:    Span
    hint:    Optional[str] = None
    notes:   List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"error: {self.message}", f"  --> {self.span}"]
        if self.hint:
            lines.append(f"  hint: {self.hint}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return str(self)


# ── Lexer Errors ───────────────────────────────────────────────

class LexError(VarekError):
    """Raised when the lexer encounters invalid input."""


class UnterminatedStringError(LexError):
    """String literal was not closed before end of line or file."""
    def __init__(self, span: Span):
        super().__init__(
            message="unterminated string literal",
            span=span,
            hint='add a closing `"` to end the string',
        )


class InvalidEscapeError(LexError):
    """Unknown escape sequence inside a string literal."""
    def __init__(self, char: str, span: Span):
        super().__init__(
            message=f"invalid escape sequence `\\{char}`",
            span=span,
            hint=r'valid escapes: \" \\ \n \t \r \0 \u{...}',
        )


class UnexpectedCharError(LexError):
    """Character that cannot start any valid token."""
    def __init__(self, char: str, span: Span):
        super().__init__(
            message=f"unexpected character `{char}`",
            span=span,
        )


# ── Parse Errors ───────────────────────────────────────────────

class ParseError(VarekError):
    """Raised when the parser cannot match expected grammar."""


class UnexpectedTokenError(ParseError):
    """Got a different token than what was expected."""
    def __init__(self, expected: str, got: str, span: Span):
        super().__init__(
            message=f"expected {expected}, found `{got}`",
            span=span,
        )


class UnexpectedEOFError(ParseError):
    """Input ended before the grammar was satisfied."""
    def __init__(self, expected: str, span: Span):
        super().__init__(
            message=f"unexpected end of file, expected {expected}",
            span=span,
        )


class InvalidSyntaxError(ParseError):
    """Catch-all for syntactically invalid constructs."""


# ── Error Accumulator ──────────────────────────────────────────

class ErrorBag:
    """
    Collects multiple errors so the compiler can report all issues
    in a single pass rather than stopping at the first one.
    """

    def __init__(self):
        self._errors: List[VarekError] = []

    def add(self, err: VarekError) -> None:
        self._errors.append(err)

    def has_errors(self) -> bool:
        return len(self._errors) > 0

    def __len__(self) -> int:
        return len(self._errors)

    def __iter__(self):
        return iter(self._errors)

    def report(self, source_lines: Optional[List[str]] = None) -> str:
        """Render all collected errors with optional source context."""
        parts = []
        for err in self._errors:
            parts.append(str(err))
            if source_lines and 0 < err.span.line <= len(source_lines):
                line_text = source_lines[err.span.line - 1]
                col = max(0, err.span.col - 1)
                parts.append(f"  {err.span.line:4d} | {line_text}")
                parts.append(f"       | {' ' * col}^")
            parts.append("")
        if self._errors:
            n = len(self._errors)
            parts.append(f"aborting due to {n} error{'s' if n != 1 else ''}")
        return "\n".join(parts)

    def raise_if_any(self, source_lines: Optional[List[str]] = None) -> None:
        if self.has_errors():
            raise VarekError(
                message=self.report(source_lines),
                span=self._errors[0].span,
            )
