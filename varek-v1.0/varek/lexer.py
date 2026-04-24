"""
varek/lexer.py
────────────────
Full lexer (tokeniser) for the VAREK language.

Converts a source string into a flat list of Token objects.
Every token carries its type, value, and source span so that
downstream stages (parser, diagnostics) always have precise
location information.

Usage:
    from varek.lexer import Lexer
    tokens = Lexer(source, filename="main.syn").tokenize()
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional

from varek.errors import (
    Span, ErrorBag,
    UnterminatedStringError, InvalidEscapeError, UnexpectedCharError,
)


# ══════════════════════════════════════════════════════════════════
# TOKEN TYPE ENUM
# ══════════════════════════════════════════════════════════════════

class TT(Enum):
    # ── Literals ──────────────────────────────────────────────
    INT         = auto()   # 42  0xFF  0b1010
    FLOAT       = auto()   # 3.14  1e-5
    STRING      = auto()   # "hello"  'world'
    BOOL        = auto()   # true | false
    NIL         = auto()   # nil

    # ── Identifier ────────────────────────────────────────────
    IDENT       = auto()   # user-defined names

    # ── Keywords ──────────────────────────────────────────────
    AND         = auto()
    AS          = auto()
    ASYNC       = auto()
    AWAIT       = auto()
    ELSE        = auto()
    EXPORT      = auto()
    FN          = auto()
    FOR         = auto()
    IF          = auto()
    IMPORT      = auto()
    IN          = auto()
    LET         = auto()
    MATCH       = auto()
    MUT         = auto()
    NOT         = auto()
    OR          = auto()
    PIPELINE    = auto()
    RETURN      = auto()
    SAFE        = auto()
    SCHEMA      = auto()

    # ── Operators ─────────────────────────────────────────────
    PIPE_FWD    = auto()   # |>
    ARROW       = auto()   # ->
    FAT_ARROW   = auto()   # =>
    SCOPE       = auto()   # ::
    WALRUS      = auto()   # :=
    EQ          = auto()   # ==
    NEQ         = auto()   # !=
    LTE         = auto()   # <=
    GTE         = auto()   # >=
    LT          = auto()   # <
    GT          = auto()   # >
    ASSIGN      = auto()   # =
    PLUS        = auto()   # +
    MINUS       = auto()   # -
    STAR        = auto()   # *
    SLASH       = auto()   # /
    PERCENT     = auto()   # %
    QMARK       = auto()   # ?
    BANG        = auto()   # !

    # ── Delimiters ────────────────────────────────────────────
    LPAREN      = auto()   # (
    RPAREN      = auto()   # )
    LBRACE      = auto()   # {
    RBRACE      = auto()   # }
    LBRACK      = auto()   # [
    RBRACK      = auto()   # ]
    COMMA       = auto()   # ,
    COLON       = auto()   # :
    DOT         = auto()   # .
    SEMICOLON   = auto()   # ;

    # ── Special ───────────────────────────────────────────────
    NEWLINE     = auto()
    EOF         = auto()


# ── Keyword map ───────────────────────────────────────────────

KEYWORDS: dict[str, TT] = {
    "and":      TT.AND,
    "as":       TT.AS,
    "async":    TT.ASYNC,
    "await":    TT.AWAIT,
    "else":     TT.ELSE,
    "export":   TT.EXPORT,
    "false":    TT.BOOL,
    "fn":       TT.FN,
    "for":      TT.FOR,
    "if":       TT.IF,
    "import":   TT.IMPORT,
    "in":       TT.IN,
    "let":      TT.LET,
    "match":    TT.MATCH,
    "mut":      TT.MUT,
    "nil":      TT.NIL,
    "not":      TT.NOT,
    "or":       TT.OR,
    "pipeline": TT.PIPELINE,
    "return":   TT.RETURN,
    "safe":     TT.SAFE,
    "schema":   TT.SCHEMA,
    "true":     TT.BOOL,
}


# ══════════════════════════════════════════════════════════════════
# TOKEN
# ══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Token:
    type:  TT
    value: object          # Python-typed value (int, float, str, bool, None)
    span:  Span

    # ── Convenience ───────────────────────────────────────────

    @property
    def line(self) -> int:
        return self.span.line

    @property
    def col(self) -> int:
        return self.span.col

    def is_keyword(self) -> bool:
        return self.type in KEYWORDS.values()

    def __repr__(self) -> str:
        val = f" {self.value!r}" if self.value is not None else ""
        return f"Token({self.type.name}{val}, {self.span.line}:{self.span.col})"

    def __str__(self) -> str:
        return repr(self)


# ── Sentinel EOF token ────────────────────────────────────────

def eof_token(filename: str, line: int, col: int) -> Token:
    return Token(TT.EOF, None, Span(filename, line, col))


# ══════════════════════════════════════════════════════════════════
# LEXER
# ══════════════════════════════════════════════════════════════════

class Lexer:
    """
    Single-pass lexer for VAREK source text.

    After construction call `tokenize()` to obtain the full token
    list. Errors are collected in `self.errors` (an ErrorBag);
    the lexer attempts to recover and continue after each error so
    that all problems are reported in one pass.

    The returned list always ends with an EOF token.
    """

    def __init__(self, source: str, filename: str = "<stdin>"):
        self.source:   str      = source
        self.filename: str      = filename
        self.errors:   ErrorBag = ErrorBag()

        self._pos:  int = 0      # current byte position
        self._line: int = 1      # 1-based
        self._col:  int = 1      # 1-based
        self._tokens: List[Token] = []

    # ── Public API ────────────────────────────────────────────

    def tokenize(self) -> List[Token]:
        """Lex the entire source and return all tokens."""
        while not self._at_end():
            self._skip_whitespace_and_comments()
            if self._at_end():
                break
            tok = self._next_token()
            if tok is not None:
                self._tokens.append(tok)

        self._tokens.append(eof_token(self.filename, self._line, self._col))
        return self._tokens

    # ── Internal helpers ──────────────────────────────────────

    def _at_end(self) -> bool:
        return self._pos >= len(self.source)

    def _peek(self, offset: int = 0) -> str:
        idx = self._pos + offset
        return self.source[idx] if idx < len(self.source) else "\x00"

    def _advance(self) -> str:
        ch = self.source[self._pos]
        self._pos += 1
        if ch == "\n":
            self._line += 1
            self._col = 1
        else:
            self._col += 1
        return ch

    def _match(self, expected: str) -> bool:
        if not self._at_end() and self._peek() == expected:
            self._advance()
            return True
        return False

    def _span(self, start_line: int, start_col: int) -> Span:
        return Span(
            file=self.filename,
            line=start_line,
            col=start_col,
            end_line=self._line,
            end_col=self._col,
        )

    def _make(self, tt: TT, value: object,
              line: int, col: int) -> Token:
        return Token(tt, value, self._span(line, col))

    # ── Whitespace and comments ───────────────────────────────

    def _skip_whitespace_and_comments(self):
        while not self._at_end():
            ch = self._peek()

            if ch in " \t\r":
                self._advance()

            elif ch == "\n":
                self._advance()          # skip bare newlines (not significant)

            elif ch == "-" and self._peek(1) == "-" and self._peek(2) == "-":
                # Multi-line comment: --- ... ---
                self._advance(); self._advance(); self._advance()
                while not self._at_end():
                    if (self._peek() == "-" and
                            self._peek(1) == "-" and
                            self._peek(2) == "-"):
                        self._advance(); self._advance(); self._advance()
                        break
                    self._advance()

            elif ch == "-" and self._peek(1) == "-":
                # Single-line comment: -- to EOL
                while not self._at_end() and self._peek() != "\n":
                    self._advance()

            else:
                break

    # ── Token dispatch ────────────────────────────────────────

    def _next_token(self) -> Optional[Token]:
        line, col = self._line, self._col
        ch = self._advance()

        # ── String literals ───────────────────────────────────
        if ch in ('"', "'"):
            return self._lex_string(ch, line, col)

        # ── Numeric literals ──────────────────────────────────
        if ch.isdigit():
            return self._lex_number(ch, line, col)

        # ── Identifiers and keywords ──────────────────────────
        if ch.isalpha() or ch == "_":
            return self._lex_ident(ch, line, col)

        # ── Multi-character operators ─────────────────────────
        if ch == "|":
            if self._match(">"):
                return self._make(TT.PIPE_FWD, "|>", line, col)
            return self._make(TT.BANG, "|", line, col)   # fallback

        if ch == "-":
            if self._match(">"):
                return self._make(TT.ARROW, "->", line, col)
            return self._make(TT.MINUS, "-", line, col)

        if ch == "=":
            if self._match(">"):
                return self._make(TT.FAT_ARROW, "=>", line, col)
            if self._match("="):
                return self._make(TT.EQ, "==", line, col)
            return self._make(TT.ASSIGN, "=", line, col)

        if ch == ":":
            if self._match(":"):
                return self._make(TT.SCOPE, "::", line, col)
            if self._match("="):
                return self._make(TT.WALRUS, ":=", line, col)
            return self._make(TT.COLON, ":", line, col)

        if ch == "!":
            if self._match("="):
                return self._make(TT.NEQ, "!=", line, col)
            return self._make(TT.BANG, "!", line, col)

        if ch == "<":
            if self._match("="):
                return self._make(TT.LTE, "<=", line, col)
            return self._make(TT.LT, "<", line, col)

        if ch == ">":
            if self._match("="):
                return self._make(TT.GTE, ">=", line, col)
            return self._make(TT.GT, ">", line, col)

        # ── Single-character tokens ───────────────────────────
        SINGLE: dict[str, TT] = {
            "(": TT.LPAREN,  ")": TT.RPAREN,
            "{": TT.LBRACE,  "}": TT.RBRACE,
            "[": TT.LBRACK,  "]": TT.RBRACK,
            ",": TT.COMMA,   ".": TT.DOT,
            ";": TT.SEMICOLON,
            "+": TT.PLUS,    "*": TT.STAR,
            "/": TT.SLASH,   "%": TT.PERCENT,
            "?": TT.QMARK,
        }
        if ch in SINGLE:
            return self._make(SINGLE[ch], ch, line, col)

        # ── Unknown character ─────────────────────────────────
        err = UnexpectedCharError(ch, self._span(line, col))
        self.errors.add(err)
        return None     # skip and continue

    # ── String lexing ──────────────────────────────────────────

    def _lex_string(self, quote: str, line: int, col: int) -> Token:
        buf: List[str] = []

        while not self._at_end():
            ch = self._peek()

            if ch == "\n":
                err = UnterminatedStringError(self._span(line, col))
                self.errors.add(err)
                break

            if ch == quote:
                self._advance()    # consume closing quote
                return self._make(TT.STRING, "".join(buf), line, col)

            if ch == "\\":
                self._advance()    # consume backslash
                esc = self._advance() if not self._at_end() else "\x00"
                SIMPLE = {
                    '"': '"',  "'": "'",  "\\": "\\",
                    "n": "\n", "t": "\t", "r": "\r", "0": "\x00",
                }
                if esc in SIMPLE:
                    buf.append(SIMPLE[esc])
                elif esc == "u":
                    # Unicode: \u{HHHH}
                    if self._match("{"):
                        hex_chars: List[str] = []
                        while not self._at_end() and self._peek() != "}":
                            hex_chars.append(self._advance())
                        if self._match("}"):
                            try:
                                buf.append(chr(int("".join(hex_chars), 16)))
                            except ValueError:
                                err = InvalidEscapeError(
                                    "u{...}", self._span(line, col))
                                self.errors.add(err)
                        else:
                            err = InvalidEscapeError(
                                "u{", self._span(line, col))
                            self.errors.add(err)
                    else:
                        err = InvalidEscapeError("u", self._span(line, col))
                        self.errors.add(err)
                else:
                    err = InvalidEscapeError(esc, self._span(line, col))
                    self.errors.add(err)
                    buf.append(esc)   # recover: emit the char
                continue

            buf.append(self._advance())

        # Reached end without closing quote
        if not self.errors.has_errors():
            err = UnterminatedStringError(self._span(line, col))
            self.errors.add(err)
        return self._make(TT.STRING, "".join(buf), line, col)

    # ── Number lexing ─────────────────────────────────────────

    def _lex_number(self, first: str, line: int, col: int) -> Token:
        buf = [first]

        # Hex: 0x...
        if first == "0" and self._peek() in ("x", "X"):
            buf.append(self._advance())
            while self._peek() in "0123456789abcdefABCDEF_":
                c = self._advance()
                if c != "_":
                    buf.append(c)
            return self._make(TT.INT, int("".join(buf), 16), line, col)

        # Binary: 0b...
        if first == "0" and self._peek() in ("b", "B"):
            buf.append(self._advance())
            while self._peek() in "01_":
                c = self._advance()
                if c != "_":
                    buf.append(c)
            return self._make(TT.INT, int("".join(buf), 2), line, col)

        # Decimal integer or float
        while self._peek().isdigit() or self._peek() == "_":
            c = self._advance()
            if c != "_":
                buf.append(c)

        is_float = False

        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            buf.append(self._advance())  # '.'
            while self._peek().isdigit() or self._peek() == "_":
                c = self._advance()
                if c != "_":
                    buf.append(c)

        if self._peek() in ("e", "E"):
            is_float = True
            buf.append(self._advance())
            if self._peek() in ("+", "-"):
                buf.append(self._advance())
            while self._peek().isdigit():
                buf.append(self._advance())

        raw = "".join(buf)
        if is_float:
            return self._make(TT.FLOAT, float(raw), line, col)
        return self._make(TT.INT, int(raw), line, col)

    # ── Identifier / keyword lexing ───────────────────────────

    def _lex_ident(self, first: str, line: int, col: int) -> Token:
        buf = [first]
        while self._peek().isalnum() or self._peek() == "_":
            buf.append(self._advance())
        word = "".join(buf)

        if word in KEYWORDS:
            tt = KEYWORDS[word]
            value: object = word
            if tt == TT.BOOL:
                value = (word == "true")
            elif tt == TT.NIL:
                value = None
            return self._make(tt, value, line, col)

        return self._make(TT.IDENT, word, line, col)
