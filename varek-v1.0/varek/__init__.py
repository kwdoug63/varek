"""
VAREK — AI Pipeline Programming Language
v0.2 — Type System + Inference Engine

Author : Kenneth Wayne Douglas, MD
License: MIT
"""

from varek.lexer    import Lexer, Token, TT
from varek.parser   import Parser
from varek.errors   import ErrorBag, VarekError
from varek.printer  import ASTPrinter
from varek.checker  import TypeChecker, CheckResult, SchemaValidator
from varek.types    import (
    Type, TypeVar, Scheme, Substitution,
    PrimType, OptionalType, ArrayType, MapType, TupleType,
    TensorType, ResultType, FunctionType, SchemaType, FieldDef,
    T_INT, T_FLOAT, T_STR, T_BOOL, T_NIL,
    Dim, fresh_var,
)
from varek.env      import TypeEnv, SchemaRegistry
from varek.infer    import Inferrer
from varek.builtins import build_global_env

__version__ = "1.0.0"
__author__  = "Kenneth Wayne Douglas, MD"
__license__ = "MIT"


def parse(source: str, filename: str = "<stdin>"):
    lexer  = Lexer(source, filename)
    tokens = lexer.tokenize()
    errors = ErrorBag()
    for e in lexer.errors:
        errors.add(e)
    parser = Parser(tokens, filename)
    tree   = parser.parse()
    for e in parser.errors:
        errors.add(e)
    return tree, errors


def check(source: str, filename: str = "<stdin>") -> CheckResult:
    return TypeChecker.check(source, filename)


def check_expr(source: str):
    return TypeChecker.check_expr(source)


__all__ = [
    "Lexer","Token","TT","Parser","ASTPrinter","parse",
    "TypeChecker","CheckResult","SchemaValidator","check","check_expr",
    "Type","TypeVar","Scheme","Substitution",
    "PrimType","OptionalType","ArrayType","MapType","TupleType",
    "TensorType","ResultType","FunctionType","SchemaType","FieldDef",
    "T_INT","T_FLOAT","T_STR","T_BOOL","T_NIL","Dim","fresh_var",
    "TypeEnv","SchemaRegistry","Inferrer","build_global_env",
    "ErrorBag","VarekError",
]
