#!/usr/bin/env python3
"""
syn — VAREK command-line tool (v0.1)

Usage:
  syn parse  <file>         Parse a .syn file and print the AST
  varek check  <file>         Parse and report any errors
  syn tokens <file>         Print the token stream
  syn demo                  Run the built-in demo
  syn --version             Print version

Author : Kenneth Wayne Douglas, MD
License: MIT
"""

import sys
import os
import argparse

# Allow running from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import varek
from varek.lexer   import Lexer
from varek.parser  import Parser
from varek.printer import ASTPrinter


# ── ANSI colour helpers ───────────────────────────────────────────

def _c(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)
def yellow(t): return _c("33", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)


# ── Commands ──────────────────────────────────────────────────────

def cmd_tokens(path: str) -> int:
    source = open(path).read()
    lexer  = Lexer(source, filename=path)
    tokens = lexer.tokenize()

    print(bold(f"\n  Tokens  —  {path}\n"))
    print(f"  {'#':>4}  {'TYPE':<18} {'VALUE':<28} {'LINE:COL'}")
    print(f"  {'─'*4}  {'─'*18} {'─'*28} {'─'*10}")

    for i, tok in enumerate(tokens):
        val = repr(tok.value) if tok.value is not None else dim("—")
        loc = f"{tok.line}:{tok.col}"
        print(f"  {i:>4}  {cyan(tok.type.name):<27} {val:<28} {dim(loc)}")

    if lexer.errors.has_errors():
        print()
        print(red(lexer.errors.report(source.splitlines())))
        return 1
    return 0


def cmd_parse(path: str) -> int:
    source = open(path).read()
    tree, errors = varek.parse(source, filename=path)

    if errors.has_errors():
        print(red("\n  Parse errors:\n"))
        print(errors.report(source.splitlines()))
        return 1

    print(bold(f"\n  AST  —  {path}\n"))
    rendered = ASTPrinter.print(tree)
    for line in rendered.splitlines():
        # Colour node names
        import re
        line = re.sub(
            r'\b(Program|SchemaDecl|PipelineDecl|FnDecl|LetStmt|'
            r'ReturnStmt|ExprStmt|Block|ImportStmt|BinaryExpr|UnaryExpr|'
            r'PipeExpr|CallExpr|MemberExpr|IndexExpr|PropagateExpr|'
            r'IfExpr|MatchExpr|ForExpr|AwaitExpr|LambdaExpr|'
            r'ArrayLiteral|MapLiteral|TupleLiteral|WildcardPattern|'
            r'Literal|Ident|NamedType|OptionalType|ArrayType|MapType|'
            r'TupleType|TensorType|ResultType)\b',
            lambda m: cyan(m.group(0)), line
        )
        print("  " + line)
    print()
    return 0


def cmd_check(path: str) -> int:
    source = open(path).read()
    _, errors = varek.parse(source, filename=path)

    if errors.has_errors():
        print(red(f"\n  {len(errors)} error(s) in {path}:\n"))
        print(errors.report(source.splitlines()))
        return 1

    stmts = varek.parse(source, path)[0].statements
    print(green(f"\n  ✓  {path}  —  {len(stmts)} top-level declaration(s), no errors\n"))
    return 0


def cmd_demo() -> int:
    DEMO_SOURCE = '''
import python::numpy as np

schema ImageInput {
  path:   str,
  label:  str?,
  width:  int,
  height: int
}

pipeline classify_images {
  source: ImageInput[]
  steps:  [preprocess -> embed -> infer -> postprocess]
  output: ClassificationResult[]
  config { batch_size: 32, parallelism: 8 }
}

fn preprocess(img: ImageInput) -> Tensor<float, [3, 224, 224]> {
  load_image(img.path)
    |> resize(224, 224)
    |> normalize(mean=[0.485, 0.456, 0.406])
}

async fn infer(t: Tensor<float, [3, 224, 224]>) -> ClassificationResult {
  let model = load_model("resnet50.synmodel")?
  model.forward(t)
}

fn load_model(path: str) -> Result<Model> {
  if not file_exists(path) {
    return Err("not found: " + path)
  }
  Ok(Model.from_file(path))
}
'''

    WIDTH = 62
    print("\n" + "═" * WIDTH)
    print(bold(f"  VAREK v{varek.__version__}  —  Reference Parser Demo"))
    print(f"  {varek.__author__}")
    print("═" * WIDTH)

    # ── Step 1: Tokenise ──────────────────────────────────────
    print(f"\n{bold('  [1/3] Lexer')}\n")
    lexer  = Lexer(DEMO_SOURCE, "<demo>")
    tokens = lexer.tokenize()
    non_eof = [t for t in tokens if t.type.name != "EOF"]
    print(f"  {green(str(len(non_eof)))} tokens produced")
    from collections import Counter
    counts = Counter(t.type.name for t in non_eof)
    for tt, n in sorted(counts.items(), key=lambda x: -x[1])[:8]:
        print(f"    {cyan(tt):<22} × {n}")

    if lexer.errors.has_errors():
        print(red("\n  Lex errors:"))
        print(lexer.errors.report(DEMO_SOURCE.splitlines()))
        return 1

    # ── Step 2: Parse ─────────────────────────────────────────
    print(f"\n{bold('  [2/3] Parser')}\n")
    tree, errors = varek.parse(DEMO_SOURCE, "<demo>")

    if errors.has_errors():
        print(red(errors.report(DEMO_SOURCE.splitlines())))
        return 1

    print(f"  {green('✓')}  Parse successful — "
          f"{len(tree.statements)} top-level statements\n")

    for i, stmt in enumerate(tree.statements):
        kind = type(stmt).__name__
        name = getattr(stmt, "name", "")
        print(f"  {dim(str(i+1) + '.')}  {cyan(kind)}"
              + (f"  `{bold(name)}`" if name else ""))

    # ── Step 3: AST ───────────────────────────────────────────
    print(f"\n{bold('  [3/3] AST (excerpt)')}\n")
    ast_text = ASTPrinter.print(tree)
    lines = ast_text.splitlines()[:30]
    for line in lines:
        print("  " + dim(line))
    if len(ast_text.splitlines()) > 30:
        remaining = len(ast_text.splitlines()) - 30
        print(f"  {dim(f'... {remaining} more lines')}")

    print("\n" + "═" * WIDTH)
    print(f"  {green('VAREK v0.1 — MIT License')}")
    print(f"  {dim('github.com/varek-lang/varek')}")
    print("═" * WIDTH + "\n")
    return 0


# ── CLI ───────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="varek",
        description="VAREK language tools v0.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="store_true",
                   help="Print version and exit")

    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("parse",  help="Parse a .syn file and print AST")
    sp.add_argument("file")

    sc = sub.add_parser("check",  help="Check a .syn file for errors")
    sc.add_argument("file")

    st = sub.add_parser("tokens", help="Print token stream of a .syn file")
    st.add_argument("file")

    sub.add_parser("demo", help="Run the built-in demo")

    args = p.parse_args()

    if args.version:
        print(f"syn {varek.__version__}")
        return 0

    if args.command == "parse":
        return cmd_parse(args.file)
    if args.command == "check":
        return cmd_check(args.file)
    if args.command == "tokens":
        return cmd_tokens(args.file)
    if args.command == "demo":
        return cmd_demo()

    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
