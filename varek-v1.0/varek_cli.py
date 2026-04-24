#!/usr/bin/env python3
"""
varek — The VAREK Package Manager
===================================
Version 1.0.0 | MIT License | Kenneth Wayne Douglas, MD

Commands:
  varek new <name>          Create a new VAREK project
  varek build               Build the current project
  varek run [script]        Run the project (default: main script)
  varek check               Type-check without running
  varek test                Run tests
  varek bench               Run benchmarks
  varek repl                Start the interactive REPL
  varek fmt [path]          Format .syn source files
  varek doc                 Generate documentation
  varek install [pkg]       Install dependencies (or a specific package)
  varek add <pkg>           Add a dependency to varek.toml
  varek remove <pkg>        Remove a dependency
  varek publish             Package and publish to registry
  varek search <query>      Search the package registry
  varek info <pkg>          Show package information
  varek update              Update all dependencies
  varek clean               Remove build artifacts
  varek init                Initialize varek.toml in current directory
  varek registry update     Refresh the registry index
  varek version             Show version information
"""

import sys
import os
import time
import shutil
import tempfile
import argparse
import textwrap
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ── ANSI ──────────────────────────────────────────────────────────

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def bold(t):   return _c("1",  t)
def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def dim(t):    return _c("2",  t)
def magenta(t):return _c("35", t)


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

VERSION = "1.0.0"

LOGO = f"""
{bold(cyan('  ███████╗██╗   ██╗███╗   ██╗'))}
{bold(cyan('  ██╔════╝╚██╗ ██╔╝████╗  ██║'))}
{bold(cyan('  ███████╗ ╚████╔╝ ██╔██╗ ██║'))}
{bold(cyan('  ╚════██║  ╚██╔╝  ██║╚██╗██║'))}
{bold(cyan('  ███████║   ██║   ██║ ╚████║'))}
{bold(cyan('  ╚══════╝   ╚═╝   ╚═╝  ╚═══╝'))}
  {bold('Package Manager')} {dim(f'v{VERSION}')}
"""

def _ok(msg):    print(f"  {green('✓')} {msg}")
def _err(msg):   print(f"  {red('✗')} {msg}"); sys.exit(1)
def _warn(msg):  print(f"  {yellow('!')} {msg}")
def _info(msg):  print(f"  {dim('·')} {msg}")
def _step(msg):  print(f"  {cyan('→')} {msg}")

def _require_manifest(path="."):
    from varek.packager import ManifestParser
    mf = os.path.join(path, "varek.toml")
    if not os.path.exists(mf):
        _err("No varek.toml found. Run `varek init` or `varek new <name>` first.")
    return ManifestParser.parse_file(mf)


# ══════════════════════════════════════════════════════════════════
# TEMPLATES
# ══════════════════════════════════════════════════════════════════

MANIFEST_TEMPLATE = '''\
[package]
name        = "{name}"
version     = "0.1.0"
authors     = ["{author}"]
license     = "MIT"
description = "A VAREK project"
varek     = ">=1.0.0"

[dependencies]

[dev-dependencies]

[build]
target    = "interpret"
opt_level = 2
emit      = ["ir"]

[scripts]
main  = "src/main.syn"
test  = "tests/test_main.syn"
'''

MAIN_TEMPLATE = '''\
---
{name} — main entry point.

Created with varek new.
---

import var::io
import var::tensor

fn main() -> Result<nil> {{
  io.println("Hello from {name}!")

  -- Create a sample tensor
  let t = tensor.randn([3, 4])
  io.println("Tensor shape: " + str(tensor.shape(t)))

  Ok(nil)
}}
'''

TEST_TEMPLATE = '''\
---
Tests for {name}.
Run with: varek test
---

import var::io

fn test_hello() -> bool {{
  io.println("Running test_hello...")
  true
}}

fn run_all_tests() -> nil {{
  let passed = 0
  let failed = 0

  if test_hello() {{
    io.println("  PASS  test_hello")
  }} else {{
    io.println("  FAIL  test_hello")
  }}

  io.println("Tests complete.")
}}

run_all_tests()
'''

README_TEMPLATE = '''\
# {name}

A VAREK project.

## Quick Start

```bash
varek run          # Run the project
varek test         # Run tests
varek build        # Compile to native
```

## Structure

```
{name}/
├── varek.toml     # Project manifest
├── src/
│   └── main.syn # Entry point
├── tests/
│   └── test_main.syn
└── README.md
```

## License

MIT
'''


# ══════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════

def cmd_new(args):
    """Create a new VAREK project."""
    name   = args.name
    author = os.environ.get("SYN_AUTHOR", os.environ.get("USER", "Author"))
    target = Path(name)

    if target.exists():
        _err(f"Directory '{name}' already exists.")

    print(f"\n  {bold('Creating')} VAREK project {cyan(name)}\n")

    # Create structure
    for d in ["src", "tests", "docs", "benchmarks", ".syn"]:
        (target / d).mkdir(parents=True, exist_ok=True)

    # Write files
    (target / "varek.toml").write_text(
        MANIFEST_TEMPLATE.format(name=name, author=author))
    (target / "src" / "main.syn").write_text(
        MAIN_TEMPLATE.format(name=name))
    (target / "tests" / "test_main.syn").write_text(
        TEST_TEMPLATE.format(name=name))
    (target / "README.md").write_text(
        README_TEMPLATE.format(name=name))
    (target / ".gitignore").write_text(
        ".syn/\ntarget/\n*.varekpkg\n*.ll\n*.s\n*.o\n")
    (target / ".syn" / "deps").mkdir(exist_ok=True)

    _ok(f"Created project: {bold(name)}/")
    print(f"""
  {dim('Get started:')}

    {cyan(f'cd {name}')}
    {cyan('varek run')}

  {dim('Documentation:')} https://varek-lang.org/docs
""")


def cmd_init(args):
    """Initialize varek.toml in the current directory."""
    if os.path.exists("varek.toml"):
        _err("varek.toml already exists.")

    name   = os.path.basename(os.getcwd())
    author = os.environ.get("SYN_AUTHOR", os.environ.get("USER", "Author"))

    with open("varek.toml", "w") as f:
        f.write(MANIFEST_TEMPLATE.format(name=name, author=author))

    _ok(f"Created varek.toml for project {bold(name)}")


def cmd_build(args):
    """Build the project."""
    manifest = _require_manifest()
    _step(f"Building {bold(manifest.package.name)} v{manifest.package.version}")

    from varek.compiler import Compiler, CompileMode

    script = manifest.scripts.get("main", "src/main.syn")
    if not os.path.exists(script):
        _err(f"Main script not found: {script}")

    with open(script) as f:
        source = f.read()

    mode = (CompileMode.COMPILE if manifest.build.target == "native"
            else CompileMode.EMIT_IR)
    opt  = manifest.build.opt_level

    os.makedirs("target", exist_ok=True)
    output = f"target/{manifest.package.name}"
    if mode == CompileMode.EMIT_IR:
        output += ".ll"

    t0     = time.perf_counter()
    result = Compiler.compile(source, script, mode=mode,
                               output=output, opt_level=opt)
    elapsed= (time.perf_counter() - t0) * 1000

    if result.ok:
        _ok(f"Build successful in {elapsed:.0f}ms → {output}")
        if result.timings:
            for stage, t in result.timings.items():
                print(f"    {dim(stage):<20} {t*1000:.1f}ms")
    else:
        print(red("  Build failed:\n"))
        print(result.report())
        sys.exit(1)


def cmd_run(args):
    """Run the project."""
    manifest = _require_manifest()
    script_key = getattr(args, "script", None) or "main"
    script = manifest.scripts.get(script_key, "src/main.syn")

    if not os.path.exists(script):
        _err(f"Script not found: {script}")

    _step(f"Running {bold(manifest.package.name)}")

    from varek.runtime import Interpreter
    interp = Interpreter()
    try:
        with open(script) as f:
            source = f.read()
        interp.run(source, script)
    except Exception as e:
        print(red(f"\n  Runtime error: {e}"))
        sys.exit(1)


def cmd_check(args):
    """Type-check the project."""
    manifest = _require_manifest()
    script   = manifest.scripts.get("main", "src/main.syn")

    if not os.path.exists(script):
        _err(f"Script not found: {script}")

    _step(f"Checking {bold(manifest.package.name)}")

    import varek
    with open(script) as f:
        source = f.read()

    result = varek.check(source, script)
    if result.ok:
        bindings = list(result.bindings())
        _ok(f"Type check passed — {len(bindings)} top-level bindings")
    else:
        print(red("  Type errors:\n"))
        print(result.report())
        sys.exit(1)


def cmd_test(args):
    """Run tests."""
    manifest  = _require_manifest()
    test_script = manifest.scripts.get("test", "tests/test_main.syn")

    if not os.path.exists(test_script):
        _warn(f"Test script not found: {test_script}")
        return

    _step(f"Testing {bold(manifest.package.name)}")

    from varek.runtime import Interpreter
    interp = Interpreter()
    try:
        with open(test_script) as f:
            source = f.read()
        t0 = time.perf_counter()
        interp.run(source, test_script)
        elapsed = (time.perf_counter() - t0) * 1000
        _ok(f"Tests completed in {elapsed:.0f}ms")
    except Exception as e:
        print(red(f"\n  Test failed: {e}"))
        sys.exit(1)


def cmd_bench(args):
    """Run benchmarks."""
    manifest = _require_manifest()
    bench_script = manifest.scripts.get("bench", "benchmarks/bench.syn")

    if not os.path.exists(bench_script):
        _warn(f"Benchmark script not found: {bench_script}")
        return

    _step(f"Benchmarking {bold(manifest.package.name)}")

    from varek.runtime import Interpreter
    interp = Interpreter()
    with open(bench_script) as f:
        source = f.read()
    interp.run(source, bench_script)


def cmd_repl(args):
    """Start the interactive REPL."""
    from varek.repl import start_repl
    start_repl()


def cmd_fmt(args):
    """Format .syn source files."""
    from varek.formatter import format_file, check_format

    paths = getattr(args, "path", None)
    check = getattr(args, "check", False)

    if paths:
        targets = [paths] if isinstance(paths, str) else paths
    else:
        targets = list(Path(".").rglob("*.syn"))

    changed = []
    errors  = []

    for t in targets:
        path = str(t)
        try:
            if check:
                if not check_format(path):
                    changed.append(path)
                    print(f"  {yellow('!')} {path} — would reformat")
                else:
                    print(f"  {dim('✓')} {path}")
            else:
                original = open(path).read()
                formatted = format_file(path, in_place=True)
                if formatted != original:
                    changed.append(path)
                    print(f"  {green('✓')} {path} — reformatted")
                else:
                    print(f"  {dim('·')} {path} — unchanged")
        except Exception as e:
            errors.append(path)
            print(f"  {red('✗')} {path} — {e}")

    print()
    if check:
        if changed:
            print(red(f"  {len(changed)} file(s) would be reformatted"))
            sys.exit(1)
        else:
            _ok("All files are correctly formatted")
    else:
        _ok(f"Formatted {len(changed)} file(s)")


def cmd_doc(args):
    """Generate documentation."""
    from varek.doc_gen import generate_docs

    manifest   = _require_manifest()
    source_dir = getattr(args, "source", "src")
    output_dir = getattr(args, "output", "docs")
    fmt        = getattr(args, "format", "markdown")
    pkg_name   = manifest.package.name

    _step(f"Generating docs for {bold(pkg_name)}")

    if not os.path.exists(source_dir):
        _warn(f"Source directory not found: {source_dir}")
        return

    generated = generate_docs(source_dir, output_dir, fmt, pkg_name)
    _ok(f"Generated {len(generated)} files → {output_dir}/")
    for p in generated[:5]:
        print(f"    {dim(p)}")
    if len(generated) > 5:
        print(f"    {dim(f'... and {len(generated)-5} more')}")


def cmd_install(args):
    """Install all dependencies (or a specific package)."""
    from varek.packager import ManifestParser
    from varek.registry import Registry

    manifest = _require_manifest()
    reg      = Registry()

    pkg_name = getattr(args, "package", None)
    if pkg_name:
        _step(f"Installing {bold(pkg_name)}")
        version_req = getattr(args, "version", "*") or "*"
        locked = reg.install(pkg_name, version_req, target_dir=".syn/deps")
        if locked:
            _ok(f"Installed {pkg_name} {locked.version}")
        else:
            _err(f"Package '{pkg_name}' not found in registry")
    else:
        _step(f"Installing dependencies for {bold(manifest.package.name)}")
        lockfile = reg.install_from_manifest(manifest, ".")
        _ok(f"Installed {len(lockfile.packages)} package(s)")


def cmd_add(args):
    """Add a dependency to varek.toml."""
    from varek.packager import ManifestParser

    pkg  = args.package
    req  = getattr(args, "version", "*") or "^1.0.0"
    dev  = getattr(args, "dev", False)

    manifest = _require_manifest()

    if dev:
        manifest.dev_deps[pkg] = req
    else:
        manifest.dependencies[pkg] = req

    from varek.packager import ManifestParser
    ManifestParser.write(manifest, "varek.toml")

    section = "dev-dependencies" if dev else "dependencies"
    _ok(f"Added {bold(pkg)} {dim(req)} to [{section}]")
    _info("Run `varek install` to install.")


def cmd_remove(args):
    """Remove a dependency."""
    from varek.packager import ManifestParser

    pkg      = args.package
    manifest = _require_manifest()
    removed  = False

    if pkg in manifest.dependencies:
        del manifest.dependencies[pkg]
        removed = True
    if pkg in manifest.dev_deps:
        del manifest.dev_deps[pkg]
        removed = True

    if removed:
        ManifestParser.write(manifest, "varek.toml")
        _ok(f"Removed {bold(pkg)} from varek.toml")
    else:
        _warn(f"'{pkg}' not found in dependencies")


def cmd_publish(args):
    """Package and publish to registry."""
    from varek.packager import create_package
    from varek.registry import Registry

    manifest = _require_manifest()
    _step(f"Packaging {bold(manifest.package.name)} v{manifest.package.version}")

    try:
        pkg_path = create_package(".")
        _ok(f"Created package: {pkg_path}")
    except Exception as e:
        _err(f"Packaging failed: {e}")

    target = getattr(args, "registry", "local")
    if target == "local" or not target:
        reg = Registry("local")
        if reg.publish_local(pkg_path):
            _ok(f"Published to local registry")
        else:
            _err("Publish failed")
    else:
        _warn(f"Remote publishing to {target} not yet supported in v1.0")
        _info("Use `varek publish --registry local` for local publishing")


def cmd_search(args):
    """Search the package registry."""
    from varek.registry import Registry

    query = args.query
    reg   = Registry()
    results = reg.search(query)

    if not results:
        _warn(f"No packages found for '{query}'")
        return

    print(f"\n  {bold('Search results')} for '{cyan(query)}'\n")
    print(f"  {'NAME':<24} {'VERSION':<10} DESCRIPTION")
    print(f"  {'-'*24} {'-'*10} {'-'*32}")
    for r in results:
        name = r["name"]
        ver  = r["version"]
        desc = r["description"][:40]
        print(f"  {cyan(name):<33} {dim(ver):<10} {desc}")
    print()


def cmd_info(args):
    """Show package information."""
    from varek.registry import Registry

    pkg = args.package
    reg = Registry()
    info = reg.info(pkg)

    if not info:
        _err(f"Package '{pkg}' not found")

    latest = reg._index.latest(pkg)
    versions = reg._index.list_versions(pkg)

    print(f"\n  {bold(pkg)}\n")
    print(f"  Version:     {cyan(str(latest))}")
    print(f"  Description: {info.get('description','')}")
    kw = info.get("keywords", [])
    if kw:
        print(f"  Keywords:    {', '.join(kw)}")
    deps = info.get("deps", {})
    if deps:
        print(f"  Deps:        {', '.join(f'{k} {v}' for k,v in deps.items())}")
    print(f"  All versions: {', '.join(str(v) for v in versions[-5:])}")
    print()


def cmd_update(args):
    """Update all dependencies."""
    manifest = _require_manifest()
    _step(f"Updating dependencies for {bold(manifest.package.name)}")

    from varek.registry import Registry
    from varek.packager import Lockfile

    reg = Registry()
    lockfile = reg.install_from_manifest(manifest, ".")
    _ok(f"Updated {len(lockfile.packages)} package(s)")


def cmd_clean(args):
    """Remove build artifacts."""
    dirs  = ["target", ".syn/cache"]
    files = list(Path(".").glob("*.ll")) + list(Path(".").glob("*.s")) + \
            list(Path(".").glob("*.o")) + list(Path(".").glob("*.varekpkg"))

    removed = 0
    for d in dirs:
        if os.path.exists(d):
            shutil.rmtree(d)
            _info(f"Removed {d}/")
            removed += 1
    for f in files:
        f.unlink()
        _info(f"Removed {f}")
        removed += 1

    _ok(f"Cleaned {removed} artifact(s)")


def cmd_registry(args):
    """Registry subcommands."""
    from varek.registry import Registry
    subcmd = getattr(args, "subcmd", None)

    if subcmd == "update":
        reg = Registry()
        reg.update()
    elif subcmd == "list":
        reg = Registry()
        pkgs = reg._index.list_packages()
        print(f"\n  {bold('Registry')} — {len(pkgs)} packages\n")
        for p in pkgs:
            latest = reg._index.latest(p)
            print(f"  {cyan(p):<30} {dim(str(latest)) if latest else ''}")
        print()
    else:
        print("Usage: varek registry <update|list>")


def cmd_version(args):
    """Show version information."""
    import varek
    print(f"\n  {bold(cyan('VAREK'))} Package Manager {bold(VERSION)}")
    print(f"  Language version: {varek.__version__}")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  Platform: {sys.platform}\n")


# ══════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="varek",
        description="The VAREK Package Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          varek new my-pipeline       Create a new project
          varek run                   Run the project
          varek repl                  Start interactive REPL
          varek fmt                   Format all .syn files
          varek doc --format html     Generate HTML docs
          varek install               Install dependencies
          varek publish               Publish to registry
        """)
    )
    p.add_argument("--version", "-V", action="store_true")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    # new
    sp = sub.add_parser("new", help="Create a new project")
    sp.add_argument("name", help="Project name")

    # init
    sub.add_parser("init", help="Initialize varek.toml in current directory")

    # build
    sp = sub.add_parser("build", help="Build the project")
    sp.add_argument("--release", action="store_true", help="Optimized build")

    # run
    sp = sub.add_parser("run", help="Run the project")
    sp.add_argument("script", nargs="?", help="Script name from [scripts]")

    # check
    sub.add_parser("check", help="Type-check without running")

    # test
    sub.add_parser("test", help="Run tests")

    # bench
    sub.add_parser("bench", help="Run benchmarks")

    # repl
    sub.add_parser("repl", help="Start interactive REPL")

    # fmt
    sp = sub.add_parser("fmt", help="Format .syn files")
    sp.add_argument("path", nargs="?", help="File or directory to format")
    sp.add_argument("--check", action="store_true", help="Check only, don't write")

    # doc
    sp = sub.add_parser("doc", help="Generate documentation")
    sp.add_argument("--source", default="src", help="Source directory")
    sp.add_argument("--output", default="docs", help="Output directory")
    sp.add_argument("--format", default="markdown",
                    choices=["markdown","html","both"], help="Output format")

    # install
    sp = sub.add_parser("install", help="Install dependencies")
    sp.add_argument("package", nargs="?", help="Specific package to install")
    sp.add_argument("--version", help="Version requirement")

    # add
    sp = sub.add_parser("add", help="Add a dependency")
    sp.add_argument("package", help="Package name")
    sp.add_argument("--version", default="*", help="Version requirement")
    sp.add_argument("--dev", action="store_true", help="Add to dev-dependencies")

    # remove
    sp = sub.add_parser("remove", help="Remove a dependency")
    sp.add_argument("package", help="Package name")

    # publish
    sp = sub.add_parser("publish", help="Publish to registry")
    sp.add_argument("--registry", default="local", help="Registry URL or 'local'")

    # search
    sp = sub.add_parser("search", help="Search the registry")
    sp.add_argument("query", help="Search query")

    # info
    sp = sub.add_parser("info", help="Package information")
    sp.add_argument("package", help="Package name")

    # update
    sub.add_parser("update", help="Update dependencies")

    # clean
    sub.add_parser("clean", help="Remove build artifacts")

    # registry
    sp = sub.add_parser("registry", help="Registry management")
    sp.add_argument("subcmd", choices=["update","list"])

    # version
    sub.add_parser("version", help="Show version information")

    return p


COMMANDS = {
    "new":      cmd_new,
    "init":     cmd_init,
    "build":    cmd_build,
    "run":      cmd_run,
    "check":    cmd_check,
    "test":     cmd_test,
    "bench":    cmd_bench,
    "repl":     cmd_repl,
    "fmt":      cmd_fmt,
    "doc":      cmd_doc,
    "install":  cmd_install,
    "add":      cmd_add,
    "remove":   cmd_remove,
    "publish":  cmd_publish,
    "search":   cmd_search,
    "info":     cmd_info,
    "update":   cmd_update,
    "clean":    cmd_clean,
    "registry": cmd_registry,
    "version":  cmd_version,
}


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.version:
        print(f"syn {VERSION}")
        return 0

    if not args.command:
        print(LOGO)
        parser.print_help()
        return 0

    fn = COMMANDS.get(args.command)
    if fn is None:
        _err(f"Unknown command: {args.command}")

    try:
        fn(args)
        return 0
    except SystemExit as e:
        return int(e.code or 0)
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as e:
        print(red(f"\n  Unexpected error: {e}"))
        import traceback
        if os.environ.get("SYN_BACKTRACE"):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
