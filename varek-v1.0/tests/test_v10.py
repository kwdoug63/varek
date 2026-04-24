"""
tests/test_v10.py
──────────────────
VAREK v1.0 Test Suite — Package Manager, REPL, Formatter, Doc Gen, RFC.
Run: python tests/test_v10.py
"""
import sys, os, tempfile, shutil, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import varek

P=0; F=0; FAILS=[]
def chk(name, fn):
    global P,F
    try:
        assert fn() is not False
        print(f"  PASS  {name}"); P+=1
    except Exception as e:
        print(f"  FAIL  {name}: {e}"); F+=1; FAILS.append((name,str(e)))

print(f"\n=== VAREK v1.0 — Package Manager & Governance Tests ===\n")

# ════════════════════════════════════════════════════════
print("-- Version --")
# ════════════════════════════════════════════════════════
chk("version 1.0.0",   lambda: varek.__version__ == "1.0.0")
chk("author",          lambda: "Kenneth" in varek.__author__)

# ════════════════════════════════════════════════════════
print("\n-- Semver --")
# ════════════════════════════════════════════════════════
from varek.packager import Version, VersionReq

chk("parse 1.2.3",     lambda: Version.parse("1.2.3") == Version(1,2,3))
chk("parse v1.2.3",    lambda: Version.parse("v1.2.3") == Version(1,2,3))
chk("parse 1.0",       lambda: Version.parse("1.0") == Version(1,0,0))
chk("str 1.2.3",       lambda: str(Version(1,2,3)) == "1.2.3")
chk("str 1.0.0-rc.1",  lambda: str(Version(1,0,0,"rc.1")) == "1.0.0-rc.1")
chk("is_stable",        lambda: Version(1,0,0).is_stable())
chk("not stable pre",   lambda: not Version(1,0,0,"alpha.1").is_stable())
chk("ordering 1<2",     lambda: Version(1,0,0) < Version(2,0,0))
chk("ordering minor",   lambda: Version(1,1,0) > Version(1,0,9))
chk("ordering patch",   lambda: Version(1,0,2) > Version(1,0,1))
chk("bump_patch",       lambda: Version(1,2,3).bump_patch() == Version(1,2,4))
chk("bump_minor",       lambda: Version(1,2,3).bump_minor() == Version(1,3,0))
chk("bump_major",       lambda: Version(1,2,3).bump_major() == Version(2,0,0))

chk("req * matches all",   lambda: VersionReq("*").matches(Version(9,9,9)))
chk("req ^1.2 compat",     lambda: VersionReq("^1.2.0").matches(Version(1,3,0)))
chk("req ^1.2 same maj",   lambda: not VersionReq("^1.2.0").matches(Version(2,0,0)))
chk("req >=1.0",            lambda: VersionReq(">=1.0.0").matches(Version(1,5,0)))
chk("req >=1.0 fails",      lambda: not VersionReq(">=1.0.0").matches(Version(0,9,0)))
chk("req >1.0 strict",      lambda: not VersionReq(">1.0.0").matches(Version(1,0,0)))
chk("req =exact",           lambda: VersionReq("=1.2.3").matches(Version(1,2,3)))
chk("req =exact fails",     lambda: not VersionReq("=1.2.3").matches(Version(1,2,4)))
chk("req ~1.2 patch",       lambda: VersionReq("~1.2.0").matches(Version(1,2,5)))
chk("req ~1.2 minor fail",  lambda: not VersionReq("~1.2.0").matches(Version(1,3,0)))

# ════════════════════════════════════════════════════════
print("\n-- Manifest Parser --")
# ════════════════════════════════════════════════════════
from varek.packager import ManifestParser, Manifest, PackageMeta

TOML = '''
[package]
name        = "test-pkg"
version     = "1.2.3"
authors     = ["Alice", "Bob"]
license     = "Apache-2.0"
description = "A test package"
keywords    = ["test", "varek"]
varek     = ">=1.0.0"

[dependencies]
"core-utils" = "^1.0.0"
"ml-ext"     = ">=0.5.0"

[dev-dependencies]
"test-helpers" = "*"

[build]
target    = "native"
opt_level = 3
emit      = ["ir", "obj"]

[scripts]
main  = "src/main.syn"
test  = "tests/run.syn"
bench = "benchmarks/bench.syn"
'''

m = ManifestParser.parse(TOML)
chk("manifest name",       lambda m=m: m.package.name == "test-pkg")
chk("manifest version",    lambda m=m: str(m.package.version) == "1.2.3")
chk("manifest authors",    lambda m=m: len(m.package.authors) == 2)
chk("manifest license",    lambda m=m: m.package.license == "Apache-2.0")
chk("manifest desc",       lambda m=m: "test" in m.package.description)
chk("manifest keywords",   lambda m=m: "varek" in m.package.keywords)
chk("manifest deps",       lambda m=m: "core-utils" in m.dependencies)
chk("manifest dep req",    lambda m=m: m.dependencies["core-utils"] == "^1.0.0")
chk("manifest dev deps",   lambda m=m: "test-helpers" in m.dev_deps)
chk("manifest build tgt",  lambda m=m: m.build.target == "native")
chk("manifest opt level",  lambda m=m: m.build.opt_level == 3)
chk("manifest emit",       lambda m=m: "obj" in m.build.emit)
chk("manifest scripts",    lambda m=m: m.scripts["main"] == "src/main.syn")

def _test_manifest_roundtrip():
    with tempfile.NamedTemporaryFile(suffix=".toml",delete=False,mode="w") as f:
        path = f.name
    try:
        ManifestParser.write(m, path)
        m2 = ManifestParser.parse_file(path)
        return (m2.package.name == m.package.name and
                str(m2.package.version) == str(m.package.version) and
                "core-utils" in m2.dependencies)
    finally:
        os.unlink(path)
chk("manifest roundtrip",  _test_manifest_roundtrip)

# ════════════════════════════════════════════════════════
print("\n-- Lockfile --")
# ════════════════════════════════════════════════════════
from varek.packager import Lockfile, LockedPackage

def _test_lockfile():
    lf = Lockfile(varek_version="1.0.0")
    lf.packages.append(LockedPackage("pkg","1.0.0","sha256:abc","registry","./pkg.varekpkg"))
    with tempfile.NamedTemporaryFile(suffix=".lock",delete=False,mode="w") as f:
        path = f.name
    try:
        lf.save(path)
        lf2 = Lockfile.load(path)
        return (len(lf2.packages) == 1 and
                lf2.packages[0].name == "pkg" and
                lf2.packages[0].version == "1.0.0")
    finally:
        os.unlink(path)
chk("lockfile save/load",  _test_lockfile)
chk("lockfile empty load", lambda: len(Lockfile.load("/nonexistent.lock").packages) == 0)

# ════════════════════════════════════════════════════════
print("\n-- Package Archive --")
# ════════════════════════════════════════════════════════
from varek.packager import create_package, extract_package, package_checksum

def _test_package_create_extract():
    with tempfile.TemporaryDirectory() as proj:
        # Write a minimal project
        (ManifestParser.parse(TOML),)  # just use the parsed manifest
        with open(os.path.join(proj,"varek.toml"),"w") as f:
            f.write('[package]\nname="mypkg"\nversion="0.1.0"\n')
        os.makedirs(os.path.join(proj,"src"))
        with open(os.path.join(proj,"src","main.syn"),"w") as f:
            f.write('let x = 1\n')

        with tempfile.NamedTemporaryFile(suffix=".varekpkg",delete=False) as f:
            pkg_path = f.name

        try:
            created = create_package(proj, pkg_path)
            assert os.path.exists(created) and os.path.getsize(created) > 0

            with tempfile.TemporaryDirectory() as extract_dir:
                extracted = extract_package(created, extract_dir)
                assert extracted.package.name == "mypkg"
                assert os.path.exists(os.path.join(extract_dir,"src","main.syn"))
            return True
        finally:
            if os.path.exists(pkg_path): os.unlink(pkg_path)
chk("create + extract package", _test_package_create_extract)

def _test_checksum():
    data = b"hello varek"
    cs = package_checksum(data)
    return cs.startswith("sha256:") and len(cs) == 71
chk("checksum format",     _test_checksum)

# ════════════════════════════════════════════════════════
print("\n-- Registry --")
# ════════════════════════════════════════════════════════
from varek.registry import Registry, RegistryIndex

def _make_index():
    return RegistryIndex({
        "packages": {
            "core-utils": {
                "1.0.0": {"url":"","checksum":"sha256:abc","description":"Core utilities","keywords":["core"],"deps":{}},
                "1.1.0": {"url":"","checksum":"sha256:def","description":"Core utilities","keywords":["core"],"deps":{}},
                "2.0.0": {"url":"","checksum":"sha256:ghi","description":"Core utilities","keywords":["core"],"deps":{}},
            },
            "ml-ext": {
                "0.5.0": {"url":"","checksum":"sha256:jkl","description":"ML extensions","keywords":["ml","tensor"],"deps":{}},
            }
        }
    })

idx = _make_index()
chk("list packages",       lambda: "core-utils" in idx.list_packages())
chk("list versions",       lambda: len(idx.list_versions("core-utils")) == 3)
chk("latest stable",       lambda: str(idx.latest("core-utils")) == "2.0.0")
chk("latest missing",      lambda: idx.latest("nonexistent") is None)

def _test_resolve():
    r = idx.resolve("core-utils", "^1.0.0")
    return r is not None and str(r[0]) == "1.1.0"
chk("resolve ^1.0.0",      _test_resolve)

def _test_resolve_any():
    r = idx.resolve("core-utils", "*")
    return r is not None and str(r[0]) == "2.0.0"
chk("resolve *",           _test_resolve_any)

chk("resolve missing",     lambda: idx.resolve("nope","*") is None)

def _test_search():
    results = idx.search("core")
    return any(r["name"] == "core-utils" for r in results)
chk("search finds pkg",    _test_search)

def _test_search_keywords():
    results = idx.search("ml")
    return any(r["name"] == "ml-ext" for r in results)
chk("search by name",      _test_search_keywords)

def _test_index_save_load():
    with tempfile.NamedTemporaryFile(suffix=".json",delete=False) as f:
        path = f.name
    try:
        idx.save(path)
        idx2 = RegistryIndex.from_file(path)
        return "core-utils" in idx2.list_packages()
    finally:
        os.unlink(path)
chk("index save/load",     _test_index_save_load)

def _test_register():
    idx2 = _make_index()
    idx2.register("new-pkg","1.0.0",{"url":"","checksum":"","description":"New"})
    return "new-pkg" in idx2.list_packages()
chk("register new pkg",    _test_register)

def _test_yank():
    idx2 = _make_index()
    ok = idx2.yank("core-utils","1.0.0")
    info = idx2.get_info("core-utils","1.0.0")
    return ok and info.get("yanked") == True
chk("yank version",        _test_yank)

# ════════════════════════════════════════════════════════
print("\n-- Formatter --")
# ════════════════════════════════════════════════════════
from varek.formatter import format_source, Formatter

def _fmt(src): return format_source(src).strip()

chk("formatter preserves content",  lambda: "hello" in _fmt('let x = "hello"'))
chk("formatter adds newline",        lambda: format_source("let x = 1").endswith("\n"))
chk("formatter schema blank line",   lambda: "\n\n" in format_source("let x = 1\nschema S { x: int }"))
chk("formatter fn blank line",       lambda: "\n\n" in format_source("let x = 1\nfn f() -> int { 0 }"))
chk("formatter comment preserved",   lambda: "--" in _fmt("-- a comment\nlet x = 1"))
chk("formatter nil lowercase",        lambda: "nil" in _fmt("let x = nil"))

def _test_fmt_file():
    with tempfile.NamedTemporaryFile(suffix=".syn",delete=False,mode="w") as f:
        f.write("let x=1\nfn f()->int{0}\n"); path=f.name
    try:
        from varek.formatter import format_file
        result = format_file(path, in_place=True)
        with open(path) as f2: content = f2.read()
        return "fn" in content
    finally:
        os.unlink(path)
chk("format_file in_place",          _test_fmt_file)

def _test_check_format():
    from varek.formatter import check_format
    with tempfile.NamedTemporaryFile(suffix=".syn",delete=False,mode="w") as f:
        # Write already-formatted content
        f.write("let x = 1\n"); path=f.name
    try:
        return check_format(path)  # Should be True (already clean)
    finally:
        os.unlink(path)
chk("check_format clean file",       _test_check_format)

# ════════════════════════════════════════════════════════
print("\n-- Doc Generator --")
# ════════════════════════════════════════════════════════
from varek.doc_gen import DocParser, MarkdownRenderer, HtmlRenderer, generate_docs

DOC_SOURCE = '''---
Utility functions for the pipeline module.

Provides common operations used across pipeline stages.
---

---
Compute the Fibonacci number for n.

Arguments:
  n: int — the input value (must be >= 0)

Returns: int — the nth Fibonacci number

Example:
  fib(10)  -- 55
  fib(20)  -- 6765
---
fn fib(n: int) -> int {
  if n <= 1 { n } else { fib(n-1) + fib(n-2) }
}

---
An image schema for pipeline inputs.
---
schema ImageInput {
  path:  str,
  label: str?,
  width: int
}

-- Simple constant
let MAX_BATCH_SIZE = 128
'''

parser = DocParser()
module = parser.parse(DOC_SOURCE, "utils", "utils.syn")

chk("module_doc extracted",    lambda: "Utility functions" in module.module_doc)
chk("fn item found",           lambda: any(i.name == "fib" for i in module.items))
chk("schema item found",       lambda: any(i.name == "ImageInput" for i in module.items))
chk("fn doc extracted",        lambda: next(i for i in module.items if i.name=="fib").doc != "")
chk("fn signature extracted",  lambda: "fn fib" in next(i for i in module.items if i.name=="fib").signature)
chk("fn params extracted",     lambda: len(next(i for i in module.items if i.name=="fib").params) > 0)
chk("fn returns extracted",    lambda: "int" in next(i for i in module.items if i.name=="fib").returns)
chk("fn examples extracted",   lambda: len(next(i for i in module.items if i.name=="fib").examples) > 0)
chk("fn summary",              lambda: "Fibonacci" in next(i for i in module.items if i.name=="fib").summary)
chk("schema kind",             lambda: next(i for i in module.items if i.name=="ImageInput").kind == "schema")

md = MarkdownRenderer().render_module(module)
chk("md has fn header",       lambda: "### `fib`" in md)
chk("md has schema header",   lambda: "### `ImageInput`" in md)
chk("md has code block",      lambda: "```varek" in md)

html = HtmlRenderer().render_module(module, "utils")
chk("html is valid html",     lambda: "<!DOCTYPE html>" in html)
chk("html has fn anchor",     lambda: 'id="fib"' in html)
chk("html has signature",     lambda: "fn fib" in html)

def _test_generate_docs():
    with tempfile.TemporaryDirectory() as src_dir:
        with tempfile.TemporaryDirectory() as out_dir:
            # Write a .syn source file
            with open(os.path.join(src_dir,"main.syn"),"w") as f:
                f.write(DOC_SOURCE)
            generated = generate_docs(src_dir, out_dir, "markdown", "mylib")
            has_md   = any(p.endswith(".md") for p in generated)
            has_json = any(p.endswith("api.json") for p in generated)
            # Verify api.json content
            json_path = next(p for p in generated if p.endswith("api.json"))
            with open(json_path) as jf:
                api = json.load(jf)
            has_items = len(api["all_items"]) > 0
            return has_md and has_json and has_items
chk("generate_docs creates files", _test_generate_docs)

# ════════════════════════════════════════════════════════
print("\n-- syn CLI --")
# ════════════════════════════════════════════════════════
import subprocess

def _cli(*args):
    r = subprocess.run(
        [sys.executable, "varek_cli.py"] + list(args),
        capture_output=True, text=True, timeout=30
    )
    return r

chk("syn --version",          lambda: "1.0.0" in _cli("--version").stdout)
chk("varek version cmd",        lambda: "1.0.0" in _cli("version").stdout)
chk("syn no args shows help", lambda: "VAREK" in _cli().stdout)

def _test_syn_new():
    cli = os.path.abspath("varek_cli.py")
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run(
            [sys.executable, cli,"new","myproject"],
            capture_output=True, text=True, cwd=d, timeout=15
        )
        created = os.path.exists(os.path.join(d,"myproject","varek.toml"))
        has_src = os.path.exists(os.path.join(d,"myproject","src","main.syn"))
        has_test= os.path.exists(os.path.join(d,"myproject","tests","test_main.syn"))
        has_readme = os.path.exists(os.path.join(d,"myproject","README.md"))
        return r.returncode == 0 and created and has_src and has_test and has_readme
chk("varek new creates project", _test_syn_new)

def _test_syn_init():
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run(
            [sys.executable, os.path.abspath("varek_cli.py"),"init"],
            capture_output=True, text=True, cwd=d, timeout=15
        )
        return r.returncode == 0 and os.path.exists(os.path.join(d,"varek.toml"))
chk("varek init creates manifest", _test_syn_init)

def _test_syn_run():
    with tempfile.TemporaryDirectory() as d:
        # Create minimal project
        with open(os.path.join(d,"varek.toml"),"w") as f:
            f.write('[package]\nname="t"\nversion="0.1.0"\n[scripts]\nmain="main.syn"\n')
        with open(os.path.join(d,"main.syn"),"w") as f:
            f.write('let x = 42\n')
        r = subprocess.run(
            [sys.executable, os.path.abspath("varek_cli.py"),"run"],
            capture_output=True, text=True, cwd=d, timeout=15
        )
        return r.returncode == 0
chk("varek run executes project", _test_syn_run)

def _test_syn_check():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d,"varek.toml"),"w") as f:
            f.write('[package]\nname="t"\nversion="0.1.0"\n[scripts]\nmain="main.syn"\n')
        with open(os.path.join(d,"main.syn"),"w") as f:
            f.write('fn add(a: int, b: int) -> int { a + b }\n')
        r = subprocess.run(
            [sys.executable, os.path.abspath("varek_cli.py"),"check"],
            capture_output=True, text=True, cwd=d, timeout=15
        )
        return r.returncode == 0
chk("varek check passes",        _test_syn_check)

def _test_syn_fmt():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d,"varek.toml"),"w") as f:
            f.write('[package]\nname="t"\nversion="0.1.0"\n')
        with open(os.path.join(d,"src.syn"),"w") as f:
            f.write('let x=1\n')
        r = subprocess.run(
            [sys.executable, os.path.abspath("varek_cli.py"),"fmt",
             os.path.join(d,"src.syn")],
            capture_output=True, text=True, cwd=d, timeout=15
        )
        return r.returncode == 0
chk("varek fmt runs ok",         _test_syn_fmt)

def _test_syn_search():
    r = _cli("search","core")
    return r.returncode == 0  # Empty registry is fine, just no crash
chk("varek search no crash",     _test_syn_search)

# ════════════════════════════════════════════════════════
print("\n-- RFC Documents --")
# ════════════════════════════════════════════════════════

chk("RFC template exists",     lambda: os.path.exists("docs/RFC_TEMPLATE.md"))
chk("GOVERNANCE.md exists",    lambda: os.path.exists("docs/GOVERNANCE.md"))
chk("RFC 0001 exists",         lambda: os.path.exists("rfcs/0001-pipeline-type-verification.md"))
chk("RFC 0002 exists",         lambda: os.path.exists("rfcs/0002-tensor-shape-inference.md"))
chk("RFC 0003 exists",         lambda: os.path.exists("rfcs/0003-package-format.md"))

def _test_rfc_content():
    with open("rfcs/0001-pipeline-type-verification.md") as f:
        content = f.read()
    return all(kw in content for kw in ["RFC Number","Summary","Motivation","Implemented"])
chk("RFC 0001 content valid",  _test_rfc_content)

def _test_governance_content():
    with open("docs/GOVERNANCE.md") as f:
        content = f.read()
    return all(kw in content for kw in ["RFC Process","Contributor Ladder","Stability Guarantees"])
chk("GOVERNANCE content valid",_test_governance_content)

# ════════════════════════════════════════════════════════
print("\n-- Stability: v1.0 API Surface --")
# ════════════════════════════════════════════════════════

chk("varek.check available",        lambda: callable(varek.check))
chk("varek.check_expr available",   lambda: callable(varek.check_expr))
chk("varek.parse available",        lambda: callable(varek.parse))
chk("TypeChecker available",          lambda: hasattr(varek, "TypeChecker"))
chk("CheckResult available",          lambda: hasattr(varek, "CheckResult"))
chk("SchemaValidator available",      lambda: hasattr(varek, "SchemaValidator"))
chk("T_INT exported",                 lambda: varek.T_INT is not None)
chk("T_FLOAT exported",               lambda: varek.T_FLOAT is not None)
chk("FunctionType exported",          lambda: varek.FunctionType is not None)
chk("SchemaType exported",            lambda: varek.SchemaType is not None)

# Full pipeline: parse -> check -> interpret
PIPELINE_RUN_PROG = """
import var::pipeline as pl

fn scale(x: int) -> float { float(x) * 1.5 }
fn to_str(x: float) -> str { str(x) }

fn main() -> nil {
  let nums = [1, 2, 3, 4, 5]
  let results = pl.run([scale, to_str], nums)
  results
}
"""

PIPELINE_CHECK_PROG = """
fn scale(x: int) -> float { float(x) * 1.5 }
fn to_str(x: float) -> str { str(x) }
fn compute(a: int, b: int) -> float { float(a + b) }
let x = compute(1, 2)
"""

def _test_full_pipeline():
    from varek.runtime import Interpreter
    i = Interpreter()
    i.run(PIPELINE_RUN_PROG, "<test>")
    return True
chk("full pipeline program runs",     _test_full_pipeline)

check_result = varek.check(PIPELINE_CHECK_PROG)
chk("full pipeline type checks",      lambda: check_result.ok)

# ════════════════════════════════════════════════════════
print(f"\n{'='*56}")
print(f"  {P} passed  |  {F} failed  |  {P+F} total")
print(f"{'='*56}")
if FAILS:
    print("\nFailed:")
    for n,m in FAILS: print(f"  {n}: {m}")
sys.exit(0 if F==0 else 1)
