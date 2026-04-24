"""
varek/doc_gen.py
───────────────────
VAREK documentation generator (varek doc).

Parses .syn source files for doc comments and generates:
  - Markdown documentation
  - HTML documentation (single file)
  - JSON API index (for tooling)

Doc comment syntax:
  --- (triple-dash) starts a doc comment block
  The next declaration after the block is the documented item.

  ---
  Compute the Fibonacci number for n.

  Arguments:
    n: int — the input (must be >= 0)

  Returns: int — the nth Fibonacci number

  Example:
    fib(10)  -- 55
  ---
  fn fib(n: int) -> int { ... }
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict


# ══════════════════════════════════════════════════════════════════
# DOC ITEM
# ══════════════════════════════════════════════════════════════════

@dataclass
class DocItem:
    """A single documented declaration."""
    kind:        str          # "fn" | "schema" | "pipeline" | "const"
    name:        str
    signature:   str          # full signature line
    doc:         str          # raw doc comment text
    params:      List[str]    = field(default_factory=list)
    returns:     str          = ""
    examples:    List[str]    = field(default_factory=list)
    deprecated:  bool         = False
    since:       str          = ""
    source_file: str          = ""
    source_line: int          = 0

    @property
    def summary(self) -> str:
        """First sentence of the doc comment."""
        if not self.doc:
            return ""
        first_para = self.doc.strip().split("\n\n")[0]
        return first_para.replace("\n", " ").strip()

    def to_dict(self) -> dict:
        return {
            "kind":       self.kind,
            "name":       self.name,
            "signature":  self.signature,
            "doc":        self.doc,
            "params":     self.params,
            "returns":    self.returns,
            "examples":   self.examples,
            "deprecated": self.deprecated,
            "since":      self.since,
        }


@dataclass
class DocModule:
    """Documentation for a single .syn file."""
    name:        str
    path:        str
    module_doc:  str          = ""
    items:       List[DocItem] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "path":       self.path,
            "module_doc": self.module_doc,
            "items":      [i.to_dict() for i in self.items],
        }


# ══════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════

class DocParser:
    """Extracts documentation from .syn source files."""

    def parse_file(self, path: str) -> DocModule:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        mod_name = Path(path).stem
        return self.parse(source, mod_name, path)

    def parse(self, source: str, mod_name: str, path: str = "") -> DocModule:
        lines       = source.splitlines()
        module      = DocModule(name=mod_name, path=path)
        i           = 0
        pending_doc = ""
        in_doc      = False

        got_module_doc = False
        while i < len(lines):
            line = lines[i].strip()

            # ── Module-level doc (first doc block before any declaration)
            if line == "---" and not module.items and not pending_doc and not got_module_doc:
                doc_lines = []
                i += 1
                while i < len(lines) and lines[i].strip() != "---":
                    doc_lines.append(lines[i])
                    i += 1
                module.module_doc = "\n".join(doc_lines).strip()
                got_module_doc = True
                i += 1
                continue

            # ── Doc comment block ---
            if line == "---":
                doc_lines = []
                i += 1
                while i < len(lines) and lines[i].strip() != "---":
                    doc_lines.append(lines[i])
                    i += 1
                pending_doc = "\n".join(doc_lines).strip()
                i += 1
                continue

            # ── Single-line doc comment --
            if line.startswith("-- ") and pending_doc == "":
                # Check if next line is a declaration
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if self._is_decl(next_line):
                        pending_doc = line[3:].strip()
                        i += 1
                        continue

            # ── Declaration ───────────────────────────────────────
            if self._is_decl(line):
                item = self._parse_decl(line, pending_doc, path, i + 1)
                if item:
                    module.items.append(item)
                pending_doc = ""

            i += 1

        return module

    def _is_decl(self, line: str) -> bool:
        return any(line.startswith(kw) for kw in (
            "fn ", "async fn ", "export fn ", "export async fn ",
            "schema ", "pipeline ", "let ", "mut let ",
        ))

    def _parse_decl(self, line: str, doc: str, path: str, lineno: int) -> Optional[DocItem]:
        # Determine kind and name
        if "fn " in line and not line.startswith("let"):
            kind = "fn"
            m = re.search(r'\bfn\s+(\w+)', line)
            name = m.group(1) if m else "unknown"
        elif line.startswith("schema "):
            kind = "schema"
            m = re.match(r'schema\s+(\w+)', line)
            name = m.group(1) if m else "unknown"
        elif line.startswith("pipeline "):
            kind = "pipeline"
            m = re.match(r'pipeline\s+(\w+)', line)
            name = m.group(1) if m else "unknown"
        elif "let " in line:
            kind = "const"
            m = re.search(r'\blet\s+(\w+)', line)
            name = m.group(1) if m else "unknown"
        else:
            return None

        # Extract params, returns, examples from doc
        params   = self._extract_section(doc, "Arguments", "Args", "Params")
        returns  = self._extract_returns(doc)
        examples = self._extract_examples(doc)
        deprecated = "@deprecated" in doc or "Deprecated:" in doc
        since    = self._extract_tag(doc, "since") or self._extract_tag(doc, "Since")

        return DocItem(
            kind=kind, name=name,
            signature=line.rstrip("{").strip(),
            doc=doc,
            params=params,
            returns=returns,
            examples=examples,
            deprecated=deprecated,
            since=since,
            source_file=path,
            source_line=lineno,
        )

    def _extract_section(self, doc: str, *headers: str) -> List[str]:
        for header in headers:
            pat = re.compile(
                rf'^{re.escape(header)}[:\s]*\n((?:[ \t]+.*\n?)*)',
                re.MULTILINE | re.IGNORECASE
            )
            m = pat.search(doc)
            if m:
                block = m.group(1)
                lines = [l.strip() for l in block.splitlines() if l.strip()]
                return lines
        return []

    def _extract_returns(self, doc: str) -> str:
        m = re.search(r'Returns?[:\s]+(.+)', doc, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def _extract_examples(self, doc: str) -> List[str]:
        m = re.search(
            r'Examples?[:\s]*\n((?:[ \t]+.*\n?)*)',
            doc, re.MULTILINE | re.IGNORECASE
        )
        if not m:
            return []
        block = m.group(1)
        return [l.strip() for l in block.splitlines() if l.strip()]

    def _extract_tag(self, doc: str, tag: str) -> str:
        m = re.search(rf'@{re.escape(tag)}\s+(.+)', doc, re.IGNORECASE)
        return m.group(1).strip() if m else ""


# ══════════════════════════════════════════════════════════════════
# MARKDOWN RENDERER
# ══════════════════════════════════════════════════════════════════

class MarkdownRenderer:

    def render_module(self, module: DocModule) -> str:
        lines = []
        lines.append(f"# `{module.name}`\n")

        if module.module_doc:
            lines.append(module.module_doc)
            lines.append("")

        # Group by kind
        by_kind: Dict[str, List[DocItem]] = {}
        for item in module.items:
            by_kind.setdefault(item.kind, []).append(item)

        for kind, items in [("fn", "Functions"), ("schema", "Schemas"),
                              ("pipeline", "Pipelines"), ("const", "Constants")]:
            if kind not in by_kind:
                continue
            lines.append(f"## {items}\n")
            for item in sorted(by_kind[kind], key=lambda x: x.name):
                lines.append(self._render_item(item))

        return "\n".join(lines)

    def _render_item(self, item: DocItem) -> str:
        parts = []

        if item.deprecated:
            parts.append("> ⚠️ **Deprecated**\n")

        parts.append(f"### `{item.name}`\n")

        if item.since:
            parts.append(f"*Since v{item.since}*\n")

        if item.signature:
            parts.append(f"```varek\n{item.signature}\n```\n")

        if item.doc:
            # Strip structured sections from the summary
            summary = re.sub(
                r'(Arguments?|Args?|Params?|Returns?|Examples?)[:\s]*\n.*',
                '', item.doc, flags=re.DOTALL | re.IGNORECASE
            ).strip()
            if summary:
                parts.append(summary + "\n")

        if item.params:
            parts.append("**Parameters**\n")
            for p in item.params:
                parts.append(f"- {p}")
            parts.append("")

        if item.returns:
            parts.append(f"**Returns:** {item.returns}\n")

        if item.examples:
            parts.append("**Example**\n")
            parts.append("```varek")
            for ex in item.examples:
                parts.append(ex)
            parts.append("```\n")

        parts.append("---\n")
        return "\n".join(parts)


# ══════════════════════════════════════════════════════════════════
# HTML RENDERER
# ══════════════════════════════════════════════════════════════════

class HtmlRenderer:

    CSS = """
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:0 auto;padding:2rem;color:#1e293b;background:#f8fafc}
h1{color:#7c3aed;border-bottom:2px solid #e2e8f0;padding-bottom:.5rem}
h2{color:#1e293b;margin-top:2rem;border-bottom:1px solid #e2e8f0;padding-bottom:.3rem}
h3{color:#0d1117;font-family:monospace;background:#f1f5f9;padding:.4rem .6rem;border-radius:4px;display:inline-block}
pre,code{font-family:'JetBrains Mono',monospace;background:#0f1923;color:#e2e8f0;padding:.2rem .4rem;border-radius:3px}
pre{padding:1rem;overflow-x:auto;border-radius:6px}
blockquote{border-left:3px solid #f59e0b;margin:0;padding:.5rem 1rem;background:#fffbeb}
.deprecated{background:#fef2f2;border:1px solid #fecaca;padding:.5rem 1rem;border-radius:6px;margin:.5rem 0}
.since{color:#64748b;font-size:.85rem}
hr{border:none;border-top:1px solid #e2e8f0;margin:2rem 0}
nav{background:#fff;padding:1rem;border-radius:6px;border:1px solid #e2e8f0;margin-bottom:2rem}
nav a{color:#7c3aed;text-decoration:none;margin-right:1rem}nav a:hover{text-decoration:underline}
</style>
"""

    def render_module(self, module: DocModule, pkg_name: str = "") -> str:
        title = f"{pkg_name} — {module.name}" if pkg_name else module.name

        nav_links = " ".join(
            f'<a href="#{item.name}">{item.name}</a>'
            for item in module.items
        )

        body_parts = []
        body_parts.append(f"<h1><code>{module.name}</code></h1>")

        if module.module_doc:
            body_parts.append(f"<p>{self._md2html(module.module_doc)}</p>")

        if nav_links:
            body_parts.append(f'<nav>{nav_links}</nav>')

        by_kind: Dict[str, List[DocItem]] = {}
        for item in module.items:
            by_kind.setdefault(item.kind, []).append(item)

        for kind, label in [("fn","Functions"),("schema","Schemas"),
                             ("pipeline","Pipelines"),("const","Constants")]:
            if kind not in by_kind:
                continue
            body_parts.append(f"<h2>{label}</h2>")
            for item in sorted(by_kind[kind], key=lambda x: x.name):
                body_parts.append(self._render_item_html(item))

        body = "\n".join(body_parts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
{self.CSS}
</head>
<body>
{body}
</body>
</html>"""

    def _render_item_html(self, item: DocItem) -> str:
        parts = [f'<hr><h3 id="{item.name}">{item.name}</h3>']

        if item.deprecated:
            parts.append('<div class="deprecated">⚠️ <strong>Deprecated</strong></div>')

        if item.since:
            parts.append(f'<span class="since">Since v{item.since}</span>')

        if item.signature:
            parts.append(f"<pre>{item.signature}</pre>")

        if item.doc:
            summary = re.sub(
                r'(Arguments?|Returns?|Examples?)[:\s]*\n.*', '',
                item.doc, flags=re.DOTALL | re.IGNORECASE
            ).strip()
            if summary:
                parts.append(f"<p>{self._md2html(summary)}</p>")

        if item.params:
            parts.append("<p><strong>Parameters</strong></p><ul>")
            for p in item.params:
                parts.append(f"<li>{p}</li>")
            parts.append("</ul>")

        if item.returns:
            parts.append(f"<p><strong>Returns:</strong> {item.returns}</p>")

        if item.examples:
            parts.append("<p><strong>Example</strong></p><pre>")
            parts.append("\n".join(item.examples))
            parts.append("</pre>")

        return "\n".join(parts)

    def _md2html(self, text: str) -> str:
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
        text = text.replace("\n", "<br>")
        return text


# ══════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def generate_docs(
    source_dir: str,
    output_dir: str,
    format_: str = "markdown",
    pkg_name:  str = "",
) -> List[str]:
    """
    Generate documentation for all .syn files in source_dir.
    Returns list of generated output paths.
    """
    parser   = DocParser()
    md_rend  = MarkdownRenderer()
    html_rend= HtmlRenderer()

    os.makedirs(output_dir, exist_ok=True)
    generated = []

    syn_files = list(Path(source_dir).rglob("*.syn"))
    if not syn_files:
        return []

    # Generate per-module docs
    modules = []
    for path in sorted(syn_files):
        try:
            module = parser.parse_file(str(path))
            modules.append(module)

            if format_ in ("markdown", "both"):
                out_path = os.path.join(output_dir, f"{module.name}.md")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(md_rend.render_module(module))
                generated.append(out_path)

            if format_ in ("html", "both"):
                out_path = os.path.join(output_dir, f"{module.name}.html")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(html_rend.render_module(module, pkg_name))
                generated.append(out_path)

        except Exception as e:
            print(f"  Warning: could not parse {path}: {e}")

    # Generate JSON API index
    api_index = {
        "package":  pkg_name,
        "modules":  [m.to_dict() for m in modules],
        "all_items": [
            {**item.to_dict(), "module": m.name}
            for m in modules for item in m.items
        ]
    }
    idx_path = os.path.join(output_dir, "api.json")
    with open(idx_path, "w", encoding="utf-8") as f:
        json.dump(api_index, f, indent=2)
    generated.append(idx_path)

    # Generate index page
    if format_ in ("html", "both"):
        idx_html = _render_index_html(modules, pkg_name)
        idx_path = os.path.join(output_dir, "index.html")
        with open(idx_path, "w", encoding="utf-8") as f:
            f.write(idx_html)
        generated.append(idx_path)

    if format_ in ("markdown", "both"):
        idx_md = _render_index_md(modules, pkg_name)
        idx_path = os.path.join(output_dir, "index.md")
        with open(idx_path, "w", encoding="utf-8") as f:
            f.write(idx_md)
        generated.append(idx_path)

    return generated


def _render_index_md(modules: List[DocModule], pkg_name: str) -> str:
    lines = [f"# {pkg_name} API Reference\n"]
    for m in sorted(modules, key=lambda x: x.name):
        lines.append(f"## [{m.name}]({m.name}.md)\n")
        if m.module_doc:
            lines.append(m.module_doc.split("\n")[0])
            lines.append("")
        for item in sorted(m.items, key=lambda x: x.name):
            lines.append(f"- [`{item.name}`]({m.name}.md#{item.name}) — {item.summary}")
        lines.append("")
    return "\n".join(lines)


def _render_index_html(modules: List[DocModule], pkg_name: str) -> str:
    items_html = ""
    for m in sorted(modules, key=lambda x: x.name):
        items_html += f'<h2><a href="{m.name}.html">{m.name}</a></h2>'
        if m.module_doc:
            items_html += f'<p>{m.module_doc.split(chr(10))[0]}</p>'
        items_html += "<ul>"
        for item in sorted(m.items, key=lambda x: x.name):
            items_html += f'<li><a href="{m.name}.html#{item.name}"><code>{item.name}</code></a>'
            if item.summary:
                items_html += f' — {item.summary}'
            items_html += '</li>'
        items_html += "</ul>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>{pkg_name} — API Reference</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:0 auto;padding:2rem}}
h1{{color:#7c3aed}}a{{color:#7c3aed}}</style>
</head>
<body>
<h1>{pkg_name} — API Reference</h1>
{items_html}
</body></html>"""
