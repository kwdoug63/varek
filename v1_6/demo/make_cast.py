#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
make_cast.py — generate an asciinema v2 cast file for the VAREK v1.6 demo.

Commands and outputs are real (executed against the v1.6 source tree
and a freshly-patched warden in /tmp). Typing and pacing are
synthesized to read at human speed. Output: varek_v1_6_demo.cast in
this directory.

Usage:
    python3 demo/make_cast.py            # from v1_6/
    python3 make_cast.py                 # from v1_6/demo/

Cast format reference: https://docs.asciinema.org/manual/asciicast/v2/
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── Visual / pacing parameters ────────────────────────────────────
WIDTH               = 100
HEIGHT              =  32
PROMPT              = "$ "
PROMPT_DELAY        = 0.15
CHAR_DELAY          = 0.040    # ~25 cps typing
PAUSE_AFTER_TYPE    = 0.30
PAUSE_BEFORE_OUTPUT = 0.15
SHORT_PAUSE         = 0.80
SCENE_PAUSE         = 1.60
EMPHASIS_PAUSE      = 3.00


# ── Cast builder ──────────────────────────────────────────────────

class Cast:
    def __init__(self, width: int, height: int) -> None:
        self.width  = width
        self.height = height
        self.t      = 0.0
        self.events: list = []

    def _emit(self, text: str) -> None:
        if not text:
            return
        self.events.append([round(self.t, 6), "o", text])

    def _advance(self, dt: float) -> None:
        self.t += max(0.0, dt)

    def prompt(self) -> None:
        self._emit(PROMPT)
        self._advance(PROMPT_DELAY)

    def type(self, cmd: str) -> None:
        for ch in cmd:
            self._emit(ch)
            self._advance(CHAR_DELAY)
        self._advance(PAUSE_AFTER_TYPE)
        self._emit("\r\n")
        self._advance(PAUSE_BEFORE_OUTPUT)

    def output(self, text: str) -> None:
        # Terminals expect CRLF, not LF.
        normalized = text.replace("\r\n", "\n").replace("\n", "\r\n")
        if normalized and not normalized.endswith("\r\n"):
            normalized += "\r\n"
        self._emit(normalized)
        self._advance(0.15)

    def comment(self, text: str) -> None:
        """Type a shell comment line (no execution)."""
        self.prompt()
        self.type("# " + text)

    def pause(self, seconds: float) -> None:
        self._advance(seconds)

    def render(self, title: str) -> str:
        header = {
            "version":   2,
            "width":     self.width,
            "height":    self.height,
            "timestamp": int(time.time()),
            "env":       {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
            "title":     title,
        }
        lines = [json.dumps(header)]
        for ev in self.events:
            lines.append(json.dumps(ev))
        return "\n".join(lines) + "\n"


# ── Command execution helpers ─────────────────────────────────────

def run(cmd: str, cwd: Path) -> str:
    """Run a shell command, return combined stdout+stderr as a single string."""
    r = subprocess.run(cmd, cwd=str(cwd), shell=True,
                       capture_output=True, text=True)
    return r.stdout + r.stderr


def run_streams(cmd: str, cwd: Path):
    """Run a shell command, return (stdout, stderr) separately."""
    r = subprocess.run(cmd, cwd=str(cwd), shell=True,
                       capture_output=True, text=True)
    return r.stdout, r.stderr


def pretty_jsonl(stream: str) -> str:
    """Pretty-print one JSON-per-line stream. Non-JSON lines pass through."""
    out_lines = []
    for line in stream.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            out_lines.append(json.dumps(obj, indent=2))
        except json.JSONDecodeError:
            out_lines.append(line)
    return "\n".join(out_lines)


# ── Scene script ──────────────────────────────────────────────────

def build_cast(v1_6_dir: Path, warden_dir: Path, tmp: Path) -> Cast:
    cast = Cast(WIDTH, HEIGHT)

    # Scene 0 — context
    cast.comment("VAREK v1.6 demo")
    cast.comment("Pre-execution verification of agent action graphs")
    cast.comment("USPTO Provisional 64/062,549")
    cast.pause(SHORT_PAUSE)

    # Scene 1 — unit tests (8 binaries)
    cast.prompt()
    cast.type("make check")
    full = run("make check", cwd=v1_6_dir)
    test_lines = "\n".join(
        line for line in full.splitlines()
        if line.startswith(("--", "test_", "all "))
    )
    cast.output(test_lines)
    cast.pause(SCENE_PAUSE)

    # Scene 2 — kernel demo
    cast.comment("v1.6.0 kernel: ExecutionPlan + compositional evaluator")
    cast.prompt()
    cast.type("./plan_demo")
    cast.output(run("./plan_demo", cwd=v1_6_dir))
    cast.pause(SCENE_PAUSE)

    # Scene 3 — adapter demo with pretty-printed pathology
    cast.comment("v1.6.1 adapter: plan_spec -> verified plan + JSON pathology")
    cast.prompt()
    cast.type("./adapter_demo 2> >(python3 -m json.tool --json-lines)")
    out, err = run_streams("./adapter_demo", cwd=v1_6_dir)
    cast.output(out + pretty_jsonl(err))
    cast.pause(SCENE_PAUSE)

    # Scene 4 — patched warden, denied plan (the pre-execution suppression moment)
    cast.comment("v1.6.2 integration: patched warden refuses to fork "
                 "when plan is unsatisfied")
    cast.prompt()
    cast.type("cat plan_denied.txt")
    cast.output((tmp / "plan_denied.txt").read_text())
    cast.pause(SHORT_PAUSE)

    cast.prompt()
    cmd = ("./warden policy.txt --plan plan_denied.txt "
           "-- /bin/echo 'TARGET RAN (must NOT appear)'")
    cast.type(cmd)
    denied_out = run(
        "./warden policy.txt --plan plan_denied.txt "
        "-- /bin/echo 'TARGET RAN (must NOT appear)'",
        cwd=tmp,
    )
    # Pretty-print the embedded JSON line so the suppression record is readable.
    pretty = []
    for line in denied_out.splitlines():
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                pretty.append(json.dumps(json.loads(s), indent=2))
                continue
            except json.JSONDecodeError:
                pass
        pretty.append(line)
    cast.output("\n".join(pretty))
    cast.pause(EMPHASIS_PAUSE)

    # Scene 5 — authorized plan, both layers fire
    cast.comment("Authorized plan: both layers fire in sequence")
    cast.comment("  pp- record = plan-level (v1.6); pr- record = per-action (v1.4)")
    cast.prompt()
    cast.type("cat plan_allowed.txt")
    cast.output((tmp / "plan_allowed.txt").read_text())
    cast.pause(SHORT_PAUSE)

    cast.prompt()
    cmd = "./warden policy.txt --plan plan_allowed.txt -- /bin/true"
    cast.type(cmd)
    ok_out = run(cmd, cwd=tmp)
    pretty = []
    for line in ok_out.splitlines():
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                pretty.append(json.dumps(json.loads(s), indent=2))
                continue
            except json.JSONDecodeError:
                pass
        pretty.append(line)
    cast.output("\n".join(pretty))
    cast.pause(EMPHASIS_PAUSE)

    cast.comment("Plan layer authorized the abstract intent.")
    cast.comment("Per-action layer caught the actual exec target. ")
    cast.comment("Layered defense, end to end.")
    cast.pause(SCENE_PAUSE)

    return cast


# ── Setup: build v1.6 module and apply patch in throwaway tree ────

def prepare_environment(v1_6_dir: Path) -> tuple[Path, Path]:
    """Build v1.6 tools in place, apply patch in a throwaway tree, and
    materialize policy/plan files in a temp directory for warden scenes."""
    # Build v1.6.0/1 binaries in the source tree
    subprocess.run(["make", "clean"], cwd=str(v1_6_dir),
                   capture_output=True, check=True)
    subprocess.run(["make"], cwd=str(v1_6_dir),
                   capture_output=True, check=True)

    # Apply the warden patch in a throwaway copy
    repo_src = v1_6_dir.parent
    work = Path(tempfile.mkdtemp(prefix="varek_demo_"))
    shutil.copytree(repo_src, work / "varek")
    subprocess.run(
        ["git", "apply", str(work / "varek" / "v1_6" / "warden_v1_4.patch")],
        cwd=str(work / "varek"), check=True,
    )
    warden_dir = work / "varek" / "varek" / "v1_4"
    subprocess.run(["make", "warden"], cwd=str(warden_dir),
                   capture_output=True, check=True)

    # Materialize policy + two plan files in a shared scene directory
    scene = Path(tempfile.mkdtemp(prefix="varek_scene_"))
    (scene / "warden").symlink_to(warden_dir / "warden")
    (scene / "policy.txt").write_text(
        "allow path /var/data/\n"
        "allow exec /usr/bin/python3\n"
        "deny  host api.example.com\n"
    )
    (scene / "plan_denied.txt").write_text(
        "action load file_open    /var/data/input.json\n"
        "action exec process_exec /usr/bin/python3\n"
        "action post net_connect  api.example.com:443\n"
        "edge load exec\n"
        "edge exec post\n"
    )
    (scene / "plan_allowed.txt").write_text(
        "action load file_open    /var/data/input.json\n"
        "action exec process_exec /usr/bin/python3\n"
        "edge load exec\n"
    )
    return work, scene


def main() -> int:
    here = Path(__file__).resolve().parent
    # Script lives in demo/, so v1_6 is the parent.
    v1_6 = here.parent if here.name == "demo" else here
    if not (v1_6 / "Makefile").exists():
        print(f"ERROR: cannot locate v1_6 Makefile from {here}", file=sys.stderr)
        return 2

    work, scene = prepare_environment(v1_6)
    try:
        cast = build_cast(v1_6, work / "varek" / "varek" / "v1_4", scene)
        out_path = here / "varek_v1_6_demo.cast"
        out_path.write_text(cast.render(title="VAREK v1.6 — pre-execution plan verification"))

        # Sanity-check: header parses, events are time-monotonic.
        with open(out_path) as f:
            header = json.loads(f.readline())
            assert header["version"] == 2
            t_prev = -1.0
            n_events = 0
            for line in f:
                if not line.strip(): continue
                ev = json.loads(line)
                assert ev[1] == "o"
                assert ev[0] >= t_prev, f"non-monotonic at event {n_events}"
                t_prev = ev[0]
                n_events += 1
        duration = t_prev
        print(f"wrote {out_path} ({n_events} events, {duration:.1f}s playback)")
        return 0
    finally:
        shutil.rmtree(work,  ignore_errors=True)
        shutil.rmtree(scene, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
