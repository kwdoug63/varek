# VAREK v1.6 — recorded demo

This directory contains a recorded asciinema cast of the v1.6
end-to-end demo and the script that produced it. The cast is a real
terminal session: every command was executed against the v1.6 source
tree and a freshly-patched v1.4 Warden. Typing and pacing are
synthesized to read at human speed.

| File                       | Purpose                                                 |
|----------------------------|---------------------------------------------------------|
| `varek_v1_6_demo.cast`     | asciinema v2 cast file (~18 KB, ~56s playback).         |
| `index.html`               | Self-contained player page for drop-on-server hosting.  |
| `make_cast.py`             | Reproducible cast generator. Re-run to refresh.         |
| `DEMO.md`                  | This file.                                              |

## Play it locally

The Python `asciinema` 2.x CLI is **Unix-only** (it depends on `fcntl`).
For local playback, choose by OS:

- **Linux / macOS / WSL**: `pip install asciinema && asciinema play demo/varek_v1_6_demo.cast`
- **Windows (native)**: download the asciinema 3.x Rust static binary from
  [github.com/asciinema/asciinema/releases](https://github.com/asciinema/asciinema/releases),
  then `asciinema.exe play demo/varek_v1_6_demo.cast`.

## Self-host on your own domain (recommended)

`demo/index.html` is a complete drop-on-server page that loads the cast
and the [asciinema-player](https://github.com/asciinema/asciinema-player)
JS library from jsDelivr. Upload both files to a directory on your
web server:

```
varek-lang.org/demo/
├── index.html
└── varek_v1_6_demo.cast
```

Open `https://varek-lang.org/demo/` and the player is live. No
asciinema.org account, no CLI, no build step. CDN-delivered
stylesheet and JS bundle pin to the asciinema-player v3 major
version; the page renders in dark mode when the visitor's OS
preference is dark.

To pin a specific asciinema-player minor version, edit the two
`@3` references in `index.html` to e.g. `@3.14`.

## Embed in the main README via asciinema.org

If you want the player to render directly in the repo README on
GitHub (no self-hosting), upload to asciinema.org once and embed
the SVG badge:

```sh
# On Linux/macOS/WSL:
asciinema upload demo/varek_v1_6_demo.cast
# On Windows native: use the Rust 3.x asciinema.exe binary.
```

The upload command prints a URL like `https://asciinema.org/a/12345`.
Embed in the main README with:

```markdown
[![asciicast](https://asciinema.org/a/12345.svg)](https://asciinema.org/a/12345)
```

The SVG badge is a clickable thumbnail; clicking opens the
interactive player on asciinema.org.

## Render to GIF (for LinkedIn / Twitter / slide decks)

LinkedIn does not embed asciinema players. For those channels, render
to GIF or MP4 with [`agg`](https://github.com/asciinema/agg):

```sh
cargo install --git https://github.com/asciinema/agg
agg demo/varek_v1_6_demo.cast demo/varek_v1_6_demo.gif \
    --font-family 'JetBrains Mono,Monaco,monospace' \
    --speed 1.2
```

For an MP4 from the GIF: `ffmpeg -i demo/varek_v1_6_demo.gif demo/varek_v1_6_demo.mp4`.

## Render to SVG (inline README embeds)

For an SVG that renders directly in GitHub READMEs without external
hosting, use [`svg-term-cli`](https://github.com/marionebl/svg-term-cli):

```sh
npm install -g svg-term-cli
svg-term --cast=- --out=demo/varek_v1_6_demo.svg < demo/varek_v1_6_demo.cast
```

Then in the README:

```markdown
![VAREK v1.6 demo](demo/varek_v1_6_demo.svg)
```

## Reproduce the cast

```sh
cd v1_6
python3 demo/make_cast.py
```

The generator:

1. Cleans and rebuilds the v1.6 tools.
2. Copies the repo to a throwaway tree and applies `warden_v1_4.patch`.
3. Builds the patched Warden.
4. Synthesizes a temp scene directory with policy and plan files.
5. Runs each demo command, captures output, builds the cast.
6. Validates the produced cast (header parses, events are time-monotonic).
7. Cleans up the throwaway tree.

No state outside `demo/varek_v1_6_demo.cast` is modified.

## Annotated transcript

The cast walks through six scenes in roughly 56 seconds.

### 1. Unit tests (8 binaries)

```
$ make check
-- tests/test_evaluator
test_evaluator: PASS
...
-- tests/test_plan_parser
test_plan_parser: PASS
all tests passed
```

Eight test binaries covering: baseline evaluator behavior, symmetric
suppression on UNSAT and UNKNOWN, exhaustive permutation invariance
(960 permutations across three node-set shapes), fanout poisoning at
every position, cycle detection, the Warden adapter, the JSON
pathology format, and the plan-file parser.

### 2. v1.6.0 kernel

```
$ ./plan_demo
clean_plan: decision=SATISFIED authorized=true nodes=3 edges=3
poisoned_plan: decision=UNSATISFIED authorized=false
```

A clean three-node diamond verifies and authorizes. A four-node plan
with one UNSATISFIED node suppresses the whole plan via the
compositional join.

### 3. v1.6.1 adapter + pathology

```
$ ./adapter_demo
scenario_1 (permissive decider):  SATISFIED
scenario_2 (toy decider denies net_connect): UNSATISFIED
```

The adapter emits one JSON pathology record per verification. Records
include the suppressed node label, the suppression reason classifier
(`node` / `cycle` / `empty` / `capacity` / `edge_index`), the
plan-level decision, and the monotonic-clock verification latency
in microseconds.

### 4. Patched Warden refuses to fork on UNSATISFIED plan

```
$ ./warden policy.txt --plan plan_denied.txt -- /bin/echo 'TARGET RAN (must NOT appear)'
[warden] loaded policy default v1.4 with 3 rules
{
  "decision": "UNSATISFIED",
  "authorized": false,
  "suppression_reason": "node",
  "suppressed_node": "post",
  ...
}
[warden] plan rejected (UNSATISFIED); refusing to fork target
```

The target binary never runs. The plan verification fires in `main()`
before `fork()`; on any non-SATISFIED decision the supervisor exits
with non-zero status and the agent process is never created. This is
the strongest possible realization of "pre-execution verification."

### 5. Authorized plan — both layers visible

```
$ ./warden policy.txt --plan plan_allowed.txt -- /bin/true
[warden] loaded policy default v1.4 with 3 rules
{
  "report_id": "pp-...",         <-- plan-level v1.6 record
  "decision": "SATISFIED",
  "authorized": true,
  ...
}
[warden] plan authorized (2 actions); proceeding to supervise
[warden] supervising pid=...   notify_fd=4  policy=default (3 rules)
execvp: Permission denied
{
  "report_id": "pr-...",         <-- per-action v1.4 record
  "action": "process.exec",
  "target": "/bin/true",
  "decision_final": "DENY",
  "kernel_verdict": "EPERM",
  ...
}
```

Two pathology record prefixes appear in sequence:

- `pp-` — plan-level. The agent's declared intent ("exec a Python
  interpreter") was authorized by v1.6.
- `pr-` — per-action. The actual `execve()` syscall at runtime was
  for `/bin/true`, which is not on the policy allowlist. v1.4's
  per-syscall layer catches it and returns `EPERM` to the kernel.

Layered defense, end to end. The plan layer authorized the abstract
intent. The per-action layer enforced what was actually attempted at
runtime. The two layers operate independently and reinforce rather
than substitute for each other.

## Patent mapping

The demo demonstrates the three patent claims composed:

| Patent | What it covers                                    | Where it appears in the demo            |
|--------|---------------------------------------------------|-----------------------------------------|
| 64/006,104 | SMT-style decision procedure, symmetric suppression | Every record is SATISFIED / UNSATISFIED / UNKNOWN with both negatives suppressing. |
| 64/059,592 | Warden architecture, kernel injection           | The `pr-` per-action records show the v1.4 Warden's seccomp-unotify supervisor in action. |
| 64/062,549 | Pre-execution verification of action graphs     | The `pp-` plan-level records and the pre-fork rejection are this patent in code. |
