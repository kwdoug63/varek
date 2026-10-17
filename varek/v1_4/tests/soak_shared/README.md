# The shared soak: v1.28.1, v1.29.0 and v1.31.0

One 24-hour soak for the three releases after v1.28.0, run from the v1.31
branch: its Warden is all three. Three runs side by side, each a turn a
minute, every tenth turn a probe; then `soak_check.py` judges them and
writes `report.txt`. Everything they talk to runs on the same host, so what
each run let through can be checked where it arrives.

| Run | Releases | What it does |
|---|---|---|
| A | v1.28.1, v1.31.0 | An agent on behalf of a user whose token the Warden verified (`trust issuer`, `require on-behalf-of`), the egress proxy in inspecting mode. It launches two confined MCP servers once and keeps them all run: `fs` reads project files under its own rules; `gh` calls a remote MCP server with the run's MCP token (`credential mt ... audience=`), put in by the proxy only where a rule written `for=gh` names it. The agent also makes MCP calls of its own and launches sub-agents (`coder` launches `tester`). The user's token expires near the end, and the run is revoked by it. The OCSF export follows the stream the whole run. |
| B | v1.29.0 | `varek run` with nothing set up (the baseline policy and the `python` profile): an agent's work in its project directory, each turn writing files, running `python3` and, every fifth turn, `git commit`. |
| C | v1.29.0 | The same work as a dry run of a narrower policy (the project read-only but `build/` and `.git/`). At the end, `varek policy suggest` drafts a policy from the run, and a short dry run under the draft checks it. |

**Run A's tasks**, in turn: `tools/list` and `tools/call search_code` by
the agent; `fs` reads a project file; `gh` calls `get_issue` on the remote
server; `coder` and `tester` each open a project file.

**Run A's probes**, in turn:

| Probe | What happens | Must be |
|---|---|---|
| `mcp_delete` | the agent calls `delete_repo` | 403 (a deny rule) |
| `mcp_unlisted` | the agent calls `other_tool` | 403 (no rule) |
| `agent_get` | the agent calls `get_issue` itself | 403 (only `gh`'s rule allows it) |
| `fs_outside` | `fs` reads the agent's own file | EACCES (not `fs`'s) |
| `fs_store` | `fs` reads the MCP token's file | EACCES |
| `gh_delete` | `gh` calls `delete_repo` | 403 (deny `for=gh`) |
| `agent_srvfile` | the agent opens a file only `fs` may read | EACCES |
| `env_launch` | the agent launches a second `fs` with `PYTHONPATH` set | refused at the launch (`subagent_env`) |

**Run B's probes**: reading `/etc/shadow`, writing outside the project, and
launching a program the agent wrote (a copy of `true`): each EACCES.

**The run must show** (`soak_check.py`):

- A: every task before the expiry worked and every probe held, each call
  decided for its own subject (the agent, `fs`, `gh`, the sub-agents), with
  the chain `user`, `agent`, sub-agent... on every record and each server's
  certificate subject; the remote server got the MCP token only in `gh`'s
  allowed calls, and nothing refused, no placeholder and no user's token;
  the expiry recorded once and the run revoked by it, every decision after
  it refused and nothing reaching the remote server after; no token in the
  stream, the agent's output or the OCSF events; the audit passing; the OCSF
  events matching the stream (`varek_ocsf.py --verify`) and valid OCSF 1.9.0
  (`tests/ocsf_validate.py`).
- B: every turn of work done (git commits made), every probe refused and
  recorded; the audit passing (the stream signed with the key `varek run`
  made on first use).
- C: every turn of work done, the narrower policy's refusals recorded and let
  through (`"enforced": false`); the audit saying `VERIFIED: DRY RUN, NOT
  ENFORCED` (exit 3); the draft linting and loading in the certificate
  checker; under the draft, nothing let through but the system calls the
  draft notes no rule can admit (git's `link`).

It also reports each task's time at the agent, the Warden's time per
decision for each subject, and each process's memory over the run
(`rss.tsv`: the Warden of each run, A's proxy and `warden-secrets`, and the
two MCP servers).

| File | What it does |
|---|---|
| `soak.sh` | Runs the soak: the stand-ins, the policies, the three runs, the OCSF export, then `policy suggest` and the checker. |
| `agent_a.py` | Run A's agent: its tasks and probes. |
| `fs_server.py`, `gh_server.py` | Run A's stdio MCP servers (confined). |
| `soak_remote.py` | Run A's remote MCP server: checks the token where it arrives, and logs no value. |
| `build_agent.py` | Runs B's and C's agent: the work, and B's probes. |
| `soak_check.py` | Judges the runs and writes `report.txt`. |

It reuses `tests/v1310_as.py` (the user's issuer, which also mints the
tokens), `tests/dns_test_server.py` and `tests/v1281_sub` (the sub-agents).

## Running it

On the droplet, as root.

1. Install what the stand-ins and the work need:

   ```
   apt-get install -y python3-cryptography openssl git
   ```

2. Check out the branch and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git ~/varek131
   cd ~/varek131 && git checkout claude/varek-v1310-01dbw5
   make -C varek/v1_4 all tests/v1281_sub
   ```

3. A 6-minute trial (a turn every 3 s; it must end `soak_check: PASS`):

   ```
   varek/v1_4/tests/soak_shared/soak.sh --hours 0.1 --interval 3 --out /var/tmp/varek-soak-shared-trial
   ```

4. The 24-hour run, detached from the terminal:

   ```
   cd ~/varek131 && setsid nohup varek/v1_4/tests/soak_shared/soak.sh --hours 24 --out /var/tmp/varek-soak-shared-24h > /var/tmp/soak-shared.out 2>&1 < /dev/null &
   ```

5. Its progress, and at the end its result:

   ```
   ps -eo pid,etime,args | grep soak_shared | grep -v grep; wc -l /var/tmp/varek-soak-shared-24h/*/agent.jsonl
   tail -60 /var/tmp/soak-shared.out
   ```

**Memory.** Over 24 hours runs B and C each write about 250 MB of
records, and the checker and the audit read each stream whole (the audit's
known limit since v1.27.1). On a 2 GB host add swap before the run:

```
fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
```

If the steps after the runs were cut short (`Killed` after "the runs
finished"), they can be done again on the same directory, with the same
options:

```
cd ~/varek131 && varek/v1_4/tests/soak_shared/soak.sh --hours 24 --sign-key KEY --out /var/tmp/varek-soak-shared-24h --check-only
```

While it runs, run nothing else under the Warden on the droplet: the test
suites included (`test_v1280.sh` runs `varek revoke --all`, which revokes
every run on the host, the soak's three with it).

The tokens are in `/etc/varek-soak-shared/` (test values minted by the
stand-in issuer, not real secrets), and the agents' files are installed to
`/opt/varek-soak-shared`. A run may launch 1,024 sub-agents, and run A
launches two every fifth task, so `soak.sh` refuses an interval too short
for the hours asked (at 24 hours, under about 32 s).
