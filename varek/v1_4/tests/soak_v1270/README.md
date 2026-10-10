# The v1.27 soak test

Section 7 of `docs/security/v1.27-program-launches.md`: an agent under the
Warden, with `require warden 1.27`, launches programs for 24 hours. Once a
minute it runs one task in turn, and every tenth turn is a launch the policy
must refuse. The run must show:
- every task succeeded, with each of its launches allowed, certified and seen
  running (an `exec_result` of `launched`, or `gone` for a program that ended
  before any mediated call);
- every probe refused, for the reason it must be, with EACCES to the agent;
- no process killed by the identity check, and the audit passing.

| File | What it does |
|---|---|
| `soak.sh` | Runs the test: writes the policy, starts the Warden and the agent, then runs the checker. |
| `soak_agent.py` | The agent: one task a minute, every tenth turn a probe. |
| `soak_check.py` | Judges the run and writes `report.txt`. |

**The tasks**, in turn:

| Task | Launches |
|---|---|
| `git` | `git --version`, then `git hash-object` of a file |
| `python` | `python3 -c 'print(sum(range(1000)))'` |
| `compile` | `cc -o t t.c`: `cc`, then `cc1`, `as`, `collect2` and `ld` (only where `cc`, its `cc1`, `as` and `ld` are installed) |

**The probes**, in turn:

| Probe | What it launches | Must be |
|---|---|---|
| `unlisted` | `/usr/bin/false` | refused, no rule allows it (`default_deny_unknown`) |
| `denied` | `/usr/bin/env` | refused by the deny rule (`policy_match`) |
| `written` | a program the agent writes now into a directory whose names a rule allows | refused, not in the launch set (`exec_not_in_ruleset`) |

## Running it

On the droplet, as root.

1. Check that Landlock is enabled (it must be listed):

   ```
   cat /sys/kernel/security/lsm
   ```

2. Check out the branch and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git ~/varek127
   cd ~/varek127 && git checkout claude/varek-roadmap-landing-01dbw5
   make -C varek/v1_4 all
   ```

3. A 3-minute trial (it must end `soak_check: PASS`):

   ```
   varek/v1_4/tests/soak_v1270/soak.sh --hours 0.05 --out /var/tmp/varek-soak1270-trial
   ```

4. The 24-hour run, detached from the terminal:

   ```
   cd ~/varek127 && setsid nohup varek/v1_4/tests/soak_v1270/soak.sh --hours 24 --out /var/tmp/varek-soak1270-24h > /var/tmp/soak1270.out 2>&1 < /dev/null &
   ```

5. Its progress, and at the end its result:

   ```
   ps -eo pid,etime,args | grep soak_v1270 | grep -v grep; wc -l /var/tmp/varek-soak1270-24h/agent.jsonl
   tail -25 /var/tmp/soak1270.out
   ```

The agent's work directory is `/var/tmp/varek-soak1270-work` (the compile's
temporary files and the written probes collect there), and its script is
installed to `/opt/varek-soak1270-agent`.
