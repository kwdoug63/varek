# es_probe: the Endpoint Security measurements, on an EC2 Mac

The measurements M1 to M4 and M6 of
`docs/security/macos-endpoint-security.md`, made with `es_probe`, a
minimal Endpoint Security client: it supervises one command and its
children, answers each AUTH event from a fixed rule, and records each
answer's time against its deadline, one JSON line each. CI builds it on
GitHub's macOS runner (`platform-fail-closed.yml`: no warnings on macOS
26.7.2, November 15, 2026), signs it ad hoc and runs it as root, where it
stops at `es_new_client` as not entitled; signed with the Developer ID
profile, and run, only on an EC2 Mac. Its measurements are untested until
that run.

Every command below runs on the Mac, at its `ec2-user@… %` prompt (zsh;
first `setopt interactivecomments`), unless it says otherwise. Root only
where `sudo` says so.

## 1. The files

On the Mac, in `~/apple-signing` (mode 700), as ec2-user:

- `varek-devid.key`, the Developer ID key (mode 600). It is the only
  secret here: copy it across only between your own terminals, never
  through a chat, the repository or a bucket, and delete it from the Mac
  before the instance is terminated (step 5).
- the Developer ID Application certificate Apple issued (`.cer`);
- the Developer ID provisioning profile for `ai.soberagents.varek.warden`
  (`.provisionprofile`).

And the checkout:

```
git clone -b claude/varek-roadmap-landing-01dbw5-macos-es https://github.com/kwdoug63/varek.git ~/varek # end
```

## 2. Sign

From an ssh login as ec2-user:

```
~/varek/varek/v1_4/tests/es_probe/keychain.sh ~/apple-signing/varek-devid.key ~/apple-signing/CERT.cer # end
```

From a Session Manager shell, not `sudo -iu ec2-user` (it keeps root's
security session: `0 valid identities`, and codesign fails with
`errSecInternalComponent`), but ec2-user's own, with the keychain made
the default and build_sign.sh in the same command (November 15, 2026):

```
sudo launchctl asuser 501 sudo -u ec2-user -H zsh -c 'K=~/varek/varek/v1_4/tests/es_probe; $K/keychain.sh ~/apple-signing/varek-devid.key ~/apple-signing/CERT.cer && security default-keychain -d user -s ~/Library/Keychains/varek-signing.keychain-db && $K/build_sign.sh ~/apple-signing/PROFILE.provisionprofile "IDENTITY"' # end
```

It checks the certificate is the key's, makes a keychain of its own and
prints the identity, `Developer ID Application: … (TEAM)`. Then, with that
name for IDENTITY:

```
~/varek/varek/v1_4/tests/es_probe/build_sign.sh ~/apple-signing/PROFILE.provisionprofile "IDENTITY" # end
```

It checks the profile (its application identifier, and the Endpoint
Security entitlement), builds, bundles, signs and verifies
`~/es_probe/VarekESProbe.app`.

## 3. M6: what must be approved

```
sudo ~/es_probe/VarekESProbe.app/Contents/MacOS/varek-es-probe -- /usr/bin/true # end
```

- `not entitled`: the signature or the profile is wrong (step 2's output).
- `not permitted`: Full Disk Access is not approved, as expected the first
  time. It is granted in System Settings → Privacy & Security → Full Disk
  Access → `+` → `~/es_probe/VarekESProbe.app`, which needs the Mac's
  screen: enable Screen Sharing (`sudo launchctl load -w
  /System/Library/LaunchDaemons/com.apple.screensharing.plist`), set a
  password for ec2-user yourself (`sudo passwd ec2-user`), and connect a
  VNC viewer through an ssh tunnel (`ssh -L 5900:localhost:5900
  ec2-user@ADDRESS`, then `localhost:5900`). Record each step (M6).
- If it is approved and still `not permitted` from the shell, run it as a
  job of launchd, whose responsible process is the probe itself, not the
  shell that started it (M6 records which one it took):

  ```
  sudo launchctl submit -l ai.soberagents.varek.esprobe -o /tmp/esp.out -e /tmp/esp.err -- $HOME/es_probe/VarekESProbe.app/Contents/MacOS/varek-es-probe --log /tmp/esp.jsonl -- /usr/bin/true # end
  ```

  then `cat /tmp/esp.out /tmp/esp.err`, and `sudo launchctl remove
  ai.soberagents.varek.esprobe`.

Below, `P` is the probe as root, a shell function (if only the `launchctl
submit` form worked, use that form instead):

```
P() { sudo $HOME/es_probe/VarekESProbe.app/Contents/MacOS/varek-es-probe "$@"; } # end
```

## 4. The measurements

Each writes its JSON lines to `~/es-m*.jsonl` and a summary to the
terminal. Send the summaries.

**M1, the time to answer, against the deadline.** A loop of opens, then a
build:

```
P --log ~/es-m1a.jsonl -- /bin/sh -c 'for i in $(seq 1 5000); do /bin/cat /etc/hosts > /dev/null; done' # end
```

```
P --log ~/es-m1b.jsonl -- /bin/sh -c 'cd /tmp && rm -rf m1 && git clone -q https://github.com/kwdoug63/varek.git m1 && python3 -m compileall -q m1 > /dev/null' # end
```

The deadline itself (`budget_ms` in every line), and what happens past it:
each answer delayed, 1 s, then 10 s, then 70 s (a client past its deadline
is expected to be killed: whether the open then goes ahead is the
question):

```
P --log ~/es-m1c.jsonl --delay-us 1000000 -- /bin/cat /etc/hosts # end
```

(and `--delay-us 10000000`, then `--delay-us 70000000`, each with its own
`--log`).

**M2, children.** Opens by a child and a grandchild in the background,
selected by inverted muting (the design's), then by pid, which sees every
process and so misses nothing of the tree:

```
P --log ~/es-m2.jsonl -- /bin/sh -c '/bin/cat /etc/hosts > /dev/null; (/bin/cat /etc/hosts > /dev/null &); /bin/sh -c "/bin/cat /etc/hosts > /dev/null"; wait' # end
```

```
P --log ~/es-m2t.jsonl --track-pids -- /bin/sh -c '/bin/cat /etc/hosts > /dev/null; (/bin/cat /etc/hosts > /dev/null &); /bin/sh -c "/bin/cat /etc/hosts > /dev/null"; wait' # end
```

Every `cat`'s open of `/etc/hosts` should be in each log, three of them,
and the summaries' forks and execs the same. Fewer under inverted muting
means a child acted before its fork was handled (its events unseen): run
it ten times (`for i in $(seq 1 10); do P --log ~/es-m2-$i.jsonl -- …; done`)
to see how often.

**M3, a read-only answer to a read-write open**, and the other writes
refused:

```
sudo mkdir -p /tmp/esw && echo before | sudo tee /tmp/esw/f > /dev/null && sudo chmod 666 /tmp/esw/f # end
```

```
P --log ~/es-m3.jsonl --deny-write /tmp/esw -- /bin/sh -c 'cat /tmp/esw/f; echo after > /tmp/esw/f; echo "write rc=$?"; python3 -c "import os; fd=os.open(\"/tmp/esw/f\", os.O_RDWR); print(\"rdwr fd\", fd, os.read(fd, 6)); os.write(fd, b\"x\")"; rm -f /tmp/esw/f; echo "rm rc=$?"; mv /tmp/esw/f /tmp/esw/g; echo "mv rc=$?"; touch /tmp/esw/new; echo "create rc=$?"; cat /tmp/esw/f' # end
```

What the caller sees for each (an error, and which; or a descriptor that
reads and fails to write) is M3's answer; the file must still read
`before`.

**M4, the kernel's cache.** The loop of M1 again with `--cache`, counting
the answers:

```
P --log ~/es-m4.jsonl --cache -- /bin/sh -c 'for i in $(seq 1 5000); do /bin/cat /etc/hosts > /dev/null; done' # end
```

Fewer answers than M1's first run means opens answered from the cache;
then the same with `--deny-write /private/etc` added (ES gives real paths:
`/etc` is `/private/etc`).

**M4b, a cached allow against a rule that comes after it.** A file anyone
may write:

```
sudo mkdir -p /private/tmp/esc && echo start | sudo tee /private/tmp/esc/f > /dev/null && sudo chmod 666 /private/tmp/esc/f # end
```

1. The same client, the rule turned on mid-run: three appends allowed and
   cached, then the rule (`--rules-on-usr1`: SIGUSR1 from the command),
   then three more appends, each with its exit status:

   ```
   P --log ~/es-m4b.jsonl --track-pids --cache --deny-write /private/tmp/esc --rules-on-usr1 -- /bin/sh -c 'for i in 1 2 3; do /bin/sh -c "echo a$i >> /private/tmp/esc/f"; done; kill -USR1 $PPID; sleep 1; for i in 1 2 3; do /bin/sh -c "echo b$i >> /private/tmp/esc/f"; echo "b$i rc=$?"; done; cat /private/tmp/esc/f' # end
   ```

2. The same, the file reset first (the `mkdir` command above), with
   `--clear-cache-on-usr1` added and `--log ~/es-m4c.jsonl`.
3. Across clients, the file reset first: one probe caches the appends with
   no rule, then a new probe has the rule from its start:

   ```
   P --log ~/es-m4d1.jsonl --track-pids --cache -- /bin/sh -c 'for i in 1 2 3; do /bin/sh -c "echo a$i >> /private/tmp/esc/f"; done' && P --log ~/es-m4d2.jsonl --track-pids --cache --deny-write /private/tmp/esc -- /bin/sh -c 'for i in 1 2 3; do /bin/sh -c "echo b$i >> /private/tmp/esc/f"; echo "b$i rc=$?"; done; cat /private/tmp/esc/f' # end
   ```

For each, send:
- the `b` lines' rc: 0 means the cached allow outlived the rule; 1, with
  "Operation not permitted", means it did not;
- the file's last lines;
- the log's opens of `/private/tmp/esc/f` after the `{"event":"usr1"}`
  line (in 3, in the second log). None, while the appends succeed, means
  they were answered from the cache.

**M4c, the cache across processes** (`m4c.py`, one Python process for
each open). The test file reset as for M4b first, each time. `M` is the
helper:

```
M=~/varek/varek/v1_4/tests/es_probe/m4c.py # end
```

1. Control: the agent's read-write open, under a rule refusing writes
   there, with nothing cached before it (expect EPERM):

   ```
   P --log ~/es-m4c0.jsonl --track-pids --cache --deny-write /private/tmp/esc -- /usr/bin/python3 $M open /private/tmp/esc/f # end
   ```

2. A process outside the tree opens the file read-write while the probe
   runs (allowed, and cached: `--track-pids` caches others' answers), then
   the agent makes the same open, from the same executable, under the
   rule:

   ```
   (sleep 3; /usr/bin/python3 $M open /private/tmp/esc/f) & P --log ~/es-m4c1.jsonl --track-pids --cache --deny-write /private/tmp/esc -- /bin/sh -c "sleep 6; /usr/bin/python3 $M open /private/tmp/esc/f"; wait # end
   ```

   The outside open should print `ok`. If the agent's also prints `ok`,
   and the log has no open of the file, the outside process's cached allow
   answered the agent's open: D6 must never cache another process's
   answer. EPERM, with the open in the log, means the cache did not carry
   it over.

3. One long-lived process: three appends, the rule (SIGUSR1 to the probe,
   its parent), three more, each with its result:

   ```
   P --log ~/es-m4c2.jsonl --track-pids --cache --deny-write /private/tmp/esc --rules-on-usr1 -- /usr/bin/python3 $M loop /private/tmp/esc/f; cat /private/tmp/esc/f # end
   ```

   `ok` after the rule means an allow cached for the process outlived the
   rule.

For each: the lines `m4c.py` printed, the summary line, the file, and the
log's opens of `/private/tmp/esc/f` (in 3, those after `{"event":"usr1"}`).

**The cost of D6 and D10** (every other process's AUTH events answered
by the client, uncached). The agent's own answers are uncached in every
run (no `--cache`). Each workload without the probe first, for its time, as root as the
probe's command is (and `m1`, left by a run as root, removed with sudo):

```
cd /tmp && sudo /usr/bin/time -p /bin/sh -c 'for i in $(seq 1 5000); do /bin/cat /etc/hosts > /dev/null; done' # end
```

```
cd /tmp && sudo rm -rf m1 && sudo /usr/bin/time -p /bin/sh -c 'git clone -q https://github.com/kwdoug63/varek.git m1 && python3 -m compileall -q m1 > /dev/null' # end
```

Then each workload under the probe three ways, `O` set to each in turn:
the others cached (as before), uncached, and uncached with the system's
SIP-protected paths muted:

```
for O in "" "--others-uncached" "--others-uncached --mute-system-targets"; do echo "== others: ${O:-cached}"; P --track-pids $O -- /bin/sh -c 'for i in $(seq 1 5000); do /bin/cat /etc/hosts > /dev/null; done'; done # end
```

```
for O in "" "--others-uncached" "--others-uncached --mute-system-targets"; do echo "== others: ${O:-cached}"; cd /tmp && sudo rm -rf m1 && P --track-pids $O -- /bin/sh -c 'git clone -q https://github.com/kwdoug63/varek.git m1 && python3 -m compileall -q m1 > /dev/null'; done # end
```

And the machine at rest, a minute of `sleep`, for the background load the
client carries:

```
for O in "" "--others-uncached" "--others-uncached --mute-system-targets"; do echo "== others: ${O:-cached}"; P --track-pids $O -- /bin/sleep 60; done # end
```

For each: the summary's three lines (the agent's answers and their times;
the other processes' answers, a second, and their times; the wall time
and the probe's CPU time), and the two `time` lines without the probe.
With `--mute-system-targets` the agent's own events on those paths are not
seen either (the reads of the system's libraries; their writes SIP
refuses): that run is for the cost only.

## 5. Afterwards

- The logs: `tar czf ~/es-probe-logs.tgz ~/es-m*.jsonl`, kept as the Mac
  run's results were (`docs/security/v1.33-mac-runbook.md`, Afterwards).
- Delete the key and the keychain from the Mac (in ec2-user's session, as
  in step 2):
  `security delete-keychain ~/Library/Keychains/varek-signing.keychain-db && rm -P ~/apple-signing/varek-devid.key # end`
- Terminate the instance; release the host after its 24 hours.
