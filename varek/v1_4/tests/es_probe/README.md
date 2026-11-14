# es_probe: the Endpoint Security measurements, on an EC2 Mac

The measurements M1 to M4 and M6 of
`docs/security/macos-endpoint-security.md`, made with `es_probe`, a
minimal Endpoint Security client: it supervises one command and its
children, answers each AUTH event from a fixed rule, and records each
answer's time against its deadline, one JSON line each. Not built in CI
(it needs the macOS SDK); built, signed and run on an EC2 Mac. Untested
until that run: the first build may need fixing there.

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

```
~/varek/varek/v1_4/tests/es_probe/keychain.sh ~/apple-signing/varek-devid.key ~/apple-signing/CERT.cer # end
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

**M2, children.** Opens by a child and a grandchild in the background:

```
P --log ~/es-m2.jsonl -- /bin/sh -c '/bin/cat /etc/hosts > /dev/null; (/bin/cat /etc/hosts > /dev/null &); /bin/sh -c "/bin/cat /etc/hosts > /dev/null"; wait' # end
```

Every `cat`'s open of `/etc/hosts` should be in the log, three of them.

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
then the same with `--deny-write /etc` added, to see whether a cached
allow outlives a new client's rule.

## 5. Afterwards

- The logs: `tar czf ~/es-probe-logs.tgz ~/es-m*.jsonl`, kept as the Mac
  run's results were (`docs/security/v1.33-mac-runbook.md`, Afterwards).
- Delete the key and the keychain from the Mac:
  `security delete-keychain varek-signing.keychain && rm -P ~/apple-signing/varek-devid.key # end`
- Terminate the instance; release the host after its 24 hours.
