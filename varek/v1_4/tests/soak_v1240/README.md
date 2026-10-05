# v1.24 soak test: 24 hours against CDN-hosted APIs

This is the last ship gate for v1.24.0 (section 5 of
`docs/security/v1.21-stage2-host-names.md`). An agent runs under the Warden and
fetches three real APIs by name every minute, one each on Fastly, Cloudflare
and CloudFront. The run passes when all of these hold:

- No connect was refused because the table was stale.
- Every refresh was recorded.
- Every address the agent reached appears in the resolution records.
- Each URL really was served by its content network.
- `varek_audit.py` passes.

| File | What it is |
|---|---|
| `soak.sh` | Runs the test. It writes the policy, starts the Warden and the agent, then runs the checker. |
| `soak_agent.py` | The agent. It uses only Python's standard library and resolves through the Warden's hosts view. |
| `soak_check.py` | The checker. It writes `report.txt`, and you can run it again on a finished run. |

## Running it (on the droplet, as root)

The droplet needs Linux 5.14 or later (as for any Warden run), outbound HTTPS, and `build-essential`,
`libseccomp-dev`, `libsodium-dev` and `python3`.

1. **On the droplet**, get the code and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git && cd varek
   make -C varek/v1_4 all
   ```

2. **On the droplet**, run a three-minute trial. It confirms that each URL
   answers and shows the expected network's headers:

   ```
   sudo varek/v1_4/tests/soak_v1240/soak.sh --hours 0.05
   ```

   The report should end in `soak_check: PASS`. If a URL fails with "does not
   test fastly" (or cloudflare, cloudfront), swap it for another URL on that
   network with `--url https://host/path=fastly`.

3. **On the droplet**, start the 24-hour run inside tmux, so it survives a
   disconnected SSH session:

   ```
   tmux new -s soak
   sudo varek/v1_4/tests/soak_v1240/soak.sh --hours 24 --out /var/tmp/varek-soak-24h
   ```

   Detach with `Ctrl-b d`, and reattach later with `tmux attach -t soak`. To
   also sign the stream, add `--sign-key /path/log.key` (a key from
   `varek/v1_4/tools/varek_keygen`). The checker then verifies the signatures
   against `log.key.pub`.

4. **After 24 hours, on the droplet**, read `/var/tmp/varek-soak-24h/report.txt`.
   Copy `report.txt`, `policy.txt`, `verdicts.log` and `agent.jsonl` off the
   droplet. The release notes quote `report.txt`, and the other three let
   anyone re-run the checker.

## Reading the report

- **`refused connects to the soak ports`** must be 0. A refused connect means
  the agent connected to an address the table no longer held. That is a stale
  table, and the run fails.
- **`failures outside the Warden`** counts timeouts and server errors from the
  APIs themselves. Up to 1% of fetches may fail this way. More than that means
  the network was bad, so run the test again.
- **`N answer changes`** for each name shows how often the content network
  rotated its addresses. **`N fetch(es) used an address in its grace period`**
  shows the grace period at work.
- **`worst lateness`** is the longest a refresh came after its TTL. A gap of
  more than the TTL plus 30 s fails the run.
