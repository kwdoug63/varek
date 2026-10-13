# The v1.28 soak test

Step 7 of `docs/security/v1.28-credential-release.md`: credential release for
24 hours. An agent under the Warden (the egress proxy in inspecting mode)
holds only placeholders for four credentials, and once a minute calls an API
with one of them in turn. Near the end the run is revoked with `varek
revoke`. Everything it talks to runs on the same host, so every swap can be
checked where it arrives:

| Credential | Store (a local stand-in, `tests/v1280_stores.py`) | Sent as |
|---|---|---|
| `api` | a file, `/etc/varek-soak1280/api.key` (root's, 0600) | `GET /v1/a`, `Authorization: Bearer` |
| `db` | a Vault lease of 60 s, renewed by `warden-secrets` every 40 s | `GET /v1/b`, `X-Api-Key` |
| `st` | AWS Secrets Manager (each request's SigV4 signature checked) | `POST /v1/c`, `X-Token`, with a body |
| `gh` | Vault KV version 2 | `GET /v1/d`, `Authorization: token` |

The API (`soak_api.py`) answers 200 only when the header holds exactly the
value, and logs whether it did (never the value).

**The probes**, every tenth turn, in turn:

| Probe | What the agent does | Must be |
|---|---|---|
| `missing` | `/v1/a` without its header | refused by the proxy, 403, a `credential_refused` record |
| `other` | `/v1/a` with the `db` credential's placeholder | refused, 403, `credential_refused` |
| `elsewhere` | `/v1/plain?q=<placeholder>`, where no rule names a credential | sent as it is: the API sees the placeholder and no value |
| `read` | opens the file store | EACCES |

**The run must show** (`soak_check.py`, written to `report.txt`): every call
before the revocation succeeded, with the value where its rule names it and
nowhere else; every probe held; the lease renewed all run long, none
failing; the revocation recorded once by root, the proxy holding no value
after it, the lease revoked at the stand-in, every turn after it refused and
none reaching the API; no value in the verdict stream, the agent's output or
the API's log; and the audit passing. It also reports the time per call,
the Warden's time to decide a request with a credential, and each process's
memory over the run (`rss.tsv`).

| File | What it does |
|---|---|
| `soak.sh` | Runs the test: the stand-ins, the API, a DNS stand-in, the policy, the Warden and the agent; the revocation; then the checker. |
| `soak_agent.py` | The agent: one call a minute, every tenth turn a probe. |
| `soak_api.py` | The API: checks each value where it arrives. |
| `soak_check.py` | Judges the run and writes `report.txt`. |

## Running it

On the droplet, as root.

1. Install what the stand-ins need (Python's `cryptography`) and check
   OpenSSL is there:

   ```
   apt-get install -y python3-cryptography openssl
   ```

2. Check out the branch and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git ~/varek128
   cd ~/varek128 && git checkout claude/varek-roadmap-landing-01dbw5
   make -C varek/v1_4 all
   ```

3. A 6-minute trial (a call every 3 s; it must end `soak_check: PASS`):

   ```
   varek/v1_4/tests/soak_v1280/soak.sh --hours 0.1 --interval 3 --out /var/tmp/varek-soak1280-trial
   ```

4. The 24-hour run, detached from the terminal:

   ```
   cd ~/varek128 && setsid nohup varek/v1_4/tests/soak_v1280/soak.sh --hours 24 --out /var/tmp/varek-soak1280-24h > /var/tmp/soak1280.out 2>&1 < /dev/null &
   ```

5. Its progress, and at the end its result:

   ```
   ps -eo pid,etime,args | grep soak_v1280 | grep -v grep; wc -l /var/tmp/varek-soak1280-24h/agent.jsonl
   tail -30 /var/tmp/soak1280.out
   ```

The stores' secrets are in `/etc/varek-soak1280/` (test values, not real
secrets), and the agent's script is installed to `/opt/varek-soak1280-agent`.
