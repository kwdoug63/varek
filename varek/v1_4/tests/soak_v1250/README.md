# The v1.25 soak test

Section 5 of `docs/security/v1.25-wildcard-host-names.md`: before v1.25 ships,
an agent runs for 24 hours against a real API reached through many names
under one suffix, fetching every minute. The run must show:
- no refused connect caused by a stale table;
- every question to the stub recorded;
- no budget hit at the default budgets in normal use.

| File | What it does |
|---|---|
| `soak.sh` | Runs the test: writes the policy (`allow host *.wikipedia.org:443`, default budgets), starts the Warden and the agent, then runs the checker. |
| `soak_agent.py` | The agent: one fetch a minute, the names in turn, each resolved through the Warden's stub. |
| `soak_check.py` | Judges the run and writes `report.txt`. |

**The workload.** The Wikipedia API (`action=query&meta=siteinfo`) of 40
language editions, `https://<lang>.wikipedia.org/...`, one request a minute
in all.
- Wikimedia alone creates names under `wikipedia.org`, so the wildcard is not
  refused as a shared domain.
- Every edition is served from the same addresses, the way per-tenant names
  behind a CDN are. So each connect is decided over many names on one
  address.
- The User-Agent names this project and its repository, as Wikimedia's API
  etiquette asks.

## Running it

All steps are on the droplet, as root. The run uses its own checkout, so it
can go beside the v1.24 soak, which runs from `~/varek`.

1. Check out the v1.25 branch and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git ~/varek125
   cd ~/varek125 && git checkout claude/v1.25-wildcard-host-names
   make -C varek/v1_4 all
   ```

2. Run a 3-minute trial. It must end with `soak_check: PASS`:

   ```
   varek/v1_4/tests/soak_v1250/soak.sh --hours 0.05 --out /var/tmp/varek-soak125-trial
   ```

3. Start the 24-hour run in the background. It keeps running after you
   close SSH:

   ```
   cd ~/varek125 && setsid nohup varek/v1_4/tests/soak_v1250/soak.sh --hours 24 --out /var/tmp/varek-soak125-24h > /var/tmp/soak125.out 2>&1 < /dev/null &
   ```

   Check it with
   `ps -eo pid,etime,args | grep soak_v1250 | grep -v grep; tail -3 /var/tmp/soak125.out`.

4. After 24 hours, read `/var/tmp/varek-soak125-24h/report.txt`.

## What the report says about the defaults

The report also gives:
- the names charged against the budget, and the most charged in any one
  minute;
- the number of lookups on demand and of retirements;
- the most names on one address, and how many connects were recorded with
  hashed candidates.

The defaults (256 names a run, 30 a minute) are set from these figures.

## Trying it without the internet

The harness was run end to end against local test servers, as below. The
run used 20 names on one address with a 2-second interval, and passed.

```
soak.sh --hours 0.02 --interval 2 --suffix many.example.com --port <http port> \
    --template 'http://{name}:<http port>/' --names t0.many.example.com,... \
    --dns-server 127.0.0.1:<dns_test_server port>
```
