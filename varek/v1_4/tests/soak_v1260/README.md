# The v1.26 soak test

Section 6 of `docs/security/v1.26-egress-proxy.md`: before v1.26 ships, an
agent runs for 24 hours against APIs behind Fastly, Cloudflare and
CloudFront with the egress proxy on (SNI mode). The run must show:
- no refused request that the policy allows;
- every request recorded: a decision for each, and a close for each
  connection the proxy relayed;
- the refusals the policy asks for still made: the third fetch, and every
  tenth after it, is a probe
  that connects to an allowed name's address with an SNI no rule allows
  (domain fronting), and each must be refused and recorded.

| File | What it does |
|---|---|
| `soak.sh` | Runs the test: writes the policy, starts the Warden (with its proxy) and the agent, then runs the checker. |
| `soak_agent.py` | The agent: one request a minute, the URLs in turn, every tenth a probe. |
| `soak_check.py` | Judges the run and writes `report.txt`. |

**The workload**, one request a minute in all, each with a small `Range` and
a User-Agent naming this project:

| URL | CDN | Rule |
|---|---|---|
| `https://pypi.org/pypi/sampleproject/json` | Fastly | `pypi.org:443` |
| `https://api.cloudflare.com/client/v4/ips` | Cloudflare | `api.cloudflare.com:443` |
| `https://www.cloudflare.com/cdn-cgi/trace` | Cloudflare | `*.cloudflare.com:443` (a wildcard: looked up on demand, charged to its budget) |
| `http://www.cloudflare.com/cdn-cgi/trace` | Cloudflare | `www.cloudflare.com:80` (plain HTTP: decided on the `Host` header) |
| `https://ip-ranges.amazonaws.com/ip-ranges.json` | CloudFront | `ip-ranges.amazonaws.com:443` |

The probe connects to `pypi.org`'s address with SNI `example.org`.

## Running it

All steps are on the droplet, as root. The run uses its own checkout, so it
can go beside earlier soaks.

1. Check out the v1.26 branch and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git ~/varek126
   cd ~/varek126 && git checkout claude/v1.26-egress-proxy
   make -C varek/v1_4 all
   ```

2. Run a 3-minute trial. It must end with `soak_check: PASS`:

   ```
   varek/v1_4/tests/soak_v1260/soak.sh --hours 0.05 --out /var/tmp/varek-soak126-trial
   ```

3. Start the 24-hour run in the background. It keeps running after you
   close SSH:

   ```
   cd ~/varek126 && setsid nohup varek/v1_4/tests/soak_v1260/soak.sh --hours 24 --out /var/tmp/varek-soak126-24h > /var/tmp/soak126.out 2>&1 < /dev/null &
   ```

   Check it with
   `ps -eo pid,etime,args | grep soak_v1260 | grep -v grep; tail -3 /var/tmp/soak126.out`.

4. After 24 hours, read `/var/tmp/varek-soak126-24h/report.txt`.

To soak through a customer proxy as well (section 5), add
`--upstream http://HOST:PORT`.

## What the report gives

Per name: the Warden's own time on each request (the proxy's report of the
name to the socket passed back: the decision, the certificate, and the dial)
and the agent's time for the whole request. Also the closes by reason and
the bytes relayed, and any failure after the Warden passed a request on
(server errors, timeouts), which may be up to 1% of fetches.

## Trying it without the internet

The harness was run end to end on 2026-10-08 against local servers: the
same five URLs and policy, the names served by `tests/dns_test_server.py`
to a TLS and an HTTP server on this machine's address, with a 2-second
interval (`--hours 0.02 --interval 2 --dns-server 127.0.0.1:<port>
--insecure`). It passed: 33 fetches, all decided and closed, 3 probes, all
refused. A run with a URL the policy does not allow failed, as it must.
