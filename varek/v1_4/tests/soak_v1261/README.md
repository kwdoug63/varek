# The v1.26.1 soak test

Section 6 of `docs/security/v1.26.1-inspecting-mode.md`: the v1.26.0 soak
(`tests/soak_v1260`) again, with the egress proxy in inspecting mode. An agent
runs for 24 hours against APIs behind Fastly, Cloudflare and CloudFront. The
proxy verifies each server, terminates the agent's TLS with the run's CA, and
the Warden decides each request on its method, path and query. The run must
show:
- no refused request that the policy allows;
- every request recorded: the connection's decision, the request's decision
  (certified), and a close for each connection counting its requests;
- the refusals the policy asks for still made: the third fetch, and every
  tenth after it, is a probe, five kinds in turn, each of which must be
  refused and recorded.

| File | What it does |
|---|---|
| `soak.sh` | Runs the test: writes the policy, starts the Warden (with its proxy) and the agent, then runs the checker. |
| `soak_agent.py` | The agent: one request a minute, the URLs in turn, every tenth a probe. It verifies servers with the default trust store, which under the Warden includes the run's CA. |
| `soak_check.py` | Judges the run and writes `report.txt`. |

**The workload** is v1.26.0's, one request a minute, each with a small `Range`
and a User-Agent naming this project, now each with a request rule:

| URL | CDN | Host rule | Request rule |
|---|---|---|---|
| `https://pypi.org/pypi/sampleproject/json` | Fastly | `pypi.org:443` | `GET https://pypi.org/pypi/sampleproject/json` |
| `https://api.cloudflare.com/client/v4/ips` | Cloudflare | `api.cloudflare.com:443` | `GET https://api.cloudflare.com/client/v4/ips` |
| `https://www.cloudflare.com/cdn-cgi/trace` | Cloudflare | `*.cloudflare.com:443` | `GET https://*.cloudflare.com/cdn-cgi/trace` (a wildcard) |
| `http://www.cloudflare.com/cdn-cgi/trace` | Cloudflare | `www.cloudflare.com:80` | `GET http://www.cloudflare.com/cdn-cgi/trace` (plain HTTP) |
| `https://ip-ranges.amazonaws.com/ip-ranges.json` | CloudFront | `ip-ranges.amazonaws.com:443` | `GET https://ip-ranges.amazonaws.com/ip-ranges.json` |

The policy also has `deny request * https://pypi.org/simple/**`.

**The probes**, in turn, all to `pypi.org`:

| Probe | What it sends | Must be |
|---|---|---|
| `sni` | TLS with SNI `example.org` (domain fronting by SNI) | refused on the name (`net.proxy` DENY) |
| `host` | an allowed request with `Host: example.org` (domain fronting by Host) | refused by the proxy's parser: 403, close `refused_request`, nothing decided |
| `path` | `/pypi/./sampleproject/json`, the allowed path written another way | refused by the proxy's parser, the same |
| `denied` | `/simple/pip/` | refused by the deny rule (`net.request` `policy_match`), 403 |
| `unlisted` | `/pypi/pip/json` | refused, no rule allows it (`default_deny_unknown`), 403 |

## Running it

All steps are on the droplet, as root. The run uses its own checkout, so it
can go beside the v1.26.0 soak (`~/varek126`) while that one finishes.

1. Check out the branch and build it:

   ```
   git clone https://github.com/kwdoug63/varek.git ~/varek1261
   cd ~/varek1261 && git checkout claude/v1.26-egress-proxy
   make -C varek/v1_4 all
   ```

   The build needs OpenSSL's headers (`apt-get install -y libssl-dev`);
   `make -C varek/v1_4 deps-check-ssl` says if they are missing.

2. Run a 3-minute trial. It must end with `soak_check: PASS`:

   ```
   varek/v1_4/tests/soak_v1261/soak.sh --hours 0.05 --out /var/tmp/varek-soak1261-trial
   ```

3. Start the 24-hour run in the background. It keeps running after you
   close SSH:

   ```
   cd ~/varek1261 && setsid nohup varek/v1_4/tests/soak_v1261/soak.sh --hours 24 --out /var/tmp/varek-soak1261-24h > /var/tmp/soak1261.out 2>&1 < /dev/null &
   ```

   Check it with
   `ps -eo pid,etime,args | grep soak_v1261 | grep -v grep; tail -3 /var/tmp/soak1261.out`.

4. After 24 hours, read `/var/tmp/varek-soak1261-24h/report.txt`.

To soak through a customer proxy as well, add `--upstream http://HOST:PORT`.
A host whose outbound HTTPS passes through its own inspecting proxy needs
that proxy's CA: add `--trust-bundle PEM` (the host's bundle plus that CA).

## What the report gives

Per name: the Warden's own time on each connection (decided and dialed) and
on each request (decided and certified), and the agent's time for the whole
fetch. Also the probes by kind, the closes by reason with the requests they
count, and any failure after the Warden allowed a request (server errors,
timeouts), which may be up to 1% of fetches.

## Trying it without the internet

The harness was run end to end on 2026-10-08 against local servers: the
same five URLs, policy and probes, the names served by
`tests/dns_test_server.py` to TLS and HTTP servers on this machine's
address (`tests/v1261_echo_server.py`, with one certificate for the four
names, given to the proxy with `--trust-bundle`), with a 2-second interval
(`--hours 0.02 --interval 2 --dns-server 127.0.0.1:<port> --trust-bundle
<pem>`). It passed: 32 fetches, all allowed, decided, certified and closed
with their counts; 4 probes (sni, host, path, denied), all refused; the
audit passed. The fetches took about 50 ms there: the test server answers
in two small writes, and the same fetch made natively, without the Warden,
takes as long.
