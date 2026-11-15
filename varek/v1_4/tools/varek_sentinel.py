#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_sentinel.py — v1.40 (docs/security/v1.39-security-operations.md, section 3):
Microsoft Sentinel export. Each OCSF 1.9.0 event tools/varek_ocsf.py writes
(one JSON object per line, from an audited verdict stream) is sent as one row
of the custom table VarekOCSF_CL in a Log Analytics workspace (Sentinel's),
through the Azure Monitor Logs Ingestion API and a data collection rule
(integrations/sentinel/azuredeploy.json makes the table and the rule). The
standard library only.

A row carries:
  * TimeGenerated: the decision's time (the OCSF event's), to the millisecond;
  * the decision (ALLOW or DENY), the three-state verdict, the rule, the
    policy line and its text, the policy's name and SHA-256, what the
    decision was about (Target), the dry run's mark (Mode);
  * the OCSF class, activity, action, disposition, status and severity;
  * the run, the record's report id and seq, the agent, the host, the
    process id, the user, the Warden's version, an audit's result;
  * OcsfEvent: the whole OCSF event, so nothing the OCSF export says is
    lost on the way.

Usage:
    varek_sentinel.py [EVENTS | -] --endpoint URL --dcr DCR_IMMUTABLE_ID
                      [--stream Custom-VarekOCSF] [--auth client-secret|managed-identity|token]
                      [--tenant ID] [--client-id ID] [--secret-env ENVVAR] [--token-env ENVVAR]
                      [--authority URL] [--ca FILE]
                      [--batch N] [--interval SECONDS] [--timeout SECONDS] [--retries N]
        EVENTS: a file of OCSF events, or - (the default) for standard input,
        read as it arrives (a pipe from varek_ocsf.py --follow sends each
        event within --interval seconds of its being written).
        --endpoint: the data collection rule's logs ingestion endpoint (or a
        data collection endpoint's), https://NAME.REGION-1.ingest.monitor.azure.com.
        Default: the environment's AZURE_LOGS_INGESTION_ENDPOINT.
        --dcr: the data collection rule's immutable id (dcr-...). Default:
        AZURE_DCR_IMMUTABLE_ID.
        --auth: how the token for https://monitor.azure.com is had:
          client-secret (the default): Microsoft Entra ID's client
            credentials, the tenant and the client from --tenant and
            --client-id (default AZURE_TENANT_ID, AZURE_CLIENT_ID), the
            secret from the environment variable --secret-env names
            (default AZURE_CLIENT_SECRET): never from a command line;
          managed-identity: the Azure VM's identity (its instance metadata
            service; --client-id names a user-assigned one);
          token: a token already had, from the variable --token-env names
            (default AZURE_MONITOR_TOKEN).
        --authority: Entra ID's host (default AZURE_AUTHORITY_HOST, else
        https://login.microsoftonline.com).
        --ca: certificate authorities to trust, if not the system's (the
        names are always checked).
    A batch refused for a reason a retry can mend (429, 500, 502, 503, 504,
    or no answer) is sent again, --retries times at most, waiting longer
    each time (or as Retry-After says); a batch too large (413) is split; a
    401 gets a new token once; any other refusal ends the export with exit 1.

Exit status: 0 every event sent and accepted (204); 1 an event not accepted;
2 the input is not OCSF events, or the arguments are wrong.
"""
import argparse
import datetime
import gzip
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_otel import _get, _object, lines_of  # noqa: E402  (the same reading and the same object)

API_VERSION = "2023-01-01"
STREAM = "Custom-VarekOCSF"
SCOPE = "https://monitor.azure.com//.default"       # as Azure's own Logs Ingestion client asks
IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"
AUTHORITY = "https://login.microsoftonline.com"
RETRY_STATUS = (429, 500, 502, 503, 504)
MAX_BODY = 900_000              # the API takes 1 MB a call; uncompressed, with room


class SentinelError(Exception):
    pass


# ---------------------------------------------------------------- mapping --

def _iso(ms):
    return (datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def row(ev):
    """One OCSF event -> one row of VarekOCSF_CL"""
    if not isinstance(ev, dict) or "class_uid" not in ev:
        raise SentinelError("not an OCSF event (no class_uid)")
    v = _get(ev, "unmapped", "varek") or {}
    pol = ev.get("policy") if isinstance(ev.get("policy"), dict) else {}
    agent = ev.get("ai_agent") if isinstance(ev.get("ai_agent"), dict) else {}
    dev = ev.get("device") if isinstance(ev.get("device"), dict) else {}
    t = ev.get("time")
    line = v.get("policy_line")
    r = {
        "TimeGenerated": _iso(t) if isinstance(t, (int, float)) and t > 0 else _iso(time.time() * 1000),
        "EventName": "varek." + str(v.get("event") or ("decision" if "action_id" in ev else "event")),
        "Decision": v.get("decision_final"), "Verdict": v.get("decision"), "Rule": v.get("rule"),
        "PolicyLine": line if isinstance(line, int) and line > 0 else None,
        "PolicyText": pol.get("desc"), "PolicyName": pol.get("name"), "PolicySha256": pol.get("uid"),
        "Mode": v.get("mode"), "Target": _object(ev) or None,
        "ClassUid": ev.get("class_uid"), "ClassName": ev.get("class_name"),
        "ActivityName": ev.get("activity_name"), "Action": ev.get("action"),
        "Disposition": ev.get("disposition"), "Status": ev.get("status"),
        "SeverityId": ev.get("severity_id"), "Severity": ev.get("severity"),
        "RunId": _get(ev, "metadata", "correlation_uid"), "ReportId": v.get("report_id"),
        "Seq": v.get("seq"), "Agent": agent.get("name"), "AgentType": agent.get("type"),
        "Computer": dev.get("hostname") or dev.get("name"),
        "ProcessId": _get(ev, "actor", "process", "pid") or None,
        "UserId": _get(ev, "actor", "user", "uid"),
        "WardenVersion": _get(ev, "metadata", "product", "version"),
        "AuditPassed": bool(_get(v, "audit", "passed")) if v.get("event") == "audit" else None,
        "OcsfEvent": ev,
    }
    return {k: x for k, x in r.items() if x is not None and x != ""}


def batches(rows, limit=MAX_BODY):
    """rows -> lists whose JSON array stays under `limit` bytes"""
    out, size = [], 2
    for r in rows:
        n = len(json.dumps(r, separators=(",", ":"))) + 1
        if out and size + n > limit:
            yield out
            out, size = [], 2
        out.append(r)
        size += n
    if out:
        yield out


# ---------------------------------------------------------------- sending --

def ingestion_url(endpoint, dcr, stream):
    if not endpoint:
        raise SentinelError("no logs ingestion endpoint: give --endpoint, or set AZURE_LOGS_INGESTION_ENDPOINT")
    if not dcr:
        raise SentinelError("no data collection rule: give --dcr, or set AZURE_DCR_IMMUTABLE_ID")
    p = urllib.parse.urlsplit(endpoint)
    if p.scheme != "https" and p.hostname not in ("127.0.0.1", "localhost"):
        raise SentinelError(f"{endpoint}: not an https URL")
    return (endpoint.rstrip("/") + "/dataCollectionRules/" + urllib.parse.quote(dcr, safe="")
            + "/streams/" + urllib.parse.quote(stream, safe="") + "?api-version=" + API_VERSION)


class Token:
    """a bearer token for https://monitor.azure.com, had again before it expires"""

    def __init__(self, auth, env, tenant=None, client_id=None, secret_env="AZURE_CLIENT_SECRET",
                 token_env="AZURE_MONITOR_TOKEN", authority=None, ctx=None, timeout=10.0):
        self.auth, self.env, self.ctx, self.timeout = auth, env, ctx, timeout
        self.tenant = tenant or env.get("AZURE_TENANT_ID")
        self.client_id = client_id or env.get("AZURE_CLIENT_ID")
        self.secret_env, self.token_env = secret_env, token_env
        self.authority = (authority or env.get("AZURE_AUTHORITY_HOST") or AUTHORITY).rstrip("/")
        self.value, self.expires = None, 0.0
        if auth == "client-secret":
            if not self.tenant or not self.client_id:
                raise SentinelError("--auth client-secret: give --tenant and --client-id "
                                    "(or set AZURE_TENANT_ID and AZURE_CLIENT_ID)")
            if not env.get(secret_env):
                raise SentinelError(f"--auth client-secret: the environment variable {secret_env} "
                                    "(the client's secret) is not set")
        elif auth == "token":
            if not env.get(token_env):
                raise SentinelError(f"--auth token: the environment variable {token_env} is not set")
        elif auth != "managed-identity":
            raise SentinelError(f"--auth {auth}: client-secret, managed-identity or token")

    def get(self, fresh=False):
        if self.auth == "token":
            return self.env[self.token_env]
        if self.value and not fresh and time.time() < self.expires - 300:
            return self.value
        if self.auth == "client-secret":
            url = f"{self.authority}/{urllib.parse.quote(self.tenant, safe='')}/oauth2/v2.0/token"
            data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                           "client_secret": self.env[self.secret_env],
                                           "scope": SCOPE}).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            q = {"api-version": "2018-02-01", "resource": "https://monitor.azure.com"}
            if self.client_id:
                q["client_id"] = self.client_id
            url = self.env.get("VAREK_AZURE_IMDS") or IMDS          # tests: a stand-in
            req = urllib.request.Request(url + "?" + urllib.parse.urlencode(q), headers={"Metadata": "true"})
        try:
            ctx = self.ctx if url.startswith("https:") else None
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if url.startswith(IMDS) else None
            with (opener.open(req, timeout=self.timeout) if opener else
                  urllib.request.urlopen(req, timeout=self.timeout, context=ctx)) as r:
                ans = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            try:
                why = json.loads(body).get("error_description") or json.loads(body).get("error") or body
            except ValueError:
                why = body
            raise SentinelError(f"no token from {url.split('?')[0]}: HTTP {e.code} {str(why)[:300]}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SentinelError(f"no token from {url.split('?')[0]}: {getattr(e, 'reason', e)}")
        if not ans.get("access_token"):
            raise SentinelError("the token answer has no access_token")
        self.value = ans["access_token"]
        self.expires = time.time() + float(ans.get("expires_in") or 3600)
        return self.value


class Ingestion:
    """the Logs Ingestion API: POSTs a batch of rows, gzipped, with retries"""

    def __init__(self, url, token, ctx=None, timeout=10.0, retries=5, sleep=time.sleep):
        self.url, self.token, self.ctx = url, token, ctx
        self.timeout, self.retries, self.sleep = timeout, retries, sleep
        self.requests = 0

    def send(self, rows):
        """send rows; a 413 splits them in two"""
        delay, renewed = 1.0, False
        body = gzip.compress(json.dumps(rows, separators=(",", ":")).encode())
        attempt = 0
        while True:
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Authorization": "Bearer " + self.token.get(), "Content-Type": "application/json",
                "Content-Encoding": "gzip", "User-Agent": "varek-sentinel"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                    r.read()
                self.requests += 1
                return
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                self.requests += 1
                if e.code == 413 and len(rows) > 1:
                    half = len(rows) // 2
                    self.send(rows[:half])
                    self.send(rows[half:])
                    return
                if e.code == 401 and not renewed and self.token.auth != "token":
                    self.token.get(fresh=True)
                    renewed = True
                    continue
                if e.code not in RETRY_STATUS or attempt >= self.retries:
                    raise SentinelError(_refusal(e.code, text, len(rows)))
                ra = e.headers.get("Retry-After") if e.headers else None
                wait = float(ra) if ra and ra.isdigit() else delay
            except (urllib.error.URLError, OSError) as e:
                reason = getattr(e, "reason", e)
                if isinstance(reason, ssl.SSLError) or attempt >= self.retries:
                    raise SentinelError(f"no answer from {self.url.split('?')[0]}: {reason}")
                wait = delay
            attempt += 1
            self.sleep(min(wait, 30.0))
            delay = min(delay * 2, 30.0)


def _refusal(code, text, n):
    msg = f"the Logs Ingestion API refused a batch of {n} row(s): HTTP {code}"
    try:
        err = json.loads(text).get("error") or {}
        if isinstance(err, dict):
            msg += f" ({err.get('code')}: {err.get('message')})"
    except (ValueError, AttributeError):
        if text.strip():
            msg += " " + text.strip()[:300]
    return msg


# ------------------------------------------------------------------- main --

def main(argv=None, env=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(prog="varek_sentinel.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("events", nargs="?", default="-", help="OCSF events (a file, or - for standard input)")
    ap.add_argument("--endpoint", help="the logs ingestion endpoint (default: AZURE_LOGS_INGESTION_ENDPOINT)")
    ap.add_argument("--dcr", help="the data collection rule's immutable id (default: AZURE_DCR_IMMUTABLE_ID)")
    ap.add_argument("--stream", default=STREAM, help=f"the rule's stream (default {STREAM})")
    ap.add_argument("--auth", default="client-secret", choices=("client-secret", "managed-identity", "token"))
    ap.add_argument("--tenant", help="the Entra ID tenant (default: AZURE_TENANT_ID)")
    ap.add_argument("--client-id", help="the application's client id (default: AZURE_CLIENT_ID)")
    ap.add_argument("--secret-env", default="AZURE_CLIENT_SECRET", metavar="ENVVAR")
    ap.add_argument("--token-env", default="AZURE_MONITOR_TOKEN", metavar="ENVVAR")
    ap.add_argument("--authority", help="Entra ID's host (default: AZURE_AUTHORITY_HOST, else login.microsoftonline.com)")
    ap.add_argument("--ca", help="certificate authorities to trust, if not the system's")
    ap.add_argument("--batch", type=int, default=500, help="rows in one request at most (default 500)")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds an event waits at most (default 1)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=5)
    a = ap.parse_args(argv)
    try:
        url = ingestion_url(a.endpoint or env.get("AZURE_LOGS_INGESTION_ENDPOINT"),
                            a.dcr or env.get("AZURE_DCR_IMMUTABLE_ID"), a.stream)
        if a.ca and not os.path.isfile(a.ca):
            raise SentinelError(f"--ca {a.ca}: no such file")
        ctx = ssl.create_default_context(cafile=a.ca)
        token = Token(a.auth, env, a.tenant, a.client_id, a.secret_env, a.token_env, a.authority, ctx, a.timeout)
        api = Ingestion(url, token, ctx if url.startswith("https:") else None, a.timeout, a.retries)
    except (SentinelError, ssl.SSLError) as e:
        print(f"varek_sentinel: {e}", file=sys.stderr)
        return 2
    fh = sys.stdin if a.events == "-" else open(a.events, "rb")
    pending, sent, last, n = [], 0, time.monotonic(), 0

    def flush():
        nonlocal pending, sent, last
        for b in batches(pending):
            api.send(b)
            sent += len(b)
        pending = []
        last = time.monotonic()

    try:
        token.get()               # a refusal of the credentials before anything is read
        for line in lines_of(fh, a.interval):
            if line is not None and line.strip():
                n += 1
                try:
                    pending.append(row(json.loads(line)))
                except ValueError:
                    print(f"varek_sentinel: line {n} is not JSON", file=sys.stderr)
                    return 2
                except SentinelError as e:
                    print(f"varek_sentinel: line {n}: {e}", file=sys.stderr)
                    return 2
            if len(pending) >= a.batch or (pending and time.monotonic() - last >= a.interval):
                flush()
        flush()
    except SentinelError as e:
        print(f"varek_sentinel: {e} ({sent} rows sent before)", file=sys.stderr)
        return 1
    print(f"varek_sentinel: {sent} rows sent to {url.split('?')[0]} in {api.requests} request(s)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
