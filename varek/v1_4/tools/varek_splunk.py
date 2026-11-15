#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_splunk.py — v1.39 (docs/security/v1.39-security-operations.md, section 2):
Splunk export. Each OCSF 1.9.0 event tools/varek_ocsf.py writes (one JSON
object per line, from an audited verdict stream) is sent to a Splunk HTTP
Event Collector (HEC) as one event, sourcetype varek:ocsf, the whole OCSF
event as its body (the standard library only).

An HEC event carries:
  * time: the decision's (the OCSF event's, in seconds, to the millisecond);
  * host: the machine the run was on; source: varek-warden;
    sourcetype: varek:ocsf; index: --index, else the token's default;
  * event: the OCSF event, as read, so nothing the OCSF export says is lost
    (the Splunk app, integrations/splunk/varek, names its fields: the
    decision, the verdict, the policy line and its text, the run, ...);
  * fields, indexed: varek_run, varek_decision, ocsf_class_uid, for
    searches that do not read every event (tstats).

Usage:
    varek_splunk.py [EVENTS | -] [--hec URL] [--token-env ENVVAR] [--index NAME]
                    [--ca FILE] [--ack] [--ack-timeout SECONDS]
                    [--batch N] [--interval SECONDS] [--timeout SECONDS] [--retries N]
        EVENTS: a file of OCSF events, or - (the default) for standard input,
        read as it arrives (a pipe from varek_ocsf.py --follow sends each
        event within --interval seconds of its being written).
        --hec: the HEC's URL, https://HOST:8088 (its event endpoint,
        /services/collector/event, is added to a URL without a path).
        Default: the environment's SPLUNK_HEC_URL.
        --token-env: the environment variable holding the HEC token
        (default SPLUNK_HEC_TOKEN): a token is never taken from a command
        line, where ps and the shell's history show it.
        --ca: the certificate authorities to trust for the HEC's TLS
        certificate (default: the system's). Its name is checked against
        the URL's host; there is no option to skip the check.
        --ack: wait for Splunk's indexer acknowledgement of every batch (the
        token must have it on): a 200 from the HEC says it was received; an
        acknowledgement says it was indexed. A batch not acknowledged within
        --ack-timeout seconds (default 120) ends the export with exit 1.
    A batch the HEC refuses for a reason a retry can mend (429, 502, 503 --
    the HEC's "server is busy" --, 504, or no answer) is sent again,
    --retries times at most, waiting longer each time (or as Retry-After
    says); any other refusal ends the export with exit 1, naming the first
    event the HEC did not take (those before it were taken).

Exit status: 0 every event sent (and, with --ack, indexed); 1 an event not
taken; 2 the input is not OCSF events, or the arguments are wrong.
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_otel import lines_of  # noqa: E402  (the same reading of a pipe as it arrives)

SOURCE = "varek-warden"
SOURCETYPE = "varek:ocsf"
EVENT_PATH = "/services/collector/event"
ACK_PATH = "/services/collector/ack"
RETRY_STATUS = (429, 502, 503, 504)


class SplunkError(Exception):
    pass


def _get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def hec_event(ev, index=None):
    """One OCSF event -> one HEC event (a dict, sent as JSON)"""
    if not isinstance(ev, dict) or "class_uid" not in ev:
        raise SplunkError("not an OCSF event (no class_uid)")
    t = ev.get("time")
    v = _get(ev, "unmapped", "varek") or {}
    dev = ev.get("device") if isinstance(ev.get("device"), dict) else {}
    out = {"time": round(t / 1000.0, 3) if isinstance(t, (int, float)) and t > 0 else None,
           "host": dev.get("hostname") or dev.get("name"),
           "source": SOURCE, "sourcetype": SOURCETYPE, "index": index,
           "event": ev}
    fields = {"varek_run": _get(ev, "metadata", "correlation_uid"),
              "varek_decision": v.get("decision_final"),
              "ocsf_class_uid": str(ev["class_uid"])}
    fields = {k: x for k, x in fields.items() if x not in (None, "")}
    if fields:
        out["fields"] = fields
    return {k: x for k, x in out.items() if x is not None}


def body_of(events):
    """the HEC's batch form: the events' JSON objects, one after another"""
    return "\n".join(json.dumps(e, separators=(",", ":"), sort_keys=True) for e in events).encode()


def endpoint_of(url):
    """the event endpoint: /services/collector/event added to a URL without a path"""
    if not url:
        raise SplunkError("no HEC URL: give --hec, or set SPLUNK_HEC_URL")
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise SplunkError(f"{url}: not an http or https URL")
    path = p.path.rstrip("/") or EVENT_PATH
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, "", ""))


def ack_endpoint_of(event_url):
    p = urllib.parse.urlsplit(event_url)
    path = p.path[:-len("/event")] + "/ack" if p.path.endswith("/event") else ACK_PATH
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, "", ""))


class Hec:
    """an HEC: its URL, token and TLS trust; POSTs with retries"""

    def __init__(self, url, token, ca=None, timeout=10.0, retries=5, channel=None, sleep=time.sleep):
        self.url, self.ack_url = url, ack_endpoint_of(url)
        self.headers = {"Authorization": "Splunk " + token, "Content-Type": "application/json",
                        "User-Agent": "varek-splunk"}
        if channel:
            self.headers["X-Splunk-Request-Channel"] = channel
        self.ctx = ssl.create_default_context(cafile=ca) if url.startswith("https:") else None
        self.timeout, self.retries, self.sleep = timeout, retries, sleep

    def post(self, url, data):
        """POST; the HEC's JSON answer; retried on 429, 502, 503, 504 and on no answer"""
        delay = 1.0
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data, headers=self.headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                    text = r.read().decode("utf-8", "replace")
                try:
                    return json.loads(text) if text.strip() else {}
                except ValueError:
                    raise SplunkError(f"the HEC's answer is not JSON: {text[:200]}")
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code not in RETRY_STATUS or attempt == self.retries:
                    raise SplunkError(_refusal(e.code, text))
                ra = e.headers.get("Retry-After") if e.headers else None
                wait = float(ra) if ra and ra.isdigit() else delay
            except (urllib.error.URLError, OSError) as e:
                reason = getattr(e, "reason", e)
                if isinstance(reason, ssl.SSLError) or attempt == self.retries:
                    raise SplunkError(f"no answer from {url}: {reason}")
                wait = delay
            self.sleep(min(wait, 30.0))
            delay = min(delay * 2, 30.0)
        raise SplunkError("not sent")      # not reached

    def send(self, events):
        """send one batch; its ackId, if the token acknowledges"""
        ans = self.post(self.url, body_of(events))
        if ans.get("code", 0) != 0:
            raise SplunkError(_refusal(200, json.dumps(ans)))
        return ans.get("ackId")

    def acked(self, ids):
        """which of the ackIds Splunk has indexed"""
        ans = self.post(self.ack_url, json.dumps({"acks": sorted(ids)}).encode())
        return {int(k) for k, v in (ans.get("acks") or {}).items() if v is True}


def _refusal(code, text):
    try:
        ans = json.loads(text)
    except ValueError:
        ans = {}
    msg = f"the HEC refused the batch: HTTP {code}"
    if isinstance(ans, dict) and ans:
        msg += f" (code {ans.get('code')}: {ans.get('text')})"
        if "invalid-event-number" in ans:
            msg += f"; the batch's events before number {ans['invalid-event-number']} were taken"
    elif text.strip():
        msg += f" {text.strip()[:200]}"
    return msg


def main(argv=None, env=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(prog="varek_splunk.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("events", nargs="?", default="-", help="OCSF events (a file, or - for standard input)")
    ap.add_argument("--hec", help="the HEC's URL (default: SPLUNK_HEC_URL)")
    ap.add_argument("--token-env", default="SPLUNK_HEC_TOKEN", metavar="ENVVAR",
                    help="the environment variable holding the HEC token (default SPLUNK_HEC_TOKEN)")
    ap.add_argument("--index", help="the index (default: the token's)")
    ap.add_argument("--ca", help="certificate authorities to trust for the HEC's certificate")
    ap.add_argument("--ack", action="store_true", help="wait for indexer acknowledgement of every batch")
    ap.add_argument("--ack-timeout", type=float, default=120.0)
    ap.add_argument("--batch", type=int, default=256, help="events in one request at most (default 256)")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds an event waits at most (default 1)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=5)
    a = ap.parse_args(argv)
    try:
        url = endpoint_of(a.hec or env.get("SPLUNK_HEC_URL"))
        token = env.get(a.token_env)
        if not token:
            raise SplunkError(f"the environment variable {a.token_env} (the HEC token) is not set")
        if a.ca and not os.path.isfile(a.ca):
            raise SplunkError(f"--ca {a.ca}: no such file")
        hec = Hec(url, token, a.ca, a.timeout, a.retries, str(uuid.uuid4()) if a.ack else None)
    except (SplunkError, ssl.SSLError) as e:
        print(f"varek_splunk: {e}", file=sys.stderr)
        return 2
    fh = sys.stdin if a.events == "-" else open(a.events, "rb")
    pending, sent, requests, last = [], 0, 0, time.monotonic()
    waiting = {}                     # ackId -> (events, when sent)
    indexed = 0

    def flush():
        nonlocal pending, sent, requests, last
        if pending:
            ack_id = hec.send(pending)
            requests += 1
            if a.ack:
                if ack_id is None:
                    raise SplunkError("--ack: the HEC gave no ackId (the token's indexer acknowledgement is off)")
                waiting[int(ack_id)] = (len(pending), time.monotonic())
            sent += len(pending)
            pending = []
        last = time.monotonic()

    def check_acks(final=False):
        nonlocal indexed
        while waiting:
            for i in hec.acked(set(waiting)):
                indexed += waiting.pop(i)[0]
            now = time.monotonic()
            late = [i for i, (_, t) in waiting.items() if now - t > a.ack_timeout]
            if late:
                raise SplunkError(f"{sum(waiting[i][0] for i in late)} event(s) received but not "
                                  f"acknowledged as indexed within {a.ack_timeout:g} s")
            if not final or not waiting:
                return
            time.sleep(1.0)

    n = 0
    try:
        for line in lines_of(fh, a.interval):
            if line is not None and line.strip():
                n += 1
                try:
                    ev = json.loads(line)
                except ValueError:
                    print(f"varek_splunk: line {n} is not JSON", file=sys.stderr)
                    return 2
                try:
                    pending.append(hec_event(ev, a.index))
                except SplunkError as e:
                    print(f"varek_splunk: line {n}: {e}", file=sys.stderr)
                    return 2
            if len(pending) >= a.batch or (pending and time.monotonic() - last >= a.interval):
                flush()
            if waiting and line is None:
                check_acks()
        flush()
        if waiting:
            check_acks(final=True)
    except SplunkError as e:
        print(f"varek_splunk: {e} ({sent} events sent before)", file=sys.stderr)
        return 1
    tail = f", {indexed} acknowledged as indexed" if a.ack else ""
    print(f"varek_splunk: {sent} events sent to {url} in {requests} request(s){tail}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
