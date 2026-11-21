#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_falcon.py — v1.41 (docs/security/v1.39-security-operations.md, section 4):
CrowdStrike Falcon Next-Gen SIEM export. Each OCSF 1.9.0 event
tools/varek_ocsf.py writes (one JSON object per line, from an audited verdict
stream) is sent to a Next-Gen SIEM HTTP Event Collector (HEC) data connector
as one event, the whole OCSF event as its body (the standard library only).

The connector speaks the Splunk HEC protocol that Falcon LogScale takes, so
an event is the Splunk export's (tools/varek_splunk.py): time (the
decision's, in seconds, to the millisecond), host, source varek-warden,
sourcetype varek:ocsf, event (the OCSF event, as read) and fields
(varek_run, varek_decision, ocsf_class_uid). To a connector's raw URL
(.../services/collector/raw) each OCSF event goes as one line, the event alone.

Usage:
    varek_falcon.py [EVENTS | -] [--url URL] [--key-env ENVVAR] [--ca FILE]
                    [--batch N] [--interval SECONDS] [--timeout SECONDS] [--retries N]
        EVENTS: a file of OCSF events, or - (the default) for standard input,
        read as it arrives (a pipe from varek_ocsf.py --follow sends each
        event within --interval seconds of its being written).
        --url: the connector's API URL, as the Falcon console shows it on the
        connector's page (https://ID.ingest.CLOUD.crowdstrike.com/...).
        /services/collector is added to a URL that does not end in a
        collector path (/services/collector, its /event or /raw, or
        LogScale's /api/v1/ingest/hec, or its /raw). Default: the
        environment's FALCON_HEC_URL.
        --key-env: the environment variable holding the connector's API key
        (default FALCON_HEC_API_KEY): a key is never taken from a command
        line, where ps and the shell's history show it. It is sent as
        Authorization: Bearer KEY.
        --ca: the certificate authorities to trust for the connector's TLS
        certificate (default: the system's). Its name is checked against
        the URL's host; there is no option to skip the check.
    Only a 200 is an answer that the events were taken (LogScale's Ingest
    API: committed, not to be resent). A batch refused for a reason a retry
    can mend (429, any 5xx, a 2xx other than 200 or a 3xx, which is not
    followed, or no answer) is sent again, --retries times at most, waiting
    longer each time (or as Retry-After says); a batch too large (413) is
    split; any other refusal ends the export with exit 1, naming the
    position the events not sent begin at (their record's,
    unmapped.varek.position): `varek export --from-position N` sends them,
    and the stream's events from there on. An event over the 1 MB a
    Next-Gen SIEM event may be is not sent (the connector would take it
    truncated, its fields dropped, and answer 200): it ends the export so.

Exit status: 0 every event sent; 1 an event not taken; 2 the input is not OCSF
events, or the arguments are wrong.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_otel import lines_of, position_of, resume_note  # noqa: E402  (the same reading of a pipe as it arrives)
from varek_splunk import SplunkError, hec_event  # noqa: E402  (the same HEC event)

COLLECTOR = "/services/collector"
PATHS = ("/services/collector", "/services/collector/event", "/services/collector/raw",
         "/api/v1/ingest/hec", "/api/v1/ingest/hec/raw")       # LogScale's HEC paths, both forms
MAX_BODY = 900_000              # a request (CrowdStrike advises 5 MB and 5,000 events at most)
MAX_EVENT = 1_000_000           # an event (1 MB; a larger one is kept truncated, answered 200)


def _mendable(code):
    """a status a retry can mend: 429, any 5xx, and 201-399 (not taken; only a 200 is)"""
    return code == 429 or 500 <= code <= 599 or 201 <= code <= 399


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """a 3xx is not followed: urllib would send a POST's redirect on as a GET, without its events"""

    def redirect_request(self, *a, **k):
        return None


class FalconError(Exception):
    pass


def endpoint_of(url):
    """the connector's URL, /services/collector added if it ends in no collector path;
    (url, raw): raw when it is the raw endpoint, whose events are lines as read"""
    if not url:
        raise FalconError("no connector URL: give --url, or set FALCON_HEC_URL")
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise FalconError(f"{url}: not an http or https URL")
    if p.scheme != "https" and p.hostname not in ("127.0.0.1", "localhost"):
        raise FalconError(f"{url}: not an https URL")
    path = p.path.rstrip("/")
    if not path.endswith(PATHS):
        path += COLLECTOR
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, "")), path.endswith("/raw")


def event_of(ev):
    """One OCSF event -> one HEC event (the Splunk export's, with no index)"""
    try:
        return hec_event(ev)
    except SplunkError as e:
        raise FalconError(str(e))


def body_of(items):
    """the HEC's batch form: the events' JSON objects, one a line"""
    return "\n".join(json.dumps(e, separators=(",", ":"), sort_keys=True) for e in items).encode()


def batches(items, limit=MAX_BODY):
    """items -> lists whose body stays under `limit` bytes"""
    out, size = [], 0
    for e in items:
        n = len(json.dumps(e, separators=(",", ":"))) + 1
        if out and size + n > limit:
            yield out
            out, size = [], 0
        out.append(e)
        size += n
    if out:
        yield out


class Connector:
    """a Next-Gen SIEM HEC connector: its URL, API key and TLS trust; POSTs with retries"""

    def __init__(self, url, raw, key, ca=None, timeout=10.0, retries=5, sleep=time.sleep):
        self.url, self.raw = url, raw
        self.headers = {"Authorization": "Bearer " + key,
                        "Content-Type": "text/plain" if raw else "application/json",
                        "User-Agent": "varek-falcon"}
        self.ctx = ssl.create_default_context(cafile=ca) if url.startswith("https:") else None
        handlers = [_NoRedirect] + ([urllib.request.HTTPSHandler(context=self.ctx)] if self.ctx else [])
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout, self.retries, self.sleep = timeout, retries, sleep
        self.requests = 0

    def send(self, items):
        """send a batch; a 413 splits it in two"""
        delay = 1.0
        data = body_of(items)
        if len(items) == 1 and len(data) > MAX_EVENT:
            raise FalconError(f"an event of {len(data):,} bytes is over the {MAX_EVENT:,} a Next-Gen SIEM "
                              "event may be (it would be kept truncated, its fields dropped): not sent")
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(self.url, data=data, headers=self.headers, method="POST")
            try:
                with self.opener.open(req, timeout=self.timeout) as r:
                    code, text, hdrs = r.status, r.read().decode("utf-8", "replace"), r.headers
                self.requests += 1
                if code == 200:
                    _accepted(text, len(items))
                    return
            except urllib.error.HTTPError as e:
                code, text, hdrs = e.code, e.read().decode("utf-8", "replace"), e.headers
                self.requests += 1
                if code == 413 and len(items) > 1:
                    half = len(items) // 2
                    self.send(items[:half])
                    self.send(items[half:])
                    return
            except (urllib.error.URLError, OSError) as e:
                reason = getattr(e, "reason", e)
                if isinstance(reason, ssl.SSLError) or attempt == self.retries:
                    raise FalconError(f"no answer from {self.url}: {reason}")
                self.sleep(min(delay, 30.0))
                delay = min(delay * 2, 30.0)
                continue
            if not _mendable(code) or attempt == self.retries:
                raise FalconError(_refusal(code, text, len(items)))
            ra = hdrs.get("Retry-After") if hdrs else None
            wait = float(ra) if ra and ra.isdigit() else delay
            self.sleep(min(wait, 30.0))
            delay = min(delay * 2, 30.0)


def _accepted(text, n):
    """a 200: taken, unless its answer is the HEC's with a code other than 0"""
    try:
        ans = json.loads(text) if text.strip() else {}
    except ValueError:
        return
    if isinstance(ans, dict) and ans.get("code") not in (None, 0):
        raise FalconError(_refusal(200, text, n))


def _refusal(code, text, n):
    msg = f"the connector refused a batch of {n} event(s): HTTP {code}"
    try:
        ans = json.loads(text)
    except ValueError:
        ans = None
    if isinstance(ans, dict) and ans:
        why = ans.get("text") or ans.get("message") or ans.get("error") or ans.get("errors")
        msg += f" ({'code ' + str(ans['code']) + ': ' if 'code' in ans else ''}{why})"
    elif text.strip():
        msg += " " + text.strip()[:300]
    if code in (401, 403):
        msg += "; check the connector's API key (a key generated again ends the one before)"
    return msg


def main(argv=None, env=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(prog="varek_falcon.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("events", nargs="?", default="-", help="OCSF events (a file, or - for standard input)")
    ap.add_argument("--url", help="the connector's API URL (default: FALCON_HEC_URL)")
    ap.add_argument("--key-env", default="FALCON_HEC_API_KEY", metavar="ENVVAR",
                    help="the environment variable holding the connector's API key (default FALCON_HEC_API_KEY)")
    ap.add_argument("--ca", help="certificate authorities to trust for the connector's certificate")
    ap.add_argument("--batch", type=int, default=256, help="events in one request at most (default 256)")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds an event waits at most (default 1)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=5)
    a = ap.parse_args(argv)
    try:
        url, raw = endpoint_of(a.url or env.get("FALCON_HEC_URL"))
        key = env.get(a.key_env)
        if not key:
            raise FalconError(f"the environment variable {a.key_env} (the connector's API key) is not set")
        if a.ca and not os.path.isfile(a.ca):
            raise FalconError(f"--ca {a.ca}: no such file")
        hec = Connector(url, raw, key, a.ca, a.timeout, a.retries)
    except (FalconError, ssl.SSLError) as e:
        print(f"varek_falcon: {e}", file=sys.stderr)
        return 2
    fh = sys.stdin if a.events == "-" else open(a.events, "rb")
    pending, where, sent, done, last, n = [], [], 0, 0, time.monotonic(), 0

    def flush():
        nonlocal pending, where, sent, done, last
        done = 0
        for b in batches(pending):
            hec.send(b)              # a 413 splits it; a part taken before a refusal is sent again
            sent += len(b)
            done += len(b)
        pending, where, done = [], [], 0
        last = time.monotonic()

    try:
        for line in lines_of(fh, a.interval):
            if line is not None and line.strip():
                n += 1
                try:
                    ev = json.loads(line)
                except ValueError:
                    print(f"varek_falcon: line {n} is not JSON", file=sys.stderr)
                    return 2
                try:
                    item = event_of(ev)
                except FalconError as e:
                    print(f"varek_falcon: line {n}: {e}", file=sys.stderr)
                    return 2
                pending.append(ev if raw else item)
                where.append(position_of(ev))
            if len(pending) >= a.batch or (pending and time.monotonic() - last >= a.interval):
                flush()
        flush()
    except FalconError as e:
        rest = where[done] if done < len(where) else None
        print(f"varek_falcon: {e} ({sent} events sent before{resume_note(rest)})", file=sys.stderr)
        return 1
    print(f"varek_falcon: {sent} events sent to {url} in {hec.requests} request(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
