#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_otel.py — v1.39 (docs/security/v1.39-security-operations.md, section 1):
OpenTelemetry export. Each OCSF 1.9.0 event tools/varek_ocsf.py writes (one
JSON object per line, from an audited verdict stream) is sent as one OTLP log
record to an OpenTelemetry collector, over OTLP/HTTP with the JSON encoding
(no protobuf, no SDK: the standard library only).

A record carries:
  * its time (the event's), the time it was read, and a severity from the
    event's (Informational INFO, Medium WARN, High ERROR, ...), its text
    the short name (INFO, WARN, ...) a backend reads a level from;
  * a one-line body: the decision, the class and activity, the object, and
    the policy line that decided it, with its text;
  * attributes: event.name, the OCSF class, activity, action, disposition
    and status, the three-state verdict and the final decision (ALLOW or
    DENY), the rule, the policy line's number
    and text, the policy's name and SHA-256, the run, the record's report id
    and seq, the agent or sub-agent, the process id, the user; and the
    whole OCSF event as JSON (ocsf.event), the line as read, so nothing the
    OCSF export says is lost on the way (--no-full-event leaves it out);
  * the resource: service.name (varek-warden), service.version (the
    Warden's), host.name, and the run (varek.run).

Usage:
    varek_otel.py [EVENTS | -] [--endpoint URL] [--header NAME=ENVVAR]...
                  [--batch N] [--interval SECONDS] [--timeout SECONDS]
                  [--retries N] [--no-full-event]
        EVENTS: a file of OCSF events, or - (the default) for standard input,
        read as it arrives (a pipe from varek_ocsf.py --follow sends each
        event within --interval seconds of its being written).
        --endpoint: the collector's OTLP/HTTP logs URL. Default: the
        environment's OTEL_EXPORTER_OTLP_LOGS_ENDPOINT, else
        OTEL_EXPORTER_OTLP_ENDPOINT with /v1/logs added, else
        http://localhost:4318/v1/logs.
        --header NAME=ENVVAR: send the header NAME with the value of the
        environment variable ENVVAR (a vendor's API key: never on a command
        line, where ps and the shell's history show it). The environment's
        OTEL_EXPORTER_OTLP_HEADERS (name=value pairs, comma-separated) are
        sent too.
    A batch the collector refuses for a reason a retry can mend (429, 502,
    503, 504, or no answer) is sent again, --retries times at most, waiting
    longer each time (or as Retry-After says); any other refusal, and a
    partial success that rejects records, ends the export with exit 1.
    v1.40: its message then names the position the events not sent begin
    at (their record's, unmapped.varek.position): `varek export
    --from-position N` sends them, and the stream's events from there on.

Exit status: 0 every event sent and accepted; 1 an event not accepted;
2 the input is not OCSF events (a line that is not a JSON object).
"""
import argparse
import json
import os
import select
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCOPE = "varek.ocsf"
SERVICE = "varek-warden"
DEFAULT_ENDPOINT = "http://localhost:4318/v1/logs"
RETRY_STATUS = (429, 502, 503, 504)

# OCSF severity_id -> OTel severityNumber and its short name
SEVERITY = {0: (0, "UNSPECIFIED"), 1: (9, "INFO"), 2: (10, "INFO2"), 3: (13, "WARN"),
            4: (17, "ERROR"), 5: (21, "FATAL"), 6: (21, "FATAL"), 99: (9, "INFO")}


class OtelError(Exception):
    pass


# ---------------------------------------------------------------- mapping --

def _av(v):
    """an OTLP AnyValue"""
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}          # int64 as a string, as OTLP JSON says
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


def _kv(attrs):
    """{name: value} -> OTLP KeyValue list, in name order, values that are None left out"""
    return [{"key": k, "value": _av(v)} for k, v in sorted(attrs.items()) if v is not None and v != ""]


def _get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def _object(ev):
    """what the event was about, for the body: a file, a process, an
    endpoint, an MCP call, a URL, or (v1.42) the call an approval, a
    deferral or a webhook post is about"""
    for path in (("file", "path"), ("process", "file", "path"), ("process", "cmd_line"),
                 ("http_request", "url", "url_string"), ("api", "operation"),
                 ("query", "hostname")):
        v = _get(ev, *path)
        if v:
            return str(v)
    dst = ev.get("dst_endpoint")
    if isinstance(dst, dict):
        host = dst.get("hostname") or dst.get("ip")
        if host:
            return f"{host}:{dst['port']}" if dst.get("port") else str(host)
    v = _get(ev, "unmapped", "varek", "object")       # v1.42: the call an approval or a deferral is about
    if v:
        return str(v)
    v = _get(ev, "unmapped", "varek", "event")
    return str(v) if v else ""


def resource_of(ev):
    """the resource attributes of the event's run"""
    md = ev.get("metadata") if isinstance(ev.get("metadata"), dict) else {}
    dev = ev.get("device") if isinstance(ev.get("device"), dict) else {}
    return {"service.name": SERVICE, "service.version": _get(md, "product", "version"),
            "host.name": dev.get("hostname") or dev.get("name"), "varek.run": md.get("correlation_uid")}


def log_record(ev, line=None, full_event=True, observed_ns=None):
    """One OCSF event -> one OTLP LogRecord (JSON encoding)"""
    if not isinstance(ev, dict) or "class_uid" not in ev:
        raise OtelError("not an OCSF event (no class_uid)")
    v = _get(ev, "unmapped", "varek") or {}
    pol = ev.get("policy") if isinstance(ev.get("policy"), dict) else {}
    line_no = v.get("policy_line")
    sev_num, sev_name = SEVERITY.get(ev.get("severity_id"), (0, "UNSPECIFIED"))
    t = ev.get("time")
    t_ns = int(t) * 1_000_000 if isinstance(t, (int, float)) and t > 0 else 0
    what = _object(ev)
    decision = ev.get("disposition") or ev.get("action") or ""
    body = " ".join(x for x in (f"{decision}:" if decision else "", str(ev.get("type_name", "")),
                                what) if x)
    if isinstance(line_no, int) and line_no > 0:
        body += f" (policy line {line_no}" + (f": {pol['desc']}" if pol.get("desc") else "") + ")"
    elif v.get("rule"):
        body += f" ({v['rule']})"
    agent = ev.get("ai_agent") if isinstance(ev.get("ai_agent"), dict) else {}
    attrs = {
        "event.name": "varek." + str(v.get("event") or ("decision" if "action_id" in ev else "event")),
        "ocsf.class_uid": ev.get("class_uid"), "ocsf.class_name": ev.get("class_name"),
        "ocsf.activity_name": ev.get("activity_name"), "ocsf.type_uid": ev.get("type_uid"),
        "ocsf.action": ev.get("action"), "ocsf.disposition": ev.get("disposition"),
        "ocsf.status": ev.get("status"), "ocsf.severity": ev.get("severity"),
        "ocsf.metadata.uid": _get(ev, "metadata", "uid"),
        "varek.verdict": v.get("decision"), "varek.decision": v.get("decision_final"),
        "varek.rule": v.get("rule"),
        "varek.policy.line": line_no if isinstance(line_no, int) and line_no > 0 else None,
        "varek.policy.text": pol.get("desc"), "varek.policy.name": pol.get("name"),
        "varek.policy.sha256": pol.get("uid"),
        "varek.report_id": v.get("report_id"), "varek.seq": v.get("seq"),
        "varek.mode": v.get("mode"),
        "varek.agent": agent.get("name"), "varek.agent.type": agent.get("type"),
        "process.pid": _get(ev, "actor", "process", "pid") or None,
        "user.id": _get(ev, "actor", "user", "uid"),
        "varek.target": what or None,
    }
    if v.get("event") == "audit":
        attrs["varek.audit.passed"] = bool(_get(v, "audit", "passed"))
    if full_event:
        attrs["ocsf.event"] = line if line is not None else json.dumps(ev, sort_keys=True, separators=(",", ":"))
    rec = {"timeUnixNano": str(t_ns), "observedTimeUnixNano": str(observed_ns or time.time_ns()),
           # the short name, as backends read a level from it (Loki's
           # level: OCSF's "Medium" is none it knows); OCSF's in ocsf.severity
           "severityNumber": sev_num, "severityText": sev_name,
           "body": {"stringValue": body}, "attributes": _kv(attrs)}
    return rec


def payload(items):
    """[(resource attributes, LogRecord)] -> an ExportLogsServiceRequest, one
    resourceLogs entry for each resource, in the order first seen"""
    groups, order = {}, []
    for res, rec in items:
        key = json.dumps(res, sort_keys=True)
        if key not in groups:
            groups[key] = (res, [])
            order.append(key)
        groups[key][1].append(rec)
    return {"resourceLogs": [
        {"resource": {"attributes": _kv(groups[k][0])},
         "scopeLogs": [{"scope": {"name": SCOPE, "version": "1.9.0"}, "logRecords": groups[k][1]}]}
        for k in order]}


# ---------------------------------------------------------------- sending --

def endpoint_from_env(env=None):
    env = os.environ if env is None else env
    if env.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"):
        return env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]
    if env.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return env["OTEL_EXPORTER_OTLP_ENDPOINT"].rstrip("/") + "/v1/logs"
    return DEFAULT_ENDPOINT


def headers_from(specs, env=None):
    """the headers to send: OTEL_EXPORTER_OTLP_HEADERS, then each --header NAME=ENVVAR"""
    env = os.environ if env is None else env
    h = {}
    for pair in (env.get("OTEL_EXPORTER_OTLP_HEADERS") or "").split(","):
        if "=" in pair:
            k, _, val = pair.partition("=")
            h[urllib.parse.unquote(k.strip())] = urllib.parse.unquote(val.strip())
    for spec in specs or ():
        name, sep, var = spec.partition("=")
        if not sep or not name or not var:
            raise OtelError(f"--header {spec}: give NAME=ENVVAR")
        if var not in env:
            raise OtelError(f"--header {name}: the environment variable {var} is not set")
        h[name] = env[var]
    return h


def send(url, body, headers, timeout=10.0, retries=5, sleep=time.sleep):
    """POST one batch; retried on 429, 502, 503, 504 and on no answer;
    returns the number of records the collector says it rejected"""
    data = json.dumps(body, separators=(",", ":")).encode()
    h = {"Content-Type": "application/json", "User-Agent": "varek-otel"}
    h.update(headers)
    delay = 1.0
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", "replace")
            try:
                ans = json.loads(text) if text.strip() else {}
            except ValueError:
                ans = {}
            ps = ans.get("partialSuccess") if isinstance(ans, dict) else None
            return int((ps or {}).get("rejectedLogRecords") or 0), (ps or {}).get("errorMessage", "")
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS or attempt == retries:
                msg = e.read().decode("utf-8", "replace")[:300]
                raise OtelError(f"the collector refused the batch: HTTP {e.code} {msg}".strip())
            ra = e.headers.get("Retry-After") if e.headers else None
            wait = float(ra) if ra and ra.isdigit() else delay
        except (urllib.error.URLError, OSError) as e:
            if attempt == retries:
                raise OtelError(f"no answer from {url}: {getattr(e, 'reason', e)}")
            wait = delay
        sleep(min(wait, 30.0))
        delay = min(delay * 2, 30.0)
    raise OtelError("not sent")       # not reached


# ------------------------------------------------------------------- main --

def position_of(ev):
    """v1.40: the position, in its stream, of the record an OCSF event came
    from (unmapped.varek.position, as tools/varek_ocsf.py writes it); None
    for an event that names none"""
    v = _get(ev, "unmapped", "varek")
    p = v.get("position") if isinstance(v, dict) else None
    return p if type(p) is int and p >= 1 else None


def resume_note(pos):
    """v1.40: what a failed export's message adds: where the events not
    sent begin, and how to send them (nothing if that is not known: the
    export is then made again whole)"""
    if pos is None:
        return ""
    return f"; those not sent begin at position {pos}: `varek export --from-position {pos}` sends them"


def lines_of(fh, interval):
    """the input's lines as they come; None when --interval passes with none
    (a time to send what is waiting)"""
    buf = b""
    fd = fh.fileno()
    while True:
        r, _, _ = select.select([fd], [], [], interval)
        if not r:
            yield None
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            if buf.strip():
                yield buf.decode("utf-8", "replace")
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode("utf-8", "replace")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="varek_otel.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("events", nargs="?", default="-", help="OCSF events (a file, or - for standard input)")
    ap.add_argument("--endpoint", help="the collector's OTLP/HTTP logs URL")
    ap.add_argument("--header", action="append", default=[], metavar="NAME=ENVVAR")
    ap.add_argument("--batch", type=int, default=256, help="records in one request at most (default 256)")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds an event waits at most (default 1)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--no-full-event", action="store_true", help="leave the whole OCSF event out")
    a = ap.parse_args(argv)
    try:
        url = a.endpoint or endpoint_from_env()
        if not url.startswith(("http://", "https://")):
            raise OtelError(f"{url}: not an http or https URL")
        headers = headers_from(a.header)
    except OtelError as e:
        print(f"varek_otel: {e}", file=sys.stderr)
        return 2
    fh = sys.stdin if a.events == "-" else open(a.events, "rb")
    pending, sent, requests, last = [], 0, 0, time.monotonic()
    first = None                     # v1.40: the position of the first event not yet accepted

    def flush():
        nonlocal pending, sent, requests, last, first
        if pending:
            rejected, why = send(url, payload(pending), headers, a.timeout, a.retries)
            requests += 1
            if rejected:
                raise OtelError(f"the collector rejected {rejected} of {len(pending)} records: {why}".strip())
            sent += len(pending)
            pending, first = [], None
        last = time.monotonic()

    n = 0
    try:
        for line in lines_of(fh, a.interval):
            if line is not None and line.strip():
                n += 1
                try:
                    ev = json.loads(line)
                except ValueError:
                    print(f"varek_otel: line {n} is not JSON", file=sys.stderr)
                    return 2
                try:
                    pending.append((resource_of(ev), log_record(ev, line.strip(), not a.no_full_event)))
                    if len(pending) == 1:
                        first = position_of(ev)
                except OtelError as e:
                    print(f"varek_otel: line {n}: {e}", file=sys.stderr)
                    return 2
            if len(pending) >= a.batch or (pending and time.monotonic() - last >= a.interval):
                flush()
        flush()
    except OtelError as e:
        print(f"varek_otel: {e} ({sent} records sent before{resume_note(first)})", file=sys.stderr)
        return 1
    print(f"varek_otel: {sent} records sent to {url} in {requests} request(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
