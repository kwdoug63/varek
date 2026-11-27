#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_secops.py — v1.43 (docs/security/v1.39-security-operations.md, section 6):
Google Security Operations export. Each OCSF 1.9.0 event tools/varek_ocsf.py
writes (one JSON object per line, from an audited verdict stream) is sent as
one UDM event (Google's Unified Data Model) to a Google SecOps instance,
through the Chronicle API's events:import (decision G2). The export writes the
UDM itself (G1), so the policy line, its text, the three-state verdict and the
policy's SHA-256 reach the record the rules read, not only the raw log.

A UDM event carries (G4):
  * metadata: event_type from the OCSF class and activity (FILE_OPEN,
    FILE_CREATION, FILE_MODIFICATION, FILE_DELETION, FILE_READ,
    PROCESS_LAUNCH, NETWORK_CONNECTION, NETWORK_HTTP, else GENERIC_EVENT;
    GENERIC_EVENT too for an event that lacks the noun its type needs),
    the vendor and product, the Warden's version, the decision's time,
    the OCSF class and activity, the one line the OTLP export writes, and
    the run and record's position (product_log_id);
  * principal: the host and the agent's process and user;
  * target: the file, the launched program, or the host, address, port and
    URL;
  * security_result: ALLOW or BLOCK, the policy line and its text, the
    severity (MEDIUM a refusal, HIGH a failed audit, INFORMATIONAL a dry
    run's let-through and an allowed call), the three-state verdict;
  * additional: varek_decision, varek_verdict, varek_mode, varek_rule,
    varek_policy_name, varek_policy_sha256, varek_run, varek_agent,
    varek_position, varek_event, an audit's varek_audit_passed,
    varek_audit_mode and varek_audit_problems, a hold's or a deferral's
    varek_ending (v1.43 step 2: what the YARA-L rules read), and the whole
    OCSF event as JSON in
    ocsf_event, so nothing the OCSF export says is lost on the way.

Usage:
    varek_secops.py [EVENTS | -] --project ID --customer-id ID [--region us]
                    [--api-version v1alpha] [--endpoint URL]
                    [--auth auto|metadata|key-file|token] [--token-env ENVVAR] [--ca FILE]
                    [--batch N] [--max-bytes N] [--interval SECONDS] [--timeout SECONDS] [--retries N]
        EVENTS: a file of OCSF events, or - (the default) for standard input,
        read as it arrives (a pipe from varek_ocsf.py --follow sends each
        event within --interval seconds of its being written).
        --project: the Google Cloud project the instance is bound to (default:
        SECOPS_PROJECT, else GOOGLE_CLOUD_PROJECT).
        --customer-id: the instance's customer id (default: SECOPS_CUSTOMER_ID).
        --region: the instance's region (default: SECOPS_REGION, else us).
        --api-version: the Chronicle API's version (default v1alpha: the
        method is a preview; when Google moves it, this changes, not VAREK).
        --endpoint: the API's base URL, if not https://REGION-chronicle.googleapis.com.
        --auth: how the OAuth token (scope cloud-platform) is had (G3):
          auto (the default): key-file if GOOGLE_APPLICATION_CREDENTIALS is
            set, else metadata;
          metadata: the Compute Engine VM's own service account, from its
            metadata server, with no secret on the host;
          key-file: a service account's key file, the one
            GOOGLE_APPLICATION_CREDENTIALS names: its JWT is signed through
            the `cryptography` package on the host's OpenSSL;
          token: a token already had, from the variable --token-env names
            (default GOOGLE_OAUTH_ACCESS_TOKEN).
        A credential is never taken from a command line.
        --ca: certificate authorities to trust, if not the system's (the
        names are always checked).
        --max-bytes: a request's body at most (default 900000).
    A request refused for a reason a retry can mend (429, 500, 502, 503, 504,
    or no answer) is sent again, --retries times at most, waiting longer each
    time (or as Retry-After says); a request too large (413, or a 400 that
    says its payload exceeds the limit) is split; a 401 gets a new token
    once; any other refusal ends the export with exit 1, naming the position
    the events not sent begin at (their record's, unmapped.varek.position):
    `varek export --from-position N` sends them, and the stream's events from
    there on.

Exit status: 0 every event sent and accepted; 1 an event not accepted; 2 the
input is not OCSF events, or the arguments or settings are wrong.
"""
import argparse
import base64
import datetime
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_otel import _get, _object, lines_of, log_record, position_of, resume_note  # noqa: E402

API_VERSION = "v1alpha"
REGION = "us"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
METADATA = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
TOKEN_URI = "https://oauth2.googleapis.com/token"
VENDOR = "Sober Agentic Infrastructure"
PRODUCT = "VAREK"
RETRY_STATUS = (429, 500, 502, 503, 504)
MAX_BODY = 900_000             # the limit is measured in the development instance (section 6)

# OCSF class -> {activity_id: UDM event_type}; anything else is GENERIC_EVENT
FILE_TYPES = {14: "FILE_OPEN", 1: "FILE_CREATION", 3: "FILE_MODIFICATION", 5: "FILE_MODIFICATION",
              6: "FILE_MODIFICATION", 4: "FILE_DELETION", 2: "FILE_READ"}
EVENT_TYPES = {1001: FILE_TYPES, 1007: {1: "PROCESS_LAUNCH"}, 4001: {1: "NETWORK_CONNECTION", 5: "NETWORK_CONNECTION"},
               4002: None}       # HTTP: every method is NETWORK_HTTP
SEVERITY = {1: "INFORMATIONAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL", 6: "CRITICAL"}


class SecOpsError(Exception):
    pass


# ---------------------------------------------------------------- mapping --

def _iso(ms):
    return (datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def _event_type(ev):
    by_act = EVENT_TYPES.get(ev.get("class_uid"), {})
    if ev.get("class_uid") == 4002:
        return "NETWORK_HTTP"
    return (by_act or {}).get(ev.get("activity_id"), "GENERIC_EVENT")


def _has_nouns(etype, udm):
    """the nouns UDM needs for an event type (an event without them is refused)"""
    if etype == "GENERIC_EVENT":
        return True
    if not _get(udm, "principal", "hostname"):
        return False
    t = udm.get("target") or {}
    if etype.startswith("FILE_"):
        return bool(_get(t, "file", "full_path"))
    if etype == "PROCESS_LAUNCH":
        return bool(_get(t, "process", "file", "full_path"))
    if etype.startswith("NETWORK_"):
        return bool(t.get("hostname") or t.get("ip"))
    return True


def _clean(d):
    """drop empty values, nested"""
    if isinstance(d, dict):
        out = {k: _clean(v) for k, v in d.items()}
        return {k: v for k, v in out.items() if v not in (None, "", [], {})}
    if isinstance(d, list):
        return [x for x in (_clean(v) for v in d) if x not in (None, "", [], {})]
    return d


def udm(ev, line=None):
    """One OCSF event -> one UDM event"""
    if not isinstance(ev, dict) or "class_uid" not in ev:
        raise SecOpsError("not an OCSF event (no class_uid)")
    v = _get(ev, "unmapped", "varek") or {}
    pol = ev.get("policy") if isinstance(ev.get("policy"), dict) else {}
    agent = ev.get("ai_agent") if isinstance(ev.get("ai_agent"), dict) else {}
    dev = ev.get("device") if isinstance(ev.get("device"), dict) else {}
    t = ev.get("time")
    run = _get(ev, "metadata", "correlation_uid") or ""
    pos = position_of(ev)
    pline = v.get("policy_line")
    pline = pline if isinstance(pline, int) and pline > 0 else None
    audit = v.get("event") == "audit"
    passed = bool(_get(v, "audit", "passed")) if audit else None
    decision = v.get("decision_final")
    dry = v.get("mode") == "dry_run"

    meta = {
        "event_timestamp": _iso(t) if isinstance(t, (int, float)) and t > 0 else _iso(time.time() * 1000),
        "event_type": _event_type(ev),
        "vendor_name": VENDOR, "product_name": PRODUCT,
        "product_version": _get(ev, "metadata", "product", "version"),
        "product_event_type": ev.get("type_name") or ev.get("class_name"),
        "description": log_record(ev, full_event=False)["body"]["stringValue"],
        "product_log_id": f"{run}/{pos}" if run and pos else (_get(ev, "metadata", "uid") or None),
    }
    pid = _get(ev, "actor", "process", "pid")
    principal = {
        "hostname": dev.get("hostname") or dev.get("name"),
        "application": agent.get("name"),
        "process": {"pid": str(pid) if pid else None},
        "user": {"userid": _get(ev, "actor", "user", "uid") or _get(ev, "actor", "process", "user", "uid")},
    }
    target = {}
    if isinstance(ev.get("file"), dict):
        target["file"] = {"full_path": ev["file"].get("path")}
    if isinstance(ev.get("process"), dict):
        p = ev["process"]
        tp = {"pid": str(p["pid"]) if p.get("pid") else None, "file": {"full_path": _get(p, "file", "path")}}
        target["process"] = tp
    dst = ev.get("dst_endpoint") if isinstance(ev.get("dst_endpoint"), dict) else {}
    if dst.get("hostname") or _get(ev, "http_request", "url", "hostname"):
        target["hostname"] = dst.get("hostname") or _get(ev, "http_request", "url", "hostname")
    if dst.get("ip"):
        target["ip"] = [dst["ip"]]
    if isinstance(dst.get("port"), int):
        target["port"] = dst["port"]
    url = _get(ev, "http_request", "url", "url_string") or _get(ev, "api", "service", "name")
    if url:
        target["url"] = url
    if _get(ev, "api", "operation"):
        target["resource"] = {"name": _get(ev, "api", "operation")}
    if not target and _object(ev):
        target["resource"] = {"name": _object(ev)}

    out = {"metadata": meta, "principal": principal, "target": target}
    if ev.get("class_uid") == 4002 and _get(ev, "http_request", "http_method"):
        out["network"] = {"http": {"method": ev["http_request"]["http_method"]}}

    if audit:
        sr = {"severity": "INFORMATIONAL" if passed else "HIGH",
              "summary": "the run's audit " + ("passed" if passed else "failed"),
              "description": "VAREK audit: " + ("PASS" if passed else "FAIL")}
    elif decision in ("ALLOW", "DENY"):
        enforced_deny = decision == "DENY" and not dry
        sr = {"action": ["BLOCK" if enforced_deny else "ALLOW"],
              "rule_name": f"policy line {pline}" if pline else v.get("rule"),
              "rule_id": str(pline) if pline else None,
              "summary": pol.get("desc"),
              "severity": "MEDIUM" if enforced_deny else "INFORMATIONAL",
              "description": f"VAREK verdict {v.get('decision') or 'UNKNOWN'}: {decision}"
                             + (f" by {v['rule']}" if v.get("rule") else "")
                             + (" (dry run: let through, not enforced)" if dry and decision == "DENY" else "")}
    else:
        sr = {"severity": SEVERITY.get(ev.get("severity_id"), "INFORMATIONAL"),
              "description": f"VAREK {v.get('event') or ev.get('class_name')}"}
    out["security_result"] = [sr]

    extra = {
        "varek_decision": decision, "varek_verdict": v.get("decision"), "varek_mode": v.get("mode"),
        "varek_rule": v.get("rule"),
        "varek_policy_line": str(pline) if pline else None,
        "varek_policy_name": pol.get("name"), "varek_policy_sha256": pol.get("uid"),
        "varek_run": run or None, "varek_agent": agent.get("name"),
        "varek_position": str(pos) if pos else None, "varek_event": v.get("event"),
        "varek_audit_passed": ("true" if passed else "false") if audit else None,
        # v1.43 step 2: what the YARA-L rules group on, as plain strings (G6)
        "varek_audit_mode": _get(v, "audit", "mode") if audit else None,
        "varek_audit_problems": (json.dumps(_get(v, "audit", "problems"), separators=(",", ":"))
                                 if audit and _get(v, "audit", "problems") else None),
        "varek_ending": v.get("ending") if isinstance(v.get("ending"), str) else None,
        "ocsf_event": line if line is not None else json.dumps(ev, sort_keys=True, separators=(",", ":")),
    }
    out["additional"] = {k: x for k, x in extra.items() if x not in (None, "")}
    out = _clean(out)
    if not _has_nouns(out["metadata"]["event_type"], out):
        out["metadata"]["event_type"] = "GENERIC_EVENT"
    return out


def body_of(events):
    return json.dumps({"inline_source": {"events": [{"udm": e} for e in events]}},
                      separators=(",", ":")).encode()


def batches(events, limit=MAX_BODY, most=100):
    """UDM events -> lists whose request body stays under `limit` bytes"""
    out, size = [], len(body_of([]))
    for e in events:
        n = len(json.dumps({"udm": e}, separators=(",", ":"))) + 1
        if out and (size + n > limit or len(out) >= most):
            yield out
            out, size = [], len(body_of([]))
        out.append(e)
        size += n
    if out:
        yield out


# ---------------------------------------------------------------- sending --

def import_url(project, region, customer, api_version=API_VERSION, endpoint=None):
    if not project:
        raise SecOpsError("no Google Cloud project: give --project, or set SECOPS_PROJECT or GOOGLE_CLOUD_PROJECT")
    if not customer:
        raise SecOpsError("no instance: give --customer-id, or set SECOPS_CUSTOMER_ID")
    if not region:
        raise SecOpsError("no region: give --region, or set SECOPS_REGION")
    base = (endpoint or f"https://{region}-chronicle.googleapis.com").rstrip("/")
    p = urllib.parse.urlsplit(base)
    if p.scheme != "https" and p.hostname not in ("127.0.0.1", "localhost"):
        raise SecOpsError(f"{base}: not an https URL")
    q = lambda s: urllib.parse.quote(str(s), safe="")             # noqa: E731
    return (f"{base}/{q(api_version)}/projects/{q(project)}/locations/{q(region)}"
            f"/instances/{q(customer)}/events:import")


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _signed_jwt(key, now):
    """a service account's JWT for the token endpoint, RS256, through
    `cryptography` on the host's OpenSSL (VAREK implements no cryptography)"""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    try:
        pk = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    except (ValueError, TypeError) as e:
        raise SecOpsError(f"the key file's private key can't be read: {type(e).__name__}")
    if not isinstance(pk, rsa.RSAPrivateKey):
        raise SecOpsError("the key file's private key is not an RSA key")
    head = {"alg": "RS256", "typ": "JWT"}
    if key.get("private_key_id"):
        head["kid"] = key["private_key_id"]
    claims = {"iss": key["client_email"], "scope": SCOPE, "aud": key.get("token_uri") or TOKEN_URI,
              "iat": int(now), "exp": int(now) + 3600}
    msg = _b64(json.dumps(head, separators=(",", ":")).encode()) + "." + \
        _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = pk.sign(msg.encode(), padding.PKCS1v15(), hashes.SHA256())
    return msg + "." + _b64(sig)


class Token:
    """an OAuth bearer token for the Chronicle API, had again before it expires"""

    def __init__(self, auth, env, token_env="GOOGLE_OAUTH_ACCESS_TOKEN", ctx=None, timeout=10.0):
        self.env, self.ctx, self.timeout, self.token_env = env, ctx, timeout, token_env
        if auth == "auto":
            auth = "key-file" if env.get("GOOGLE_APPLICATION_CREDENTIALS") else "metadata"
        self.auth = auth
        self.value, self.expires, self.key = None, 0.0, None
        if auth == "key-file":
            path = env.get("GOOGLE_APPLICATION_CREDENTIALS")
            if not path:
                raise SecOpsError("--auth key-file: the environment variable GOOGLE_APPLICATION_CREDENTIALS "
                                  "(the service account's key file) is not set")
            try:
                with open(path, encoding="utf-8") as fh:
                    key = json.load(fh)
            except (OSError, ValueError) as e:
                raise SecOpsError(f"the key file GOOGLE_APPLICATION_CREDENTIALS names can't be read: "
                                  f"{getattr(e, 'strerror', None) or type(e).__name__}")
            if not isinstance(key, dict) or key.get("type") != "service_account" or \
                    not key.get("client_email") or not key.get("private_key"):
                raise SecOpsError("the key file GOOGLE_APPLICATION_CREDENTIALS names is not a service "
                                  "account's key (type service_account, client_email, private_key)")
            self.key = key
        elif auth == "token":
            if not env.get(token_env):
                raise SecOpsError(f"--auth token: the environment variable {token_env} is not set")
        elif auth != "metadata":
            raise SecOpsError(f"--auth {auth}: auto, metadata, key-file or token")

    def get(self, fresh=False):
        if self.auth == "token":
            return self.env[self.token_env]
        if self.value and not fresh and time.time() < self.expires - 300:
            return self.value
        opener = None
        if self.auth == "key-file":
            url = self.key.get("token_uri") or TOKEN_URI
            data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                           "assertion": _signed_jwt(self.key, time.time())}).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            base = self.env.get("VAREK_GCE_METADATA") or METADATA          # tests: a stand-in
            url = base + "?" + urllib.parse.urlencode({"scopes": SCOPE})
            req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never through a proxy
        where = url.split("?")[0]
        try:
            if opener:
                r = opener.open(req, timeout=self.timeout)
            else:
                r = urllib.request.urlopen(req, timeout=self.timeout,
                                           context=self.ctx if url.startswith("https:") else None)
            with r:
                ans = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            try:
                j = json.loads(body)
                why = j.get("error_description") or j.get("error") or body
            except ValueError:
                why = body
            raise SecOpsError(f"no token from {where}: HTTP {e.code} {str(why)[:300]}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SecOpsError(f"no token from {where}: {getattr(e, 'reason', e)}")
        if not isinstance(ans, dict) or not ans.get("access_token"):
            raise SecOpsError("the token answer has no access_token")
        self.value = ans["access_token"]
        self.expires = time.time() + float(ans.get("expires_in") or 3600)
        return self.value


def _too_large(code, text):
    if code == 413:
        return True
    if code == 400:
        t = text.lower()
        return "payload size exceeds" in t or "request payload size" in t or "too large" in t
    return False


def _refusal(code, text, n):
    msg = f"the Chronicle API refused a request of {n} event(s): HTTP {code}"
    try:
        err = json.loads(text).get("error") or {}
        if isinstance(err, dict):
            msg += f" ({err.get('status')}: {err.get('message')})"
    except (ValueError, AttributeError):
        if text.strip():
            msg += " " + text.strip()[:300]
    return msg


class Importer:
    """events:import: POSTs a request of UDM events, with retries"""

    def __init__(self, url, token, ctx=None, timeout=10.0, retries=5, sleep=time.sleep):
        self.url, self.token, self.ctx = url, token, ctx
        self.timeout, self.retries, self.sleep = timeout, retries, sleep
        self.requests = 0

    def send(self, events):
        """send events; a request too large is split in two"""
        delay, renewed, attempt = 1.0, False, 0
        body = body_of(events)
        while True:
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Authorization": "Bearer " + self.token.get(), "Content-Type": "application/json",
                "User-Agent": "varek-secops"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                    r.read()
                self.requests += 1
                return
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                self.requests += 1
                if _too_large(e.code, text) and len(events) > 1:
                    half = len(events) // 2
                    self.send(events[:half])
                    self.send(events[half:])
                    return
                if e.code == 401 and not renewed and self.token.auth != "token":
                    self.token.get(fresh=True)
                    renewed = True
                    continue
                if e.code not in RETRY_STATUS or attempt >= self.retries:
                    raise SecOpsError(_refusal(e.code, text, len(events)))
                ra = e.headers.get("Retry-After") if e.headers else None
                wait = float(ra) if ra and ra.isdigit() else delay
            except (urllib.error.URLError, OSError) as e:
                reason = getattr(e, "reason", e)
                if isinstance(reason, ssl.SSLError) or attempt >= self.retries:
                    raise SecOpsError(f"no answer from {self.url}: {reason}")
                wait = delay
            attempt += 1
            self.sleep(min(wait, 30.0))
            delay = min(delay * 2, 30.0)


# ------------------------------------------------------------------- main --

def main(argv=None, env=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(prog="varek_secops.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("events", nargs="?", default="-", help="OCSF events (a file, or - for standard input)")
    ap.add_argument("--project", help="the Google Cloud project (default: SECOPS_PROJECT, else GOOGLE_CLOUD_PROJECT)")
    ap.add_argument("--customer-id", help="the instance's customer id (default: SECOPS_CUSTOMER_ID)")
    ap.add_argument("--region", help="the instance's region (default: SECOPS_REGION, else us)")
    ap.add_argument("--api-version", default=API_VERSION, help=f"the Chronicle API's version (default {API_VERSION})")
    ap.add_argument("--endpoint", help="the API's base URL (default: https://REGION-chronicle.googleapis.com)")
    ap.add_argument("--auth", default="auto", choices=("auto", "metadata", "key-file", "token"))
    ap.add_argument("--token-env", default="GOOGLE_OAUTH_ACCESS_TOKEN", metavar="ENVVAR")
    ap.add_argument("--ca", help="certificate authorities to trust, if not the system's")
    ap.add_argument("--batch", type=int, default=100, help="events in one request at most (default 100)")
    ap.add_argument("--max-bytes", type=int, default=MAX_BODY, help=f"a request's body at most (default {MAX_BODY})")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds an event waits at most (default 1)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=5)
    a = ap.parse_args(argv)
    try:
        url = import_url(a.project or env.get("SECOPS_PROJECT") or env.get("GOOGLE_CLOUD_PROJECT"),
                         a.region or env.get("SECOPS_REGION") or REGION,
                         a.customer_id or env.get("SECOPS_CUSTOMER_ID"), a.api_version, a.endpoint)
        if a.ca and not os.path.isfile(a.ca):
            raise SecOpsError(f"--ca {a.ca}: no such file")
        if a.batch < 1 or a.max_bytes < 1000:
            raise SecOpsError("--batch is 1 or more, --max-bytes 1000 or more")
        ctx = ssl.create_default_context(cafile=a.ca)
        token = Token(a.auth, env, a.token_env, ctx, a.timeout)
        api = Importer(url, token, ctx if url.startswith("https:") else None, a.timeout, a.retries)
    except (SecOpsError, ssl.SSLError) as e:
        print(f"varek_secops: {e}", file=sys.stderr)
        return 2
    fh = sys.stdin if a.events == "-" else open(a.events, "rb")
    pending, where, sent, last, n = [], [], 0, time.monotonic(), 0
    done = 0                         # pending's events already accepted, in this flush

    def flush():
        nonlocal pending, where, sent, last, done
        done = 0
        for b in batches(pending, a.max_bytes, a.batch):
            if len(b) == 1 and len(body_of(b)) > a.max_bytes:
                raise SecOpsError(f"an event is {len(body_of(b))} bytes, over --max-bytes {a.max_bytes}: "
                                  "not sent")
            api.send(b)              # one too large is split; a part accepted before a refusal is sent again
            sent += len(b)
            done += len(b)
        pending, where, done = [], [], 0
        last = time.monotonic()

    try:
        token.get()                  # a refusal of the credentials before anything is read
        for line in lines_of(fh, a.interval):
            if line is not None and line.strip():
                n += 1
                try:
                    ev = json.loads(line)
                    pending.append(udm(ev, line.strip()))
                    where.append(position_of(ev))
                except ValueError:
                    print(f"varek_secops: line {n} is not JSON", file=sys.stderr)
                    return 2
                except SecOpsError as e:
                    print(f"varek_secops: line {n}: {e}", file=sys.stderr)
                    return 2
            if len(pending) >= a.batch or (pending and time.monotonic() - last >= a.interval):
                flush()
        flush()
    except SecOpsError as e:
        rest = where[done] if done < len(where) else None
        print(f"varek_secops: {e} ({sent} events sent before{resume_note(rest)})", file=sys.stderr)
        return 1
    print(f"varek_secops: {sent} events sent to {url} in {api.requests} request(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
