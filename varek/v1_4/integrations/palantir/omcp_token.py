#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""omcp_token.py: v1.43 step 5, the token refresher (docs/security/v1.43-palantir-ontology-mcp.md, D4).

Keeps a Palantir Ontology MCP (OMCP) access token in a VAREK file store, so
a run can hold it as a v1.31 MCP credential and release it into the calls
its policy allows. The agent never holds it. VAREK stays no OAuth client:
this script, outside the Warden, is the one that asks for tokens.

  - The token comes from the client credentials grant of a Developer
    Console application (a service user): POST to the enrollment's token
    endpoint, https://HOST/multipass/api/oauth2/token, with grant_type,
    client_id and client_secret in the form body.
  - It is written atomically (a new file in the same directory, mode 600,
    renamed over the old), so a reader sees the old token or the new one,
    never part of either. Run as root, the file is root's, as VAREK's file
    stores must be (the directories above it writable by root alone).
  - It is fetched again at half its life (--refresh-at), so the file always
    holds a token with time left: warden-secrets refuses a JWT that expires
    within 60 s.
  - Neither the token nor the client secret is printed, logged or written
    anywhere but the token's file. The secret comes from --secret-file (a
    regular file of yours that no group or other user can read) or the
    environment (OMCP_CLIENT_SECRET), never the command line.

One fetch:   omcp_token.py --foundry-host HOST --client-id ID --secret-file F --out PATH --once
Kept fresh:  the same without --once, under systemd (varek-omcp-token.service).

A run reads its file credential when it starts. Start each run with the file
current (this script keeps it so); a run that outlives its token sees the
server refuse the calls made after the token's expiry.

Standard library only. VAREK is not affiliated with Palantir Technologies Inc.
"""

import argparse
import base64
import json
import os
import re
import signal
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_PATH = "/multipass/api/oauth2/token"
MAX_TOKEN = 8192                   # warden-secrets: a value goes in one header of at most 8 KB
MIN_LIFETIME = 120                 # under this, warden-secrets' 60 s margin leaves too little
DEFAULT_OPAQUE_INTERVAL = 900      # a token whose expiry nobody says is fetched this often
TOKEN_CHARS = re.compile(r"^[A-Za-z0-9\-._~+/=]+$")   # RFC 6750's b64token
TIMEOUT = 30


class TokenError(Exception):
    pass


def log(msg):
    print(f"omcp_token: {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------- the secret --

def read_secret(path):
    """The client secret from a file only this user can read (no link)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise TokenError(f"--secret-file {path}: {e.strerror}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise TokenError(f"--secret-file {path}: not a regular file")
        if st.st_uid != os.geteuid():
            raise TokenError(f"--secret-file {path}: owned by uid {st.st_uid}, not this user ({os.geteuid()})")
        if st.st_mode & 0o077:
            raise TokenError(f"--secret-file {path}: mode {st.st_mode & 0o777:03o}; no group or other user may "
                             "read it (chmod 600)")
        if st.st_size > 4096:
            raise TokenError(f"--secret-file {path}: larger than 4 KiB")
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    secret = data.decode("utf-8", "strict").strip()
    if not secret or "\n" in secret:
        raise TokenError(f"--secret-file {path}: one line, the client secret")
    return secret


# ---------------------------------------------------------------- the token --

def _b64url_json(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def token_facts(tok, expires_in, now):
    """(form, seconds left or None, a short description). Never the token."""
    parts = tok.split(".")
    if len(parts) == 3:
        try:
            claims = _b64url_json(parts[1])
        except (ValueError, json.JSONDecodeError):
            claims = None
        if isinstance(claims, dict):
            exp = claims.get("exp")
            left = int(exp - now) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
            aud = claims.get("aud")
            desc = "JWT" + (f", aud {aud}" if aud is not None else ", no aud")
            if left is None:
                desc += ", no exp"
            return "jwt", left, desc
    left = int(expires_in) if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) else None
    return "opaque", left, "opaque"


def fetch_token(token_url, client_id, secret, scope=None, cafile=None):
    """(token, expires_in or None). Raises TokenError with the server's reason, never the secret."""
    form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if scope:
        form["scope"] = scope
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(token_url, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            raw = r.read(65537)
    except urllib.error.HTTPError as e:
        why = ""
        try:
            j = json.loads(e.read(4097) or b"{}")
            why = ": " + str(j.get("error", ""))[:80] + (f" ({str(j.get('error_description'))[:160]})"
                                                          if j.get("error_description") else "")
        except (ValueError, AttributeError):
            pass
        raise TokenError(f"the token endpoint answered {e.code}{why}")
    except urllib.error.URLError as e:
        raise TokenError(f"the token endpoint: {e.reason}")
    except (TimeoutError, OSError) as e:
        raise TokenError(f"the token endpoint: {e}")
    try:
        j = json.loads(raw)
    except ValueError:
        raise TokenError("the token endpoint's answer is not JSON")
    tok = j.get("access_token") if isinstance(j, dict) else None
    if not isinstance(tok, str) or not tok:
        raise TokenError("the token endpoint's answer has no access_token")
    ttype = str(j.get("token_type", "bearer")).lower()
    if ttype != "bearer":
        raise TokenError(f"the token endpoint gave a {ttype[:20]!r} token, not a bearer token")
    if len(tok) > MAX_TOKEN:
        raise TokenError(f"the token is {len(tok)} bytes, over the {MAX_TOKEN} a credential may be")
    if not TOKEN_CHARS.match(tok):
        raise TokenError("the token holds characters a bearer token may not")
    return tok, j.get("expires_in")


def write_atomic(path, value):
    """path's new content, mode 600: written beside it, then renamed over it."""
    d = os.path.dirname(os.path.abspath(path)) or "/"
    tmp = os.path.join(d, f".{os.path.basename(path)}.{os.getpid()}.new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        data = value.encode()
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(tmp, path)
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def check_out_dir(path):
    """Notes on what warden-secrets will refuse, so they show here first."""
    notes = []
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        raise TokenError(f"--out {path}: {d} is not a directory")
    if os.geteuid() != 0:
        notes.append("not root: warden-secrets reads a file store only when root owns it")
    p = d
    while True:
        st = os.stat(p)
        if st.st_uid != 0 or st.st_mode & 0o022:
            notes.append(f"{p} is writable by a user other than root: warden-secrets will refuse the file")
            break
        if p == "/":
            break
        p = os.path.dirname(p)
    return notes


def refresh_once(a, secret):
    """Fetch, check and write one token; seconds until the next refresh."""
    now = time.time()
    tok, expires_in = fetch_token(a.token_url, a.client_id, secret, a.scope, a.cafile)
    try:
        form, left, desc = token_facts(tok, expires_in, now)
        if left is not None and left < MIN_LIFETIME:
            raise TokenError(f"the token's life is {left} s, under {MIN_LIFETIME} s: not written")
        write_atomic(a.out, tok)
    finally:
        tok = None
    if left is None:
        nxt = a.interval
        life = "its expiry not given"
    else:
        nxt = max(30, int(left * a.refresh_at))
        life = f"expires in {left} s"
    log(f"wrote {a.out}: {desc}, {life}; next fetch in {nxt} s")
    return nxt


def main(argv=None):
    ap = argparse.ArgumentParser(prog="omcp_token.py",
                                 description="Keep a Palantir OMCP access token (client credentials grant) in a "
                                             "VAREK file store. The token and the secret are never printed.")
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument("--foundry-host", metavar="HOST", help="the enrollment's host, e.g. NAME.palantirfoundry.com")
    where.add_argument("--token-url", metavar="URL", help="the token endpoint itself (https://)")
    ap.add_argument("--client-id", default=os.environ.get("OMCP_CLIENT_ID"),
                    help="the Developer Console application's client ID (or OMCP_CLIENT_ID)")
    ap.add_argument("--secret-file", metavar="FILE",
                    help="the client secret, one line, in a file no group or other user can read "
                         "(or OMCP_CLIENT_SECRET)")
    ap.add_argument("--scope", default=os.environ.get("OMCP_SCOPE"), help="space-separated scopes, if any")
    ap.add_argument("--out", required=True, metavar="PATH",
                    help="the token's file, as the policy's `credential NAME from file:PATH` names it")
    ap.add_argument("--once", action="store_true", help="fetch one token and exit")
    ap.add_argument("--refresh-at", type=float, default=0.5,
                    help="fetch again after this fraction of the token's life (default 0.5)")
    ap.add_argument("--interval", type=int, default=DEFAULT_OPAQUE_INTERVAL,
                    help=f"seconds between fetches when the expiry is not given (default {DEFAULT_OPAQUE_INTERVAL})")
    ap.add_argument("--cafile", help="verify the token endpoint against this CA bundle (default: the system's)")
    a = ap.parse_args(argv)

    try:
        if a.foundry_host:
            if not re.match(r"^[A-Za-z0-9.-]+$", a.foundry_host):
                raise TokenError("--foundry-host is a host name")
            a.token_url = f"https://{a.foundry_host}{TOKEN_PATH}"
        if urllib.parse.urlsplit(a.token_url).scheme != "https":
            raise TokenError("the token endpoint is reached over https:// only")
        if not a.client_id:
            raise TokenError("no --client-id (or OMCP_CLIENT_ID)")
        if not 0.1 <= a.refresh_at <= 0.9:
            raise TokenError("--refresh-at is between 0.1 and 0.9")
        if a.interval < 60:
            raise TokenError("--interval is at least 60")
        if a.secret_file:
            secret = read_secret(a.secret_file)
        elif os.environ.get("OMCP_CLIENT_SECRET"):
            secret = os.environ["OMCP_CLIENT_SECRET"].strip()
        else:
            raise TokenError("no --secret-file (or OMCP_CLIENT_SECRET)")
        for n in check_out_dir(a.out):
            log("note: " + n)
    except TokenError as e:
        log(str(e))
        return 2

    if a.once:
        try:
            refresh_once(a, secret)
            return 0
        except (TokenError, OSError) as e:
            log(str(e))
            return 1

    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    backoff = 15
    while not stop:
        try:
            wait = refresh_once(a, secret)
            backoff = 15
        except (TokenError, OSError) as e:
            log(f"{e}; trying again in {backoff} s")
            wait, backoff = backoff, min(backoff * 2, 300)
        end = time.monotonic() + wait
        while not stop and time.monotonic() < end:
            time.sleep(min(1.0, end - time.monotonic()))
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
