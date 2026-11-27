#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""omcp_measure.py: v1.43 step 1 (docs/security/v1.43-palantir-ontology-mcp.md).

Measures a Palantir Ontology MCP (OMCP) server, read-only, so that D2, D4
and D7 can be decided:

  1. the token: fetched with the client credentials grant; whether it is a
     JWT, its issuer, audience, lifetime and scope (the token itself is never
     printed or written);
  2. discovery: an unauthenticated POST (the WWW-Authenticate header) and
     RFC 9728 protected resource metadata, path-inserted and at the root;
  3. MCP: initialize, notifications/initialized and tools/list (every
     page), with each tool's name, annotations, description and argument
     names. No tool is called.

Standard library only. The client secret is read with getpass (not echoed,
never stored) unless OMCP_CLIENT_SECRET is set. Writes
omcp_measure_<UTC time>.json in the current directory and prints a summary.

Environment:
  FOUNDRY_HOST        the enrollment's host name, e.g. example.palantirfoundry.com
  OMCP_URL            the MCP server URL shown on the application's MCP page
  OMCP_CLIENT_ID      the Developer Console application's client ID
  OMCP_SCOPE          optional, space-separated scopes for the token request
  OMCP_CLIENT_SECRET  optional; otherwise prompted for

VAREK is not affiliated with Palantir Technologies Inc.
"""

import base64
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_VERSIONS = ("2025-06-18", "2026-07-28")
TIMEOUT = 30


def die(msg):
    print(f"omcp_measure: {msg}", file=sys.stderr)
    sys.exit(2)


def env(name, required=True):
    v = os.environ.get(name, "").strip()
    if required and not v:
        die(f"{name} is not set")
    return v


def http(method, url, headers=None, body=None):
    """Returns (status, headers dict lower-cased, body bytes). Never raises on HTTP errors."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except urllib.error.URLError as e:
        return None, {}, str(e.reason).encode()


def b64url_json(part):
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))


def token_facts(tok, expires_in):
    facts = {"length": len(tok), "expires_in": expires_in}
    parts = tok.split(".")
    if len(parts) != 3:
        facts["form"] = "opaque"
        return facts
    try:
        hdr, claims = b64url_json(parts[0]), b64url_json(parts[1])
    except (ValueError, json.JSONDecodeError):
        facts["form"] = "opaque (three parts, not decodable)"
        return facts
    facts["form"] = "JWT"
    facts["alg"] = hdr.get("alg")
    facts["has_kid"] = "kid" in hdr
    facts["claim_names"] = sorted(claims)
    for k in ("iss", "aud", "scp", "scope"):
        if k in claims:
            facts[k] = claims[k]
    if isinstance(claims.get("exp"), (int, float)) and isinstance(claims.get("iat"), (int, float)):
        facts["lifetime_s"] = int(claims["exp"] - claims["iat"])
    return facts


def sse_messages(raw):
    """JSON-RPC messages from a text/event-stream body."""
    out, data = [], []
    for line in raw.decode("utf-8", "replace").splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif line == "" and data:
            try:
                out.append(json.loads("\n".join(data)))
            except json.JSONDecodeError:
                pass
            data = []
    return out


def rpc(url, token, session, proto, method, params, rid):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if rid is not None:
        msg["id"] = rid
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "MCP-Protocol-Version": proto,
        "Mcp-Method": method,
    }
    if session:
        headers["Mcp-Session-Id"] = session
    st, hd, body = http("POST", url, headers, json.dumps(msg).encode())
    ctype = hd.get("content-type", "")
    reply = None
    if rid is not None and body:
        msgs = sse_messages(body) if "text/event-stream" in ctype else []
        if not msgs:
            try:
                msgs = [json.loads(body)]
            except json.JSONDecodeError:
                msgs = []
        reply = next((m for m in msgs if isinstance(m, dict) and m.get("id") == rid), None)
    return st, hd, ctype, reply, body


def main():
    host = env("FOUNDRY_HOST")
    omcp = env("OMCP_URL")
    client_id = env("OMCP_CLIENT_ID")
    scope = env("OMCP_SCOPE", required=False)
    secret = os.environ.get("OMCP_CLIENT_SECRET") or getpass.getpass("Client secret (not shown): ")
    if not secret:
        die("no client secret")

    result = {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "foundry_host": host, "omcp_url": omcp}

    # 1. The token.
    form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if scope:
        form["scope"] = scope
    st, _, body = http("POST", f"https://{host}/multipass/api/oauth2/token",
                       {"Content-Type": "application/x-www-form-urlencoded"},
                       urllib.parse.urlencode(form).encode())
    secret = form["client_secret"] = None
    if st != 200:
        result["token"] = {"status": st, "error": body[:300].decode("utf-8", "replace")}
        print(json.dumps(result, indent=2))
        die(f"token request failed (HTTP {st}); check the client ID, secret and grant type")
    tj = json.loads(body)
    token = tj.get("access_token", "")
    result["token"] = token_facts(token, tj.get("expires_in"))
    result["token"]["token_type"] = tj.get("token_type")
    result["token"]["granted_scope"] = tj.get("scope")

    # 2. Discovery.
    u = urllib.parse.urlsplit(omcp)
    origin = f"{u.scheme}://{u.netloc}"
    disc = {}
    st, hd, _ = http("POST", omcp, {"Content-Type": "application/json",
                                    "Accept": "application/json, text/event-stream"},
                     b'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}')
    disc["unauthenticated_post"] = {"status": st, "www_authenticate": hd.get("www-authenticate")}
    for label, path in (("prm_path", f"/.well-known/oauth-protected-resource{u.path}"),
                        ("prm_root", "/.well-known/oauth-protected-resource")):
        st, hd, b = http("GET", origin + path, {"Accept": "application/json"})
        entry = {"url": origin + path, "status": st}
        if st == 200:
            try:
                entry["body"] = json.loads(b)
            except json.JSONDecodeError:
                entry["body"] = b[:300].decode("utf-8", "replace")
        disc[label] = entry
    result["discovery"] = disc

    # 3. MCP: initialize, then tools/list.
    mcp = {"attempts": []}
    session = proto_used = init = None
    for proto in PROTOCOL_VERSIONS[::-1]:
        st, hd, ctype, reply, body = rpc(omcp, token, None, proto, "initialize", {
            "protocolVersion": proto, "capabilities": {},
            "clientInfo": {"name": "varek-omcp-measure", "version": "1.43.0-step1"}}, 1)
        mcp["attempts"].append({"protocolVersion": proto, "status": st, "content_type": ctype,
                                "error": (reply or {}).get("error")})
        if st == 200 and reply and "result" in reply:
            session, proto_used, init = hd.get("mcp-session-id"), proto, reply["result"]
            break
    if init is None:
        result["mcp"] = mcp
        print(json.dumps(result, indent=2))
        die("initialize failed with every protocol version tried")
    mcp.update({"requested_protocol": proto_used,
                "server_protocol": init.get("protocolVersion"),
                "server_info": init.get("serverInfo"),
                "capabilities": init.get("capabilities"),
                "session_id_issued": session is not None})
    proto_hdr = init.get("protocolVersion") or proto_used
    st, *_ = rpc(omcp, token, session, proto_hdr, "notifications/initialized", None, None)
    mcp["initialized_status"] = st

    tools, cursor, rid = [], None, 2
    while True:
        st, _, ctype, reply, body = rpc(omcp, token, session, proto_hdr, "tools/list",
                                        {"cursor": cursor} if cursor else {}, rid)
        if not reply or "result" not in reply:
            mcp["tools_list_error"] = {"status": st, "content_type": ctype,
                                       "reply": reply, "body": body[:300].decode("utf-8", "replace")}
            break
        for t in reply["result"].get("tools", []):
            schema = t.get("inputSchema") or {}
            tools.append({
                "name": t.get("name"),
                "title": t.get("title"),
                "annotations": t.get("annotations"),
                "description": (t.get("description") or "")[:300],
                "arguments": sorted((schema.get("properties") or {}).keys()),
                "required": schema.get("required", []),
            })
        cursor, rid = reply["result"].get("nextCursor"), rid + 1
        if not cursor or rid > 50:
            break
    mcp["tools"] = tools
    result["mcp"] = mcp
    token = None

    out = f"omcp_measure_{result['measured_at'].replace(':', '').replace('-', '')}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    t = result["token"]
    print(f"Token: {t.get('form')}, expires_in {t.get('expires_in')}, aud {t.get('aud')!r}, "
          f"iss {t.get('iss')!r}")
    print(f"Unauthenticated POST: HTTP {disc['unauthenticated_post']['status']}, "
          f"WWW-Authenticate {disc['unauthenticated_post']['www_authenticate']!r}")
    print(f"Protected resource metadata: path HTTP {disc['prm_path']['status']}, "
          f"root HTTP {disc['prm_root']['status']}")
    print(f"MCP: server protocol {mcp.get('server_protocol')}, session id issued "
          f"{mcp.get('session_id_issued')}, {len(tools)} tools")
    for x in tools:
        print(f"  {x['name']}  annotations={x['annotations']}  args={x['arguments']}")
    print(f"Saved {out} (no token or secret in it).")


if __name__ == "__main__":
    main()
