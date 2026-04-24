"""
varek/stdlib/http.py
───────────────────────
var::http — HTTP client and server primitives.

Client:
  get(url: str) -> Result<HttpResponse>
  get_text(url: str) -> Result<str>
  get_json(url: str) -> Result<str>
  post(url: str, body: str) -> Result<HttpResponse>
  post_json(url: str, json_body: str) -> Result<HttpResponse>
  put(url: str, body: str) -> Result<HttpResponse>
  delete(url: str) -> Result<HttpResponse>
  request(method: str, url: str, body: str, headers: {str: str}) -> Result<HttpResponse>
  download(url: str, path: str) -> Result<nil>

Response schema:
  status: int
  body: str
  headers: {str: str}

Server (lightweight):
  serve(host: str, port: int, handler_fn) -> Result<nil>
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional

from varek.runtime import (
    VarekValue, SynStr, SynInt, SynFloat, SynBool, SynNil,
    SynArray, SynMap, SynOk, SynErr, SynSchema, SynBuiltin,
    SYN_NIL, SYN_TRUE, SYN_FALSE,
)


# ── Request helpers ───────────────────────────────────────────────

_DEFAULT_TIMEOUT = 30
_DEFAULT_HEADERS = {
    "User-Agent": "VAREK/0.4 var::http",
    "Accept": "*/*",
}

def _make_response(status: int, body: str, headers: dict) -> SynSchema:
    return SynSchema("HttpResponse", {
        "status":  SynInt(status),
        "body":    SynStr(body),
        "headers": SynMap({k: SynStr(v) for k, v in headers.items()}),
    })

def _syn_headers(headers_val) -> dict:
    """Convert a SynMap of headers to a Python dict."""
    result = dict(_DEFAULT_HEADERS)
    if isinstance(headers_val, SynMap):
        for k, v in headers_val.entries.items():
            result[str(k)] = v.value if isinstance(v, SynStr) else str(v)
    return result

def _do_request(method: str, url: str, body: Optional[bytes] = None,
                headers: dict = None, timeout: int = _DEFAULT_TIMEOUT):
    """Perform an HTTP request and return (status, body, headers)."""
    hdrs = headers or dict(_DEFAULT_HEADERS)
    req  = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            resp_hdrs = dict(resp.headers)
            return resp.status, resp_body, resp_hdrs
    except urllib.error.HTTPError as e:
        body_bytes = e.read() if hasattr(e, "read") else b""
        return e.code, body_bytes.decode("utf-8", errors="replace"), {}
    except Exception as e:
        raise RuntimeError(str(e))


# ── HTTP client functions ─────────────────────────────────────────

def _get(args):
    url = args[0].value
    try:
        status, body, hdrs = _do_request("GET", url)
        return SynOk(_make_response(status, body, hdrs))
    except Exception as e:
        return SynErr(str(e))

def _get_text(args):
    url = args[0].value
    try:
        status, body, _ = _do_request("GET", url)
        if status >= 400:
            return SynErr(f"HTTP {status}: {body[:200]}")
        return SynOk(SynStr(body))
    except Exception as e:
        return SynErr(str(e))

def _get_json(args):
    url = args[0].value
    try:
        status, body, hdrs = _do_request("GET", url,
            headers={**_DEFAULT_HEADERS, "Accept": "application/json"})
        if status >= 400:
            return SynErr(f"HTTP {status}")
        return SynOk(SynStr(body))   # returns raw JSON string
    except Exception as e:
        return SynErr(str(e))

def _post(args):
    url  = args[0].value
    body = args[1].value.encode("utf-8") if len(args) > 1 and isinstance(args[1], SynStr) else b""
    try:
        status, resp_body, hdrs = _do_request("POST", url, body=body)
        return SynOk(_make_response(status, resp_body, hdrs))
    except Exception as e:
        return SynErr(str(e))

def _post_json(args):
    url  = args[0].value
    body = args[1].value.encode("utf-8") if len(args) > 1 and isinstance(args[1], SynStr) else b"{}"
    hdrs = {**_DEFAULT_HEADERS,
            "Content-Type": "application/json",
            "Accept":       "application/json"}
    try:
        status, resp_body, resp_hdrs = _do_request("POST", url, body=body, headers=hdrs)
        return SynOk(_make_response(status, resp_body, resp_hdrs))
    except Exception as e:
        return SynErr(str(e))

def _post_form(args):
    url  = args[0].value
    data = args[1] if isinstance(args[1], SynMap) else SynMap({})
    form_data = urllib.parse.urlencode({k: v.value for k, v in data.entries.items()})
    hdrs = {**_DEFAULT_HEADERS, "Content-Type": "application/x-www-form-urlencoded"}
    try:
        status, resp_body, resp_hdrs = _do_request(
            "POST", url, body=form_data.encode("utf-8"), headers=hdrs)
        return SynOk(_make_response(status, resp_body, resp_hdrs))
    except Exception as e:
        return SynErr(str(e))

def _put(args):
    url  = args[0].value
    body = args[1].value.encode("utf-8") if len(args) > 1 and isinstance(args[1], SynStr) else b""
    try:
        status, resp_body, hdrs = _do_request("PUT", url, body=body)
        return SynOk(_make_response(status, resp_body, hdrs))
    except Exception as e:
        return SynErr(str(e))

def _patch(args):
    url  = args[0].value
    body = args[1].value.encode("utf-8") if len(args) > 1 and isinstance(args[1], SynStr) else b""
    try:
        status, resp_body, hdrs = _do_request("PATCH", url, body=body)
        return SynOk(_make_response(status, resp_body, hdrs))
    except Exception as e:
        return SynErr(str(e))

def _delete(args):
    url = args[0].value
    try:
        status, resp_body, hdrs = _do_request("DELETE", url)
        return SynOk(_make_response(status, resp_body, hdrs))
    except Exception as e:
        return SynErr(str(e))

def _request(args):
    method  = args[0].value.upper()
    url     = args[1].value
    body    = args[2].value.encode("utf-8") if len(args) > 2 and isinstance(args[2], SynStr) else None
    headers = _syn_headers(args[3]) if len(args) > 3 else dict(_DEFAULT_HEADERS)
    try:
        status, resp_body, hdrs = _do_request(method, url, body=body, headers=headers)
        return SynOk(_make_response(status, resp_body, hdrs))
    except Exception as e:
        return SynErr(str(e))

def _download(args):
    url  = args[0].value
    path = args[1].value
    try:
        urllib.request.urlretrieve(url, path)
        return SynOk(SYN_NIL)
    except Exception as e:
        return SynErr(str(e))

def _url_encode(args):
    if isinstance(args[0], SynStr):
        return SynStr(urllib.parse.quote(args[0].value, safe=""))
    if isinstance(args[0], SynMap):
        params = {k: v.value for k, v in args[0].entries.items()}
        return SynStr(urllib.parse.urlencode(params))
    return SynStr("")

def _url_decode(args):
    return SynStr(urllib.parse.unquote(args[0].value))

def _build_url(args):
    base   = args[0].value
    params = args[1] if isinstance(args[1], SynMap) else SynMap({})
    qs     = urllib.parse.urlencode({k: v.value for k, v in params.entries.items()})
    return SynStr(f"{base}?{qs}" if qs else base)

def _parse_url(args):
    url    = args[0].value
    parsed = urllib.parse.urlparse(url)
    return SynSchema("ParsedUrl", {
        "scheme":   SynStr(parsed.scheme),
        "host":     SynStr(parsed.hostname or ""),
        "port":     SynInt(parsed.port or 80),
        "path":     SynStr(parsed.path),
        "query":    SynStr(parsed.query),
        "fragment": SynStr(parsed.fragment),
    })


# ── Lightweight HTTP server ───────────────────────────────────────

def _serve(args):
    """
    Start a simple HTTP server.
    serve(host: str, port: int) -> Result<nil>
    This is synchronous and blocks. Useful for simple tools.
    """
    host = args[0].value if args else "127.0.0.1"
    port = args[1].value if len(args) > 1 else 8080
    try:
        import http.server
        import threading

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *a): pass
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"VAREK var::http server running\n")

        server = http.server.HTTPServer((host, port), _Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return SynOk(SynStr(f"http://{host}:{port}"))
    except Exception as e:
        return SynErr(str(e))


# ── JSON helpers ──────────────────────────────────────────────────

def _json_parse(args):
    s = args[0].value
    try:
        obj = json.loads(s)
        return SynOk(SynStr(json.dumps(obj)))   # normalise
    except Exception as e:
        return SynErr(str(e))

def _json_format(args):
    s = args[0].value
    try:
        obj = json.loads(s)
        return SynStr(json.dumps(obj, indent=2))
    except Exception as e:
        return SynStr(s)

def _status_ok(args):
    resp = args[0]
    if isinstance(resp, SynSchema) and "status" in resp.fields:
        return SynBool(200 <= resp.fields["status"].value < 300)
    return SYN_FALSE


def _bi(name, fn): return SynBuiltin(name, fn)

EXPORTS: dict[str, VarekValue] = {
    # Client
    "get":          _bi("get",          _get),
    "get_text":     _bi("get_text",     _get_text),
    "get_json":     _bi("get_json",     _get_json),
    "post":         _bi("post",         _post),
    "post_json":    _bi("post_json",    _post_json),
    "post_form":    _bi("post_form",    _post_form),
    "put":          _bi("put",          _put),
    "patch":        _bi("patch",        _patch),
    "delete":       _bi("delete",       _delete),
    "request":      _bi("request",      _request),
    "download":     _bi("download",     _download),
    # URL
    "url_encode":   _bi("url_encode",   _url_encode),
    "url_decode":   _bi("url_decode",   _url_decode),
    "build_url":    _bi("build_url",    _build_url),
    "parse_url":    _bi("parse_url",    _parse_url),
    # Server
    "serve":        _bi("serve",        _serve),
    # JSON
    "json_parse":   _bi("json_parse",   _json_parse),
    "json_format":  _bi("json_format",  _json_format),
    "status_ok":    _bi("status_ok",    _status_ok),
}
