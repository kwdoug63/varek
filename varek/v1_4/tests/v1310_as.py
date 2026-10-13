# SPDX-License-Identifier: MIT
"""v1310_as.py — a stand-in MCP authorization setup for test_v1310.sh
section 4 (docs/security/v1.31-standards.md, section 4): an MCP server's
protected resource metadata (RFC 9728) and its authorization servers'
metadata (RFC 8414 and OpenID discovery), with keys, over HTTPS on
localhost. Tokens are signed here with the cryptography package, apart from
the C verifier in warden-secrets.

  v1310_as.py serve DIR    make a CA (DIR/ca.pem), a certificate for
                           localhost and an ES256 key; serve; write DIR/port.
      /.well-known/oauth-protected-resource/mcp     resource https://localhost:P/mcp,
                                                    authorization servers /as, /oidc, /liar
      /.well-known/oauth-protected-resource/bad     resource https://localhost:P/elsewhere
                                                    (not the URL it is fetched for), server /as2
      /.well-known/oauth-authorization-server/as    issuer https://localhost:P/as  (RFC 8414)
      /.well-known/oauth-authorization-server/as2   issuer https://localhost:P/as2
      /oidc/.well-known/openid-configuration        issuer https://localhost:P/oidc (OpenID only)
      /.well-known/oauth-authorization-server/liar  names issuer https://localhost:P/as
      /jwks                                         the key
  v1310_as.py mint DIR ISS AUD EXP [JSON]   print a token: iss ISS, aud AUD (a JSON
                           array when it starts with '['), exp now + EXP seconds
                           (none: "-"), sub alice@example.test, more claims from JSON
"""
import base64, datetime, http.server, ipaddress, json, os, ssl, sys, time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

PEM = serialization.Encoding.PEM


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def cert(cn, key, issuer, issuer_key, ca, san=None):
    t = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(t - datetime.timedelta(minutes=5)).not_valid_after(t + datetime.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def serve(d):
    ck = ec.generate_private_key(ec.SECP256R1())
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "v1310 test CA")])
    open(os.path.join(d, "ca.pem"), "wb").write(cert("v1310 test CA", ck, cn, ck, True).public_bytes(PEM))
    sk = ec.generate_private_key(ec.SECP256R1())
    leaf = cert("localhost", sk, cn, ck, False,
                san=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    open(os.path.join(d, "tls.pem"), "wb").write(
        leaf.public_bytes(PEM) + sk.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    k = ec.generate_private_key(ec.SECP256R1())
    open(os.path.join(d, "key.pem"), "wb").write(
        k.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    n = k.public_key().public_numbers()
    jwks = {"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "use": "sig",
                      "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}]}
    log = open(os.path.join(d, "requests.log"), "a", buffering=1)

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            base = "https://localhost:%d" % self.server.server_port
            log.write("GET %s\n" % self.path)
            docs = {
                "/.well-known/oauth-protected-resource/mcp":
                    {"resource": base + "/mcp", "authorization_servers": [base + "/as", base + "/oidc", base + "/liar"]},
                "/.well-known/oauth-protected-resource/bad":
                    {"resource": base + "/elsewhere", "authorization_servers": [base + "/as2"]},
                "/.well-known/oauth-authorization-server/as": {"issuer": base + "/as", "jwks_uri": base + "/jwks"},
                "/.well-known/oauth-authorization-server/as2": {"issuer": base + "/as2", "jwks_uri": base + "/jwks"},
                "/oidc/.well-known/openid-configuration": {"issuer": base + "/oidc", "jwks_uri": base + "/jwks"},
                "/.well-known/oauth-authorization-server/liar": {"issuer": base + "/as", "jwks_uri": base + "/jwks"},
                "/jwks": jwks,
            }
            body = docs.get(self.path)
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            out = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(d, "tls.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    open(os.path.join(d, "port.tmp"), "w").write("%d\n" % srv.server_port)
    os.rename(os.path.join(d, "port.tmp"), os.path.join(d, "port"))
    srv.serve_forever()


def mint(d, iss, aud, exp, extra):
    t = int(time.time())
    c = {"iss": iss, "sub": "alice@example.test", "aud": json.loads(aud) if aud.startswith("[") else aud,
         "iat": t - 10, "jti": "jti-%d" % time.time_ns()}
    if exp != "-":
        c["exp"] = t + int(exp)
    c.update(json.loads(extra) if extra else {})
    k = serialization.load_pem_private_key(open(os.path.join(d, "key.pem"), "rb").read(), None)
    si = (b64(json.dumps({"alg": "ES256", "typ": "JWT", "kid": "k1"}).encode()) + "." +
          b64(json.dumps(c).encode())).encode()
    r, s = decode_dss_signature(k.sign(si, ec.ECDSA(hashes.SHA256())))
    return si.decode() + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2])
    else:
        print(mint(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6] if len(sys.argv) > 6 else ""))
